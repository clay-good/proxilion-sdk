"""
Tests for cloud storage exporters.

Tests cover:
- CloudExporterConfig validation
- ExportBatch creation and serialization
- S3Exporter (with mocked responses)
- GCSExporter (with mocked responses)
- AzureBlobExporter (with mocked responses)
- MultiCloudExporter with various failure strategies
- Key generation with partitioning
- Retry logic
- Compression handling
"""

from __future__ import annotations

import gzip
import json
import threading
import time
from datetime import datetime, timedelta, timezone
from unittest.mock import MagicMock, patch

import pytest

from proxilion.audit.events import AuditEventV2
from proxilion.audit.exporters.cloud_base import (
    BaseCloudExporter,
    CloudExporterConfig,
    CompressionType,
    ExportBatch,
    ExportFormat,
    ExportResult,
)
from proxilion.audit.exporters.aws_s3 import S3Exporter, S3DataLakeExporter
from proxilion.audit.exporters.gcp_storage import GCSExporter
from proxilion.audit.exporters.azure_storage import AzureBlobExporter
from proxilion.audit.exporters.multi_exporter import (
    FailureStrategy,
    MultiCloudExporter,
    MultiExportResult,
)


class TestCloudExporterConfig:
    """Tests for CloudExporterConfig dataclass."""

    def test_basic_config(self):
        """Test creating a basic configuration."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="my-bucket",
        )

        assert config.provider == "aws"
        assert config.bucket_name == "my-bucket"
        assert config.prefix == ""
        assert config.batch_size == 100
        assert config.compression == CompressionType.GZIP

    def test_config_with_prefix(self):
        """Test that prefix gets normalized with trailing slash."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="my-bucket",
            prefix="audit/logs",
        )

        assert config.prefix == "audit/logs/"

    def test_config_prefix_already_has_slash(self):
        """Test that prefix with trailing slash is not double-slashed."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="my-bucket",
            prefix="audit/logs/",
        )

        assert config.prefix == "audit/logs/"

    def test_config_full_options(self):
        """Test configuration with all options."""
        config = CloudExporterConfig(
            provider="gcp",
            bucket_name="my-bucket",
            prefix="audit/",
            region="us-central1",
            credentials_path="/path/to/creds.json",
            use_instance_credentials=False,
            batch_size=500,
            compression=CompressionType.ZSTD,
            format=ExportFormat.PARQUET,
            endpoint_url="https://custom.endpoint.com",
            connection_timeout=60.0,
            read_timeout=120.0,
            max_retries=5,
            retry_delay=2.0,
        )

        assert config.provider == "gcp"
        assert config.region == "us-central1"
        assert config.batch_size == 500
        assert config.compression == CompressionType.ZSTD
        assert config.format == ExportFormat.PARQUET
        assert config.max_retries == 5

    def test_config_string_enum_conversion(self):
        """Test that string values are converted to enums."""
        config = CloudExporterConfig(
            provider="azure",
            bucket_name="container",
            compression="gzip",  # type: ignore
            format="jsonl",  # type: ignore
        )

        assert config.compression == CompressionType.GZIP
        assert config.format == ExportFormat.JSONL


class TestExportBatch:
    """Tests for ExportBatch dataclass."""

    def test_batch_creation(self, sample_audit_event: AuditEventV2):
        """Test creating an export batch."""
        batch = ExportBatch(
            batch_id="test_batch_001",
            events=[sample_audit_event],
        )

        assert batch.batch_id == "test_batch_001"
        assert batch.event_count == 1
        assert batch.created_at is not None

    def test_batch_to_jsonl(self, sample_audit_event: AuditEventV2):
        """Test converting batch to JSON Lines."""
        batch = ExportBatch(
            batch_id="test_batch",
            events=[sample_audit_event, sample_audit_event],
        )

        jsonl = batch.to_jsonl()
        lines = jsonl.strip().split("\n")

        assert len(lines) == 2
        for line in lines:
            data = json.loads(line)
            assert "event_id" in data

    def test_batch_to_bytes_uncompressed(self, sample_audit_event: AuditEventV2):
        """Test converting batch to uncompressed bytes."""
        batch = ExportBatch(
            batch_id="test_batch",
            events=[sample_audit_event],
        )

        data = batch.to_bytes(CompressionType.NONE)
        content = data.decode("utf-8")

        assert sample_audit_event.event_id in content

    def test_batch_to_bytes_gzip(self, sample_audit_event: AuditEventV2):
        """Test converting batch to gzip-compressed bytes."""
        batch = ExportBatch(
            batch_id="test_batch",
            events=[sample_audit_event],
        )

        compressed = batch.to_bytes(CompressionType.GZIP)
        decompressed = gzip.decompress(compressed).decode("utf-8")

        assert sample_audit_event.event_id in decompressed

    def test_batch_metadata(self, sample_audit_event: AuditEventV2):
        """Test batch with metadata."""
        batch = ExportBatch(
            batch_id="test_batch",
            events=[sample_audit_event],
            metadata={"source": "test", "version": "1.0"},
        )

        assert batch.metadata["source"] == "test"
        assert batch.metadata["version"] == "1.0"


class TestBaseCloudExporter:
    """Tests for BaseCloudExporter base class."""

    def test_generate_key_default(self):
        """Test key generation with default parameters."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="bucket",
            prefix="audit/",
        )

        # Create a concrete implementation for testing
        class TestExporter(BaseCloudExporter):
            def export_batch(self, batch):
                return ExportResult(success=True)

            def health_check(self):
                return True

        exporter = TestExporter(config)
        key = exporter.generate_key()

        assert key.startswith("audit/")
        assert ".jsonl.gz" in key
        # Check partitioning structure
        parts = key.split("/")
        assert len(parts) >= 5  # prefix + year + month + day + hour + filename

    def test_generate_key_with_timestamp(self):
        """Test key generation with specific timestamp."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="bucket",
            prefix="logs/",
            compression=CompressionType.NONE,
        )

        class TestExporter(BaseCloudExporter):
            def export_batch(self, batch):
                return ExportResult(success=True)

            def health_check(self):
                return True

        exporter = TestExporter(config)
        timestamp = datetime(2024, 6, 15, 10, 30, 0, tzinfo=timezone.utc)
        key = exporter.generate_key(timestamp=timestamp, batch_id="batch_001")

        assert "2024/06/15/10/" in key
        assert "batch_001.jsonl" in key

    def test_compute_checksum(self):
        """Test checksum computation."""
        config = CloudExporterConfig(provider="aws", bucket_name="bucket")

        class TestExporter(BaseCloudExporter):
            def export_batch(self, batch):
                return ExportResult(success=True)

            def health_check(self):
                return True

        exporter = TestExporter(config)
        data = b"test data for checksum"
        checksum = exporter.compute_checksum(data)

        assert len(checksum) == 32  # MD5 hex length
        # Checksum should be deterministic
        assert checksum == exporter.compute_checksum(data)

    def test_content_type(self):
        """Test content type detection."""
        config = CloudExporterConfig(provider="aws", bucket_name="bucket")

        class TestExporter(BaseCloudExporter):
            def export_batch(self, batch):
                return ExportResult(success=True)

            def health_check(self):
                return True

        exporter = TestExporter(config)
        assert exporter.get_content_type() == "application/x-ndjson"

        config.format = ExportFormat.PARQUET
        assert exporter.get_content_type() == "application/vnd.apache.parquet"

    def test_content_encoding(self):
        """Test content encoding detection."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="bucket",
            compression=CompressionType.GZIP,
        )

        class TestExporter(BaseCloudExporter):
            def export_batch(self, batch):
                return ExportResult(success=True)

            def health_check(self):
                return True

        exporter = TestExporter(config)
        assert exporter.get_content_encoding() == "gzip"

        config.compression = CompressionType.NONE
        assert exporter.get_content_encoding() is None


class TestS3Exporter:
    """Tests for S3Exporter."""

    def test_initialization(self):
        """Test S3 exporter initialization."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="my-bucket",
            region="us-west-2",
        )

        with patch("proxilion.audit.exporters.aws_s3.HAS_BOTO3", False):
            # Without boto3, should use urllib fallback
            exporter = S3Exporter(config)
            assert exporter is not None

    def test_export_batch_boto3(self, sample_audit_event: AuditEventV2):
        """Test exporting batch with boto3."""
        # Skip if boto3 is not installed
        try:
            import boto3 as _boto3
        except ImportError:
            pytest.skip("boto3 not installed")

        config = CloudExporterConfig(
            provider="aws",
            bucket_name="test-bucket",
            region="us-east-1",
        )

        with patch.object(_boto3, "client") as mock_client_factory:
            mock_client = MagicMock()
            mock_client_factory.return_value = mock_client

            exporter = S3Exporter(config)
            batch = ExportBatch(
                batch_id="test_batch",
                events=[sample_audit_event],
            )

            result = exporter.export_batch(batch)

            assert result.success is True
            assert result.events_exported == 1
            assert result.destination.startswith("s3://")
            mock_client.put_object.assert_called_once()

    def test_sigv4_signing(self):
        """Test SigV4 signature generation."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="test-bucket",
            region="us-east-1",
        )

        with patch("proxilion.audit.exporters.aws_s3.HAS_BOTO3", False):
            exporter = S3Exporter(config)
            exporter._aws_access_key = "AKIAIOSFODNN7EXAMPLE"
            exporter._aws_secret_key = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

            headers = exporter._sign_request(
                method="PUT",
                url="https://s3.us-east-1.amazonaws.com/test-bucket/test.txt",
                host="s3.us-east-1.amazonaws.com",
                region="us-east-1",
                service="s3",
                payload=b"test content",
            )

            assert "Authorization" in headers
            assert "AWS4-HMAC-SHA256" in headers["Authorization"]
            assert "x-amz-date" in headers


class TestS3DataLakeExporter:
    """Tests for S3DataLakeExporter."""

    def test_hive_partitioned_key(self):
        """Test Hive-style partition key generation."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="data-lake",
            prefix="audit/",
        )

        with patch("proxilion.audit.exporters.aws_s3.HAS_BOTO3", False):
            exporter = S3DataLakeExporter(config, use_hive_partitions=True)
            timestamp = datetime(2024, 3, 15, 14, tzinfo=timezone.utc)
            key = exporter.generate_key(timestamp=timestamp, batch_id="batch_001")

            assert "year=2024" in key
            assert "month=03" in key
            assert "day=15" in key
            assert "hour=14" in key

    def test_athena_ddl_generation(self):
        """Test Athena CREATE TABLE DDL generation."""
        config = CloudExporterConfig(
            provider="aws",
            bucket_name="data-lake",
            prefix="audit/",
        )

        with patch("proxilion.audit.exporters.aws_s3.HAS_BOTO3", False):
            exporter = S3DataLakeExporter(config)
            ddl = exporter.get_athena_table_ddl("audit_events", "analytics")

            assert "CREATE EXTERNAL TABLE" in ddl
            assert "analytics" in ddl
            assert "audit_events" in ddl
            assert "PARTITIONED BY" in ddl
            assert "s3://data-lake/audit/" in ddl


class TestGCSExporter:
    """Tests for GCSExporter."""

    def test_initialization(self):
        """Test GCS exporter initialization."""
        config = CloudExporterConfig(
            provider="gcp",
            bucket_name="my-bucket",
        )

        with patch("proxilion.audit.exporters.gcp_storage.HAS_GCS", False):
            exporter = GCSExporter(config)
            assert exporter is not None

    def test_export_batch_gcs(self, sample_audit_event: AuditEventV2):
        """Test exporting batch with google-cloud-storage."""
        import sys

        # Create a mock gcs module
        mock_gcs_module = MagicMock()
        mock_client = MagicMock()
        mock_bucket = MagicMock()
        mock_blob = MagicMock()

        mock_gcs_module.Client.return_value = mock_client
        mock_client.bucket.return_value = mock_bucket
        mock_bucket.blob.return_value = mock_blob

        config = CloudExporterConfig(
            provider="gcp",
            bucket_name="test-bucket",
        )

        # Patch both HAS_GCS and inject gcs into module namespace
        with patch("proxilion.audit.exporters.gcp_storage.HAS_GCS", True):
            import proxilion.audit.exporters.gcp_storage as gcp_module
            original_gcs = getattr(gcp_module, "gcs", None)
            gcp_module.gcs = mock_gcs_module

            try:
                exporter = GCSExporter(config)
                exporter._bucket = mock_bucket

                batch = ExportBatch(
                    batch_id="test_batch",
                    events=[sample_audit_event],
                )

                result = exporter.export_batch(batch)

                assert result.success is True
                assert result.destination.startswith("gs://")
            finally:
                # Restore original state
                if original_gcs is None:
                    if hasattr(gcp_module, "gcs"):
                        delattr(gcp_module, "gcs")
                else:
                    gcp_module.gcs = original_gcs


class TestAzureBlobExporter:
    """Tests for AzureBlobExporter."""

    def test_initialization(self):
        """Test Azure exporter initialization."""
        config = CloudExporterConfig(
            provider="azure",
            bucket_name="my-container",
        )

        with patch("proxilion.audit.exporters.azure_storage.HAS_AZURE_STORAGE", False):
            with patch.dict("os.environ", {"AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;AccountName=test;AccountKey=dGVzdA==;EndpointSuffix=core.windows.net"}):
                exporter = AzureBlobExporter(config)
                assert exporter is not None

    def test_connection_string_parsing(self):
        """Test Azure connection string parsing."""
        config = CloudExporterConfig(
            provider="azure",
            bucket_name="container",
        )

        with patch("proxilion.audit.exporters.azure_storage.HAS_AZURE_STORAGE", False):
            with patch.dict("os.environ", {"AZURE_STORAGE_CONNECTION_STRING": "DefaultEndpointsProtocol=https;AccountName=mystorageaccount;AccountKey=YWJjZGVm;EndpointSuffix=core.windows.net"}):
                exporter = AzureBlobExporter(config)

                assert exporter._account_name == "mystorageaccount"
                assert exporter._account_key == "YWJjZGVm"


class TestMultiCloudExporter:
    """Tests for MultiCloudExporter."""

    def _create_mock_exporter(self, should_succeed: bool = True) -> MagicMock:
        """Create a mock exporter."""
        mock = MagicMock(spec=BaseCloudExporter)
        mock.config = CloudExporterConfig(provider="aws", bucket_name="test")

        if should_succeed:
            mock.export_batch.return_value = ExportResult(
                success=True,
                events_exported=1,
                batch_id="test",
                destination="mock://bucket/key",
            )
        else:
            mock.export_batch.return_value = ExportResult(
                success=False,
                batch_id="test",
                error="Mock failure",
            )

        return mock

    def test_multi_exporter_all_succeed(self, sample_audit_event: AuditEventV2):
        """Test multi-exporter when all destinations succeed."""
        mock1 = self._create_mock_exporter(True)
        mock2 = self._create_mock_exporter(True)

        multi = MultiCloudExporter(
            exporters=[mock1, mock2],
            strategy=FailureStrategy.REQUIRE_ALL,
        )

        result = multi.export([sample_audit_event])

        assert result.success is True
        assert result.successful_destinations == 2
        assert result.failed_destinations == 0

    def test_multi_exporter_one_fails_require_all(self, sample_audit_event: AuditEventV2):
        """Test multi-exporter with REQUIRE_ALL when one fails."""
        mock1 = self._create_mock_exporter(True)
        mock2 = self._create_mock_exporter(False)

        multi = MultiCloudExporter(
            exporters=[mock1, mock2],
            strategy=FailureStrategy.REQUIRE_ALL,
            retry_failed=False,
        )

        result = multi.export([sample_audit_event])

        assert result.success is False
        assert result.successful_destinations == 1
        assert result.failed_destinations == 1

    def test_multi_exporter_one_fails_require_one(self, sample_audit_event: AuditEventV2):
        """Test multi-exporter with REQUIRE_ONE when one fails."""
        mock1 = self._create_mock_exporter(True)
        mock2 = self._create_mock_exporter(False)

        multi = MultiCloudExporter(
            exporters=[mock1, mock2],
            strategy=FailureStrategy.REQUIRE_ONE,
            retry_failed=False,
        )

        result = multi.export([sample_audit_event])

        assert result.success is True  # One succeeded
        assert result.successful_destinations == 1

    def test_multi_exporter_best_effort(self, sample_audit_event: AuditEventV2):
        """Test multi-exporter with BEST_EFFORT strategy."""
        mock1 = self._create_mock_exporter(False)
        mock2 = self._create_mock_exporter(False)

        multi = MultiCloudExporter(
            exporters=[mock1, mock2],
            strategy=FailureStrategy.BEST_EFFORT,
            retry_failed=False,
        )

        result = multi.export([sample_audit_event])

        assert result.success is True  # Best effort always succeeds
        assert result.failed_destinations == 2

    def test_multi_exporter_require_majority(self, sample_audit_event: AuditEventV2):
        """Test multi-exporter with REQUIRE_MAJORITY strategy."""
        mock1 = self._create_mock_exporter(True)
        mock2 = self._create_mock_exporter(True)
        mock3 = self._create_mock_exporter(False)

        multi = MultiCloudExporter(
            exporters=[mock1, mock2, mock3],
            strategy=FailureStrategy.REQUIRE_MAJORITY,
            retry_failed=False,
        )

        result = multi.export([sample_audit_event])

        assert result.success is True  # 2/3 succeeded
        assert result.majority_succeeded is True

    def test_multi_exporter_fail_fast(self, sample_audit_event: AuditEventV2):
        """Test multi-exporter with FAIL_FAST strategy."""
        mock1 = self._create_mock_exporter(False)
        mock2 = self._create_mock_exporter(True)

        multi = MultiCloudExporter(
            exporters=[mock1, mock2],
            strategy=FailureStrategy.FAIL_FAST,
            parallel=False,  # Sequential to test fail-fast
            retry_failed=False,
        )

        result = multi.export([sample_audit_event])

        assert result.success is False
        # Second exporter may or may not be called depending on timing
        assert result.failed_destinations >= 1

    def test_multi_exporter_parallel_execution(self, sample_audit_event: AuditEventV2):
        """Test multi-exporter parallel execution."""
        # Create exporters with slight delay
        def slow_export(*args, **kwargs):
            time.sleep(0.1)
            return ExportResult(success=True, events_exported=1, batch_id="test")

        mock1 = MagicMock(spec=BaseCloudExporter)
        mock1.config = CloudExporterConfig(provider="aws", bucket_name="test")
        mock1.export_batch.side_effect = slow_export

        mock2 = MagicMock(spec=BaseCloudExporter)
        mock2.config = CloudExporterConfig(provider="gcp", bucket_name="test")
        mock2.export_batch.side_effect = slow_export

        multi = MultiCloudExporter(
            exporters=[mock1, mock2],
            parallel=True,
            retry_failed=False,
        )

        start = time.time()
        result = multi.export([sample_audit_event])
        duration = time.time() - start

        assert result.success is True
        # Parallel should be faster than sequential (2 * 0.1s)
        assert duration < 0.25

    def test_multi_exporter_health_check(self):
        """Test multi-exporter health check."""
        mock1 = self._create_mock_exporter()
        mock1.health_check.return_value = True

        mock2 = self._create_mock_exporter()
        mock2.health_check.return_value = False

        multi = MultiCloudExporter(exporters=[mock1, mock2])

        health = multi.health_check()

        assert health[0] is True
        assert health[1] is False

    def test_multi_exporter_configure(self):
        """Test multi-exporter configuration update."""
        multi = MultiCloudExporter(
            exporters=[],
            strategy=FailureStrategy.BEST_EFFORT,
            parallel=True,
        )

        multi.configure({
            "strategy": "require_all",
            "parallel": False,
            "max_retries": 5,
        })

        assert multi.strategy == FailureStrategy.REQUIRE_ALL
        assert multi.parallel is False
        assert multi.max_retries == 5

    def test_multi_export_result_helpers(self):
        """Test MultiExportResult helper methods."""
        result = MultiExportResult(
            success=True,
            results=[
                ExportResult(success=True, batch_id="1"),
                ExportResult(success=False, batch_id="2", error="failed"),
                ExportResult(success=True, batch_id="3"),
            ],
            successful_destinations=2,
            failed_destinations=1,
        )

        assert result.all_succeeded is False
        assert result.any_succeeded is True
        assert result.majority_succeeded is True
        assert len(result.get_failed_results()) == 1
        assert len(result.get_successful_results()) == 2


class TestExportResult:
    """Tests for ExportResult dataclass."""

    def test_successful_result(self):
        """Test creating a successful export result."""
        result = ExportResult(
            success=True,
            events_exported=100,
            batch_id="batch_001",
            destination="s3://bucket/key",
            duration_ms=150.5,
            bytes_written=10240,
            checksum="abc123",
        )

        assert result.success is True
        assert result.events_exported == 100
        assert result.error is None

    def test_failed_result(self):
        """Test creating a failed export result."""
        result = ExportResult(
            success=False,
            batch_id="batch_001",
            error="Connection timeout",
            duration_ms=5000.0,
        )

        assert result.success is False
        assert result.error == "Connection timeout"
        assert result.events_exported == 0
