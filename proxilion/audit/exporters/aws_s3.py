"""
AWS S3 exporter for Proxilion audit logs.

Supports exporting audit logs to:
- Amazon S3
- S3-compatible storage (MinIO, DigitalOcean Spaces, etc.)
- AWS Data Lake with Athena/Glue integration

Uses boto3 if available, falls back to stdlib urllib with SigV4 signing.
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from proxilion.audit.exporters.cloud_base import (
    BaseCloudExporter,
    CloudExporterConfig,
    ExportBatch,
    ExportResult,
)

logger = logging.getLogger(__name__)

# Check for boto3 availability
try:
    import boto3
    from botocore.config import Config as BotoConfig
    HAS_BOTO3 = True
except ImportError:
    HAS_BOTO3 = False


class S3Exporter(BaseCloudExporter):
    """
    Export audit logs to Amazon S3 or S3-compatible storage.

    Uses boto3 if installed, otherwise falls back to stdlib urllib
    with AWS Signature Version 4 signing.

    Example:
        >>> config = CloudExporterConfig(
        ...     provider="aws",
        ...     bucket_name="my-audit-logs",
        ...     prefix="proxilion/prod/",
        ...     region="us-west-2",
        ... )
        >>> exporter = S3Exporter(config)
        >>> result = exporter.export(events)
    """

    def __init__(self, config: CloudExporterConfig) -> None:
        """
        Initialize the S3 exporter.

        Args:
            config: Exporter configuration.
        """
        super().__init__(config)
        self._client = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the S3 client."""
        if HAS_BOTO3:
            self._init_boto3_client()
        else:
            self._init_urllib_client()

    def _init_boto3_client(self) -> None:
        """Initialize boto3 S3 client."""
        client_config = BotoConfig(
            connect_timeout=self.config.connection_timeout,
            read_timeout=self.config.read_timeout,
            retries={"max_attempts": 0},  # We handle retries ourselves
        )

        client_kwargs: dict[str, Any] = {
            "config": client_config,
        }

        if self.config.region:
            client_kwargs["region_name"] = self.config.region

        if self.config.endpoint_url:
            client_kwargs["endpoint_url"] = self.config.endpoint_url

        if self.config.credentials_path:
            # Load credentials from file
            creds = self._load_credentials_file(self.config.credentials_path)
            client_kwargs["aws_access_key_id"] = creds.get("aws_access_key_id")
            client_kwargs["aws_secret_access_key"] = creds.get("aws_secret_access_key")
            if "aws_session_token" in creds:
                client_kwargs["aws_session_token"] = creds["aws_session_token"]

        self._client = boto3.client("s3", **client_kwargs)

    def _init_urllib_client(self) -> None:
        """Initialize urllib-based client with SigV4 signing."""
        # For urllib fallback, we'll use environment variables or credentials file
        self._aws_access_key = os.environ.get("AWS_ACCESS_KEY_ID")
        self._aws_secret_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
        self._aws_session_token = os.environ.get("AWS_SESSION_TOKEN")

        if self.config.credentials_path:
            creds = self._load_credentials_file(self.config.credentials_path)
            self._aws_access_key = creds.get("aws_access_key_id", self._aws_access_key)
            self._aws_secret_key = creds.get("aws_secret_access_key", self._aws_secret_key)
            self._aws_session_token = creds.get("aws_session_token", self._aws_session_token)

    def _load_credentials_file(self, path: str) -> dict[str, str]:
        """Load credentials from a JSON file."""
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load credentials from {path}: {e}")
            return {}

    def export_batch(self, batch: ExportBatch) -> ExportResult:
        """
        Export a batch to S3.

        Args:
            batch: The batch to export.

        Returns:
            ExportResult with success/failure information.
        """
        start_time = time.time()

        try:
            # Prepare data
            data = batch.to_bytes(self.config.compression)
            key = self.generate_key(batch.created_at, batch.batch_id)
            checksum = self.compute_checksum(data)

            # Upload with retry
            self.with_retry(self._upload_object, key, data)

            duration_ms = (time.time() - start_time) * 1000

            logger.info(
                f"Exported {batch.event_count} events to s3://{self.config.bucket_name}/{key}"
            )

            return ExportResult(
                success=True,
                events_exported=batch.event_count,
                batch_id=batch.batch_id,
                destination=f"s3://{self.config.bucket_name}/{key}",
                duration_ms=duration_ms,
                bytes_written=len(data),
                checksum=checksum,
            )

        except Exception as e:
            duration_ms = (time.time() - start_time) * 1000
            logger.error(f"Failed to export batch {batch.batch_id}: {e}")

            return ExportResult(
                success=False,
                events_exported=0,
                batch_id=batch.batch_id,
                error=str(e),
                duration_ms=duration_ms,
            )

    def _upload_object(self, key: str, data: bytes) -> None:
        """
        Upload an object to S3.

        Args:
            key: Object key.
            data: Object data.
        """
        if HAS_BOTO3:
            self._upload_boto3(key, data)
        else:
            self._upload_urllib(key, data)

    def _upload_boto3(self, key: str, data: bytes) -> None:
        """Upload using boto3."""
        extra_args: dict[str, str] = {
            "ContentType": self.get_content_type(),
        }

        encoding = self.get_content_encoding()
        if encoding:
            extra_args["ContentEncoding"] = encoding

        self._client.put_object(
            Bucket=self.config.bucket_name,
            Key=key,
            Body=data,
            **extra_args,
        )

    def _upload_urllib(self, key: str, data: bytes) -> None:
        """Upload using urllib with SigV4 signing."""
        if not self._aws_access_key or not self._aws_secret_key:
            raise ValueError(
                "AWS credentials not configured. Set AWS_ACCESS_KEY_ID and "
                "AWS_SECRET_ACCESS_KEY environment variables or use credentials_path."
            )

        region = self.config.region or "us-east-1"
        service = "s3"
        host = self.config.endpoint_url or f"s3.{region}.amazonaws.com"

        # Remove protocol from host if present
        if host.startswith("https://"):
            host = host[8:]
        elif host.startswith("http://"):
            host = host[7:]

        # Build URL
        url = f"https://{host}/{self.config.bucket_name}/{key}"

        # Create signed request
        headers = self._sign_request(
            method="PUT",
            url=url,
            host=host,
            region=region,
            service=service,
            payload=data,
        )

        headers["Content-Type"] = self.get_content_type()
        encoding = self.get_content_encoding()
        if encoding:
            headers["Content-Encoding"] = encoding

        # Make request
        request = urllib.request.Request(url, data=data, headers=headers, method="PUT")

        try:
            with urllib.request.urlopen(
                request, timeout=self.config.read_timeout
            ) as response:
                if response.status not in (200, 201, 204):
                    raise ValueError(f"S3 upload failed with status {response.status}")
        except urllib.error.HTTPError as e:
            raise ValueError(f"S3 upload failed: {e.code} {e.reason}") from e

    def _sign_request(
        self,
        method: str,
        url: str,
        host: str,
        region: str,
        service: str,
        payload: bytes,
    ) -> dict[str, str]:
        """
        Sign a request using AWS Signature Version 4.

        Args:
            method: HTTP method.
            url: Request URL.
            host: Host header value.
            region: AWS region.
            service: AWS service name.
            payload: Request payload.

        Returns:
            Dict of headers including Authorization.
        """
        # Parse URL
        parsed = urllib.parse.urlparse(url)
        canonical_uri = parsed.path or "/"
        canonical_querystring = parsed.query

        # Current time
        t = datetime.now(timezone.utc)
        amz_date = t.strftime("%Y%m%dT%H%M%SZ")
        date_stamp = t.strftime("%Y%m%d")

        # Create payload hash
        payload_hash = hashlib.sha256(payload).hexdigest()

        # Create canonical headers
        headers_to_sign = {
            "host": host,
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
        }

        if self._aws_session_token:
            headers_to_sign["x-amz-security-token"] = self._aws_session_token

        signed_headers = ";".join(sorted(headers_to_sign.keys()))

        canonical_headers = ""
        for key in sorted(headers_to_sign.keys()):
            canonical_headers += f"{key}:{headers_to_sign[key]}\n"

        # Create canonical request
        canonical_request = (
            f"{method}\n"
            f"{canonical_uri}\n"
            f"{canonical_querystring}\n"
            f"{canonical_headers}\n"
            f"{signed_headers}\n"
            f"{payload_hash}"
        )

        # Create string to sign
        algorithm = "AWS4-HMAC-SHA256"
        credential_scope = f"{date_stamp}/{region}/{service}/aws4_request"
        string_to_sign = (
            f"{algorithm}\n"
            f"{amz_date}\n"
            f"{credential_scope}\n"
            f"{hashlib.sha256(canonical_request.encode()).hexdigest()}"
        )

        # Create signing key
        def sign(key: bytes, msg: str) -> bytes:
            return hmac.new(key, msg.encode(), hashlib.sha256).digest()

        k_date = sign(f"AWS4{self._aws_secret_key}".encode(), date_stamp)
        k_region = sign(k_date, region)
        k_service = sign(k_region, service)
        k_signing = sign(k_service, "aws4_request")

        # Create signature
        signature = hmac.new(k_signing, string_to_sign.encode(), hashlib.sha256).hexdigest()

        # Create authorization header
        authorization_header = (
            f"{algorithm} "
            f"Credential={self._aws_access_key}/{credential_scope}, "
            f"SignedHeaders={signed_headers}, "
            f"Signature={signature}"
        )

        # Build final headers
        result_headers = {
            "x-amz-date": amz_date,
            "x-amz-content-sha256": payload_hash,
            "Authorization": authorization_header,
        }

        if self._aws_session_token:
            result_headers["x-amz-security-token"] = self._aws_session_token

        return result_headers

    def health_check(self) -> bool:
        """
        Check if we can connect to S3.

        Returns:
            True if healthy.
        """
        try:
            if HAS_BOTO3:
                self._client.head_bucket(Bucket=self.config.bucket_name)
            else:
                # Try to list bucket (HEAD not easily done with urllib)
                region = self.config.region or "us-east-1"
                host = self.config.endpoint_url or f"s3.{region}.amazonaws.com"
                if host.startswith("https://"):
                    host = host[8:]
                url = f"https://{host}/{self.config.bucket_name}?max-keys=1"

                headers = self._sign_request(
                    method="GET",
                    url=url,
                    host=host,
                    region=region,
                    service="s3",
                    payload=b"",
                )

                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status == 200

            return True
        except Exception as e:
            logger.warning(f"S3 health check failed: {e}")
            return False

    def list_exports(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        max_keys: int = 1000,
    ) -> list[str]:
        """
        List exported files in the bucket.

        Args:
            start_date: Filter to exports after this date.
            end_date: Filter to exports before this date.
            max_keys: Maximum number of keys to return.

        Returns:
            List of object keys.
        """
        if not HAS_BOTO3:
            raise NotImplementedError("list_exports requires boto3")

        prefix = self.config.prefix

        # Add date prefix if filtering
        if start_date:
            prefix += f"{start_date.year:04d}/"

        paginator = self._client.get_paginator("list_objects_v2")
        pages = paginator.paginate(
            Bucket=self.config.bucket_name,
            Prefix=prefix,
            MaxKeys=max_keys,
        )

        keys = []
        for page in pages:
            for obj in page.get("Contents", []):
                key = obj["Key"]

                # Filter by date if needed
                if end_date:
                    # Extract date from key path
                    parts = key.split("/")
                    if len(parts) >= 4:
                        try:
                            year = int(parts[-4])
                            month = int(parts[-3])
                            day = int(parts[-2])
                            key_date = datetime(year, month, day, tzinfo=timezone.utc)
                            if key_date > end_date:
                                continue
                        except (ValueError, IndexError):
                            pass

                keys.append(key)

                if len(keys) >= max_keys:
                    break

        return keys


class S3DataLakeExporter(S3Exporter):
    """
    Export audit logs to S3 with Data Lake / Athena optimization.

    Extends S3Exporter with:
    - Partitioned paths compatible with Athena/Glue
    - Optional Parquet format for analytics
    - Hive-style partition naming

    Example:
        >>> config = CloudExporterConfig(
        ...     provider="aws",
        ...     bucket_name="my-data-lake",
        ...     prefix="audit/proxilion/",
        ...     format=ExportFormat.PARQUET,
        ... )
        >>> exporter = S3DataLakeExporter(config)
    """

    def __init__(
        self,
        config: CloudExporterConfig,
        use_hive_partitions: bool = True,
    ) -> None:
        """
        Initialize the Data Lake exporter.

        Args:
            config: Exporter configuration.
            use_hive_partitions: Use Hive-style partition naming (year=YYYY/).
        """
        super().__init__(config)
        self.use_hive_partitions = use_hive_partitions

    def generate_key(
        self,
        timestamp: datetime | None = None,
        batch_id: str | None = None,
    ) -> str:
        """
        Generate an object key with Hive-style partitioning.

        Format: {prefix}/year=YYYY/month=MM/day=DD/hour=HH/{batch_id}.{ext}

        Args:
            timestamp: Timestamp for partitioning.
            batch_id: Unique batch identifier.

        Returns:
            The generated object key.
        """
        if timestamp is None:
            timestamp = datetime.now(timezone.utc)

        if batch_id is None:
            with self._lock:
                self._batch_counter += 1
                batch_id = f"{timestamp.strftime('%Y%m%d%H%M%S')}_{self._batch_counter:06d}"

        # Determine file extension
        ext = self.config.format.value
        if self.config.compression.value != "none":
            ext += f".{self.config.compression.value}"

        # Build partitioned path
        if self.use_hive_partitions:
            key = (
                f"{self.config.prefix}"
                f"year={timestamp.year:04d}/"
                f"month={timestamp.month:02d}/"
                f"day={timestamp.day:02d}/"
                f"hour={timestamp.hour:02d}/"
                f"{batch_id}.{ext}"
            )
        else:
            key = super().generate_key(timestamp, batch_id)

        return key

    def get_athena_table_ddl(
        self,
        table_name: str,
        database: str = "default",
    ) -> str:
        """
        Generate Athena CREATE TABLE DDL for the audit logs.

        Args:
            table_name: Name for the Athena table.
            database: Athena database name.

        Returns:
            CREATE TABLE DDL statement.
        """
        location = f"s3://{self.config.bucket_name}/{self.config.prefix}"

        if self.config.format.value == "parquet":
            serde = "org.apache.hadoop.hive.ql.io.parquet.serde.ParquetHiveSerDe"
            input_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetInputFormat"
            output_format = "org.apache.hadoop.hive.ql.io.parquet.MapredParquetOutputFormat"
        else:
            serde = "org.openx.data.jsonserde.JsonSerDe"
            input_format = "org.apache.hadoop.mapred.TextInputFormat"
            output_format = "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat"

        ddl = f"""
CREATE EXTERNAL TABLE IF NOT EXISTS `{database}`.`{table_name}` (
    `event_id` string,
    `timestamp` timestamp,
    `sequence_number` bigint,
    `event_type` string,
    `user_id` string,
    `user_roles` array<string>,
    `session_id` string,
    `agent_id` string,
    `tool_name` string,
    `tool_arguments` string,
    `authorization_allowed` boolean,
    `authorization_reason` string,
    `policies_evaluated` array<string>,
    `event_hash` string,
    `previous_hash` string
)
PARTITIONED BY (
    `year` int,
    `month` int,
    `day` int,
    `hour` int
)
ROW FORMAT SERDE '{serde}'
STORED AS INPUTFORMAT '{input_format}'
OUTPUTFORMAT '{output_format}'
LOCATION '{location}'
TBLPROPERTIES ('has_encrypted_data'='false');
"""
        return ddl.strip()

    def get_glue_schema(self) -> dict[str, Any]:
        """
        Get Glue catalog schema for the audit logs.

        Returns:
            Schema dictionary for Glue catalog.
        """
        columns = [
            {"Name": "event_id", "Type": "string"},
            {"Name": "timestamp", "Type": "timestamp"},
            {"Name": "sequence_number", "Type": "bigint"},
            {"Name": "event_type", "Type": "string"},
            {"Name": "user_id", "Type": "string"},
            {"Name": "user_roles", "Type": "array<string>"},
            {"Name": "session_id", "Type": "string"},
            {"Name": "agent_id", "Type": "string"},
            {"Name": "tool_name", "Type": "string"},
            {"Name": "tool_arguments", "Type": "string"},
            {"Name": "authorization_allowed", "Type": "boolean"},
            {"Name": "authorization_reason", "Type": "string"},
            {"Name": "policies_evaluated", "Type": "array<string>"},
            {"Name": "event_hash", "Type": "string"},
            {"Name": "previous_hash", "Type": "string"},
        ]

        partition_keys = [
            {"Name": "year", "Type": "int"},
            {"Name": "month", "Type": "int"},
            {"Name": "day", "Type": "int"},
            {"Name": "hour", "Type": "int"},
        ]

        return {
            "Columns": columns,
            "PartitionKeys": partition_keys,
            "Location": f"s3://{self.config.bucket_name}/{self.config.prefix}",
            "InputFormat": "org.apache.hadoop.mapred.TextInputFormat",
            "OutputFormat": "org.apache.hadoop.hive.ql.io.HiveIgnoreKeyTextOutputFormat",
            "SerdeInfo": {
                "SerializationLibrary": "org.openx.data.jsonserde.JsonSerDe",
            },
        }
