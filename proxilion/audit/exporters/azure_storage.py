"""
Azure Blob Storage exporter for Proxilion audit logs.

Supports exporting audit logs to:
- Azure Blob Storage
- Azure Data Lake Storage Gen2 (ADLS)

Uses azure-storage-blob if available, falls back to urllib with SAS/connection string.
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
from base64 import b64decode, b64encode
from datetime import datetime, timezone

from proxilion.audit.exporters.cloud_base import (
    BaseCloudExporter,
    CloudExporterConfig,
    ExportBatch,
    ExportResult,
)

logger = logging.getLogger(__name__)

# Check for azure-storage-blob availability
try:
    from azure.identity import DefaultAzureCredential
    from azure.storage.blob import BlobServiceClient
    HAS_AZURE_STORAGE = True
except ImportError:
    HAS_AZURE_STORAGE = False


class AzureBlobExporter(BaseCloudExporter):
    """
    Export audit logs to Azure Blob Storage.

    Uses azure-storage-blob if installed, otherwise falls back to
    urllib with connection string or SAS token.

    Example:
        >>> config = CloudExporterConfig(
        ...     provider="azure",
        ...     bucket_name="audit-logs",  # Container name
        ...     prefix="proxilion/prod/",
        ... )
        >>> exporter = AzureBlobExporter(config)
        >>> result = exporter.export(events)
    """

    def __init__(self, config: CloudExporterConfig) -> None:
        """
        Initialize the Azure Blob exporter.

        Args:
            config: Exporter configuration.
        """
        super().__init__(config)
        self._client = None
        self._container_client = None
        self._connection_string: str | None = None
        self._account_name: str | None = None
        self._account_key: str | None = None
        self._sas_token: str | None = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the Azure Blob client."""
        if HAS_AZURE_STORAGE:
            self._init_azure_sdk_client()
        else:
            self._init_urllib_client()

    def _init_azure_sdk_client(self) -> None:
        """Initialize azure-storage-blob client."""
        # Try connection string first (from env or credentials file)
        connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")

        if self.config.credentials_path:
            creds = self._load_credentials_file(self.config.credentials_path)
            connection_string = creds.get("connection_string", connection_string)

        if connection_string:
            self._client = BlobServiceClient.from_connection_string(connection_string)
        elif self.config.use_instance_credentials:
            # Use DefaultAzureCredential (managed identity, etc.)
            account_url = self._get_account_url()
            credential = DefaultAzureCredential()
            self._client = BlobServiceClient(account_url, credential=credential)
        else:
            raise ValueError(
                "Azure credentials not configured. Set AZURE_STORAGE_CONNECTION_STRING "
                "or use credentials_path or use_instance_credentials."
            )

        self._container_client = self._client.get_container_client(
            self.config.bucket_name
        )

    def _init_urllib_client(self) -> None:
        """Initialize urllib-based client."""
        # Load connection string or credentials
        self._connection_string = os.environ.get("AZURE_STORAGE_CONNECTION_STRING")

        if self.config.credentials_path:
            creds = self._load_credentials_file(self.config.credentials_path)
            self._connection_string = creds.get("connection_string", self._connection_string)
            self._account_name = creds.get("account_name")
            self._account_key = creds.get("account_key")
            self._sas_token = creds.get("sas_token")

        # Parse connection string if provided
        if self._connection_string:
            self._parse_connection_string()

    def _load_credentials_file(self, path: str) -> dict[str, str]:
        """Load credentials from a JSON file."""
        try:
            with open(path) as f:
                return json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load credentials from {path}: {e}")
            return {}

    def _parse_connection_string(self) -> None:
        """Parse Azure connection string to extract credentials."""
        if not self._connection_string:
            return

        parts = {}
        for part in self._connection_string.split(";"):
            if "=" in part:
                key, value = part.split("=", 1)
                parts[key] = value

        self._account_name = parts.get("AccountName")
        self._account_key = parts.get("AccountKey")

    def _get_account_url(self) -> str:
        """Get the blob service account URL."""
        # Try to get from endpoint URL config
        if self.config.endpoint_url:
            return self.config.endpoint_url

        # Try to get account name from environment or credentials
        account_name = self._account_name or os.environ.get("AZURE_STORAGE_ACCOUNT")

        if not account_name:
            raise ValueError(
                "Azure storage account name not configured. Set endpoint_url, "
                "AZURE_STORAGE_ACCOUNT, or provide in credentials."
            )

        return f"https://{account_name}.blob.core.windows.net"

    def export_batch(self, batch: ExportBatch) -> ExportResult:
        """
        Export a batch to Azure Blob Storage.

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
            self.with_retry(self._upload_blob, key, data)

            duration_ms = (time.time() - start_time) * 1000

            account_url = self._get_account_url()
            destination = f"{account_url}/{self.config.bucket_name}/{key}"

            logger.info(
                f"Exported {batch.event_count} events to {destination}"
            )

            return ExportResult(
                success=True,
                events_exported=batch.event_count,
                batch_id=batch.batch_id,
                destination=destination,
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

    def _upload_blob(self, blob_name: str, data: bytes) -> None:
        """
        Upload a blob to Azure Storage.

        Args:
            blob_name: Blob name (path within container).
            data: Blob data.
        """
        if HAS_AZURE_STORAGE:
            self._upload_azure_sdk(blob_name, data)
        else:
            self._upload_urllib(blob_name, data)

    def _upload_azure_sdk(self, blob_name: str, data: bytes) -> None:
        """Upload using azure-storage-blob."""
        blob_client = self._container_client.get_blob_client(blob_name)
        blob_client.upload_blob(
            data,
            overwrite=True,
            content_settings={
                "content_type": self.get_content_type(),
            },
        )

    def _upload_urllib(self, blob_name: str, data: bytes) -> None:
        """Upload using urllib with Shared Key or SAS token."""
        if not self._account_name:
            raise ValueError(
                "Azure credentials not configured. Set AZURE_STORAGE_CONNECTION_STRING "
                "or provide account credentials."
            )

        # Build URL
        url = (
            f"https://{self._account_name}.blob.core.windows.net/"
            f"{self.config.bucket_name}/{blob_name}"
        )

        if self._sas_token:
            # Use SAS token
            url = f"{url}?{self._sas_token}"
            headers = self._get_blob_headers(data)
        elif self._account_key:
            # Use Shared Key authentication
            headers = self._sign_request(blob_name, data)
        else:
            raise ValueError("No authentication method available")

        request = urllib.request.Request(url, data=data, headers=headers, method="PUT")

        try:
            with urllib.request.urlopen(
                request, timeout=self.config.read_timeout
            ) as response:
                if response.status not in (200, 201):
                    raise ValueError(f"Azure upload failed with status {response.status}")
        except urllib.error.HTTPError as e:
            raise ValueError(f"Azure upload failed: {e.code} {e.reason}") from e

    def _get_blob_headers(self, data: bytes) -> dict[str, str]:
        """Get basic headers for blob upload."""
        return {
            "Content-Type": self.get_content_type(),
            "Content-Length": str(len(data)),
            "x-ms-blob-type": "BlockBlob",
            "x-ms-version": "2020-10-02",
        }

    def _sign_request(self, blob_name: str, data: bytes) -> dict[str, str]:
        """
        Sign a request using Azure Shared Key.

        Args:
            blob_name: Blob name.
            data: Request data.

        Returns:
            Dict of headers including Authorization.
        """
        # Current time in RFC 1123 format
        now = datetime.now(timezone.utc)
        x_ms_date = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
        x_ms_version = "2020-10-02"

        # Build canonical headers
        content_length = str(len(data))
        content_type = self.get_content_type()

        canonical_headers = (
            f"x-ms-blob-type:BlockBlob\n"
            f"x-ms-date:{x_ms_date}\n"
            f"x-ms-version:{x_ms_version}"
        )

        # Build canonical resource
        canonical_resource = f"/{self._account_name}/{self.config.bucket_name}/{blob_name}"

        # Build string to sign
        string_to_sign = (
            f"PUT\n"
            f"\n"  # Content-Encoding
            f"\n"  # Content-Language
            f"{content_length}\n"
            f"\n"  # Content-MD5
            f"{content_type}\n"
            f"\n"  # Date
            f"\n"  # If-Modified-Since
            f"\n"  # If-Match
            f"\n"  # If-None-Match
            f"\n"  # If-Unmodified-Since
            f"\n"  # Range
            f"{canonical_headers}\n"
            f"{canonical_resource}"
        )

        # Sign with HMAC-SHA256
        key = b64decode(self._account_key)
        signature = b64encode(
            hmac.new(key, string_to_sign.encode(), hashlib.sha256).digest()
        ).decode()

        return {
            "Authorization": f"SharedKey {self._account_name}:{signature}",
            "Content-Type": content_type,
            "Content-Length": content_length,
            "x-ms-blob-type": "BlockBlob",
            "x-ms-date": x_ms_date,
            "x-ms-version": x_ms_version,
        }

    def health_check(self) -> bool:
        """
        Check if we can connect to Azure Blob Storage.

        Returns:
            True if healthy.
        """
        try:
            if HAS_AZURE_STORAGE:
                self._container_client.get_container_properties()
            else:
                # Try to get container properties
                if not self._account_name:
                    logger.error("Account name not configured")
                    return False
                url = (
                    f"https://{self._account_name}.blob.core.windows.net/"
                    f"{self.config.bucket_name}?restype=container"
                )

                if self._sas_token:
                    url = f"{url}&{self._sas_token}"
                    headers = {"x-ms-version": "2020-10-02"}
                else:
                    headers = self._sign_container_request()

                request = urllib.request.Request(url, headers=headers)
                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status == 200

            return True
        except Exception as e:
            logger.warning(f"Azure health check failed: {e}")
            return False

    def _sign_container_request(self) -> dict[str, str]:
        """Sign a GET container request."""
        now = datetime.now(timezone.utc)
        x_ms_date = now.strftime("%a, %d %b %Y %H:%M:%S GMT")
        x_ms_version = "2020-10-02"

        canonical_headers = (
            f"x-ms-date:{x_ms_date}\n"
            f"x-ms-version:{x_ms_version}"
        )

        canonical_resource = (
            f"/{self._account_name}/{self.config.bucket_name}\n"
            f"restype:container"
        )

        # Build string to sign (GET + 11 empty headers + canonical headers + resource)
        empty_headers = "\n" * 11
        string_to_sign = (
            f"GET\n"
            f"{empty_headers}"
            f"{canonical_headers}\n"
            f"{canonical_resource}"
        )

        key = b64decode(self._account_key)
        signature = b64encode(
            hmac.new(key, string_to_sign.encode(), hashlib.sha256).digest()
        ).decode()

        return {
            "Authorization": f"SharedKey {self._account_name}:{signature}",
            "x-ms-date": x_ms_date,
            "x-ms-version": x_ms_version,
        }

    def list_exports(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        max_results: int = 1000,
    ) -> list[str]:
        """
        List exported blobs in the container.

        Args:
            start_date: Filter to exports after this date.
            end_date: Filter to exports before this date.
            max_results: Maximum number of results to return.

        Returns:
            List of blob names.
        """
        if not HAS_AZURE_STORAGE:
            raise NotImplementedError("list_exports requires azure-storage-blob")

        prefix = self.config.prefix
        if start_date:
            prefix += f"{start_date.year:04d}/"

        blobs = self._container_client.list_blobs(
            name_starts_with=prefix,
            results_per_page=max_results,
        )

        names = []
        for blob in blobs:
            # Filter by date if needed
            if end_date:
                parts = blob.name.split("/")
                if len(parts) >= 4:
                    try:
                        year = int(parts[-4])
                        month = int(parts[-3])
                        day = int(parts[-2])
                        blob_date = datetime(year, month, day, tzinfo=timezone.utc)
                        if blob_date > end_date:
                            continue
                    except (ValueError, IndexError):
                        pass

            names.append(blob.name)

            if len(names) >= max_results:
                break

        return names


class AzureDataLakeExporter(AzureBlobExporter):
    """
    Export audit logs to Azure Data Lake Storage Gen2.

    Extends AzureBlobExporter with:
    - Hierarchical namespace support
    - Hive-style partition naming
    - Integration hints for Azure Synapse Analytics

    Example:
        >>> config = CloudExporterConfig(
        ...     provider="azure",
        ...     bucket_name="audit-filesystem",  # ADLS filesystem
        ...     prefix="proxilion/prod/",
        ... )
        >>> exporter = AzureDataLakeExporter(config)
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
            use_hive_partitions: Use Hive-style partition naming.
        """
        super().__init__(config)
        self.use_hive_partitions = use_hive_partitions

    def generate_key(
        self,
        timestamp: datetime | None = None,
        batch_id: str | None = None,
    ) -> str:
        """
        Generate a path with Hive-style partitioning.

        Format: {prefix}/year=YYYY/month=MM/day=DD/hour=HH/{batch_id}.{ext}

        Args:
            timestamp: Timestamp for partitioning.
            batch_id: Unique batch identifier.

        Returns:
            The generated path.
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

    def get_synapse_table_sql(
        self,
        table_name: str,
        schema: str = "dbo",
    ) -> str:
        """
        Generate Azure Synapse Analytics CREATE EXTERNAL TABLE SQL.

        Args:
            table_name: Name for the external table.
            schema: SQL schema name.

        Returns:
            CREATE EXTERNAL TABLE SQL statement.
        """
        location = f"abfss://{self.config.bucket_name}@{self._account_name}.dfs.core.windows.net/{self.config.prefix}"

        sql = f"""
-- Create data source (run once)
CREATE EXTERNAL DATA SOURCE AuditDataLake
WITH (
    LOCATION = '{location}',
    CREDENTIAL = [YourCredential]
);

-- Create file format
CREATE EXTERNAL FILE FORMAT AuditJsonFormat
WITH (
    FORMAT_TYPE = DELIMITEDTEXT,
    FORMAT_OPTIONS (
        FIELD_TERMINATOR = '|',  -- Not used for JSON but required
        STRING_DELIMITER = '',
        FIRST_ROW = 1
    )
);

-- Create external table
CREATE EXTERNAL TABLE [{schema}].[{table_name}] (
    [event_id] NVARCHAR(100),
    [timestamp] DATETIME2,
    [sequence_number] BIGINT,
    [event_type] NVARCHAR(100),
    [user_id] NVARCHAR(200),
    [user_roles] NVARCHAR(1000),
    [session_id] NVARCHAR(200),
    [agent_id] NVARCHAR(200),
    [tool_name] NVARCHAR(200),
    [tool_arguments] NVARCHAR(MAX),
    [authorization_allowed] BIT,
    [authorization_reason] NVARCHAR(500),
    [policies_evaluated] NVARCHAR(1000),
    [event_hash] NVARCHAR(100),
    [previous_hash] NVARCHAR(100)
)
WITH (
    LOCATION = '',
    DATA_SOURCE = AuditDataLake,
    FILE_FORMAT = AuditJsonFormat,
    REJECT_TYPE = VALUE,
    REJECT_VALUE = 0
);
"""
        return sql.strip()
