"""
Google Cloud Storage exporter for Proxilion audit logs.

Supports exporting audit logs to:
- Google Cloud Storage
- BigQuery (for analytics)

Uses google-cloud-storage if available, falls back to urllib with OAuth2.
"""

from __future__ import annotations

import json
import logging
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from typing import Any

from proxilion.audit.events import AuditEventV2
from proxilion.audit.exporters.cloud_base import (
    BaseCloudExporter,
    CloudExporterConfig,
    ExportBatch,
    ExportResult,
)

logger = logging.getLogger(__name__)

# Check for google-cloud-storage availability
try:
    from google.cloud import storage as gcs
    from google.oauth2 import service_account
    HAS_GCS = True
except ImportError:
    HAS_GCS = False

# Check for google-cloud-bigquery availability
try:
    from google.cloud import bigquery
    HAS_BIGQUERY = True
except ImportError:
    HAS_BIGQUERY = False


class GCSExporter(BaseCloudExporter):
    """
    Export audit logs to Google Cloud Storage.

    Uses google-cloud-storage if installed, otherwise falls back to
    urllib with Application Default Credentials or service account.

    Example:
        >>> config = CloudExporterConfig(
        ...     provider="gcp",
        ...     bucket_name="my-audit-logs",
        ...     prefix="proxilion/prod/",
        ... )
        >>> exporter = GCSExporter(config)
        >>> result = exporter.export(events)
    """

    def __init__(self, config: CloudExporterConfig) -> None:
        """
        Initialize the GCS exporter.

        Args:
            config: Exporter configuration.
        """
        super().__init__(config)
        self._client = None
        self._bucket = None
        self._access_token: str | None = None
        self._token_expiry: float = 0
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize the GCS client."""
        if HAS_GCS:
            self._init_gcs_client()
        else:
            self._init_urllib_client()

    def _init_gcs_client(self) -> None:
        """Initialize google-cloud-storage client."""
        if self.config.credentials_path:
            credentials = service_account.Credentials.from_service_account_file(
                self.config.credentials_path,
                scopes=["https://www.googleapis.com/auth/devstorage.read_write"],
            )
            self._client = gcs.Client(credentials=credentials)
        else:
            # Use Application Default Credentials
            self._client = gcs.Client()

        self._bucket = self._client.bucket(self.config.bucket_name)

    def _init_urllib_client(self) -> None:
        """Initialize urllib-based client."""
        # For urllib fallback, we need credentials
        if self.config.credentials_path:
            self._load_service_account()

    def _load_service_account(self) -> None:
        """Load service account credentials from file."""
        try:
            with open(self.config.credentials_path) as f:
                self._service_account = json.load(f)
        except Exception as e:
            logger.warning(f"Failed to load service account: {e}")
            self._service_account = None

    def _get_access_token(self) -> str:
        """
        Get OAuth2 access token.

        Returns:
            Access token string.
        """
        # Check if we have a cached valid token
        if self._access_token and time.time() < self._token_expiry:
            return self._access_token

        if not hasattr(self, "_service_account") or not self._service_account:
            raise ValueError(
                "GCP credentials not configured. Set credentials_path or use "
                "Application Default Credentials with google-cloud-storage."
            )

        # Create JWT for service account
        from base64 import urlsafe_b64encode

        now = int(time.time())
        expiry = now + 3600  # 1 hour

        header = {"alg": "RS256", "typ": "JWT"}
        payload = {
            "iss": self._service_account["client_email"],
            "scope": "https://www.googleapis.com/auth/devstorage.read_write",
            "aud": "https://oauth2.googleapis.com/token",
            "iat": now,
            "exp": expiry,
        }

        # Encode header and payload
        header_b64 = urlsafe_b64encode(json.dumps(header).encode()).rstrip(b"=")
        payload_b64 = urlsafe_b64encode(json.dumps(payload).encode()).rstrip(b"=")
        signing_input = header_b64 + b"." + payload_b64

        # Sign with RSA-SHA256
        try:
            from cryptography.hazmat.primitives import hashes, serialization
            from cryptography.hazmat.primitives.asymmetric import padding

            private_key = serialization.load_pem_private_key(
                self._service_account["private_key"].encode(),
                password=None,
            )
            signature = private_key.sign(
                signing_input,
                padding.PKCS1v15(),
                hashes.SHA256(),
            )
            signature_b64 = urlsafe_b64encode(signature).rstrip(b"=")
        except ImportError as e:
            raise ImportError(
                "cryptography package required for service account auth. "
                "Install with: pip install cryptography"
            ) from e

        jwt = signing_input + b"." + signature_b64

        # Exchange JWT for access token
        token_url = "https://oauth2.googleapis.com/token"
        data = urllib.parse.urlencode({
            "grant_type": "urn:ietf:params:oauth:grant-type:jwt-bearer",
            "assertion": jwt.decode(),
        }).encode()

        request = urllib.request.Request(token_url, data=data)
        request.add_header("Content-Type", "application/x-www-form-urlencoded")

        with urllib.request.urlopen(request, timeout=30) as response:
            token_data = json.loads(response.read())
            if "access_token" not in token_data:
                raise ValueError(
                    f"Token response missing 'access_token': {list(token_data.keys())}"
                )
            self._access_token = token_data["access_token"]
            self._token_expiry = time.time() + token_data.get("expires_in", 3600) - 60

        return self._access_token

    def export_batch(self, batch: ExportBatch) -> ExportResult:
        """
        Export a batch to GCS.

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
                f"Exported {batch.event_count} events to gs://{self.config.bucket_name}/{key}"
            )

            return ExportResult(
                success=True,
                events_exported=batch.event_count,
                batch_id=batch.batch_id,
                destination=f"gs://{self.config.bucket_name}/{key}",
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
        Upload an object to GCS.

        Args:
            key: Object key.
            data: Object data.
        """
        if HAS_GCS:
            self._upload_gcs(key, data)
        else:
            self._upload_urllib(key, data)

    def _upload_gcs(self, key: str, data: bytes) -> None:
        """Upload using google-cloud-storage."""
        blob = self._bucket.blob(key)
        blob.upload_from_string(
            data,
            content_type=self.get_content_type(),
        )

    def _upload_urllib(self, key: str, data: bytes) -> None:
        """Upload using urllib with OAuth2."""
        access_token = self._get_access_token()

        # Build upload URL
        url = (
            f"https://storage.googleapis.com/upload/storage/v1/b/"
            f"{urllib.parse.quote(self.config.bucket_name)}/o"
            f"?uploadType=media&name={urllib.parse.quote(key)}"
        )

        headers = {
            "Authorization": f"Bearer {access_token}",
            "Content-Type": self.get_content_type(),
            "Content-Length": str(len(data)),
        }

        request = urllib.request.Request(url, data=data, headers=headers, method="POST")

        try:
            with urllib.request.urlopen(
                request, timeout=self.config.read_timeout
            ) as response:
                if response.status not in (200, 201):
                    raise ValueError(f"GCS upload failed with status {response.status}")
        except urllib.error.HTTPError as e:
            raise ValueError(f"GCS upload failed: {e.code} {e.reason}") from e

    def health_check(self) -> bool:
        """
        Check if we can connect to GCS.

        Returns:
            True if healthy.
        """
        try:
            if HAS_GCS:
                if self._bucket is None:
                    logger.error("GCS bucket not initialized")
                    return False
                self._bucket.reload()
            else:
                # Try to get bucket metadata
                access_token = self._get_access_token()
                url = (
                    f"https://storage.googleapis.com/storage/v1/b/"
                    f"{urllib.parse.quote(self.config.bucket_name)}"
                )
                headers = {"Authorization": f"Bearer {access_token}"}
                request = urllib.request.Request(url, headers=headers)

                with urllib.request.urlopen(request, timeout=10) as response:
                    return response.status == 200

            return True
        except Exception as e:
            logger.warning(f"GCS health check failed: {e}")
            return False

    def list_exports(
        self,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        max_results: int = 1000,
    ) -> list[str]:
        """
        List exported files in the bucket.

        Args:
            start_date: Filter to exports after this date.
            end_date: Filter to exports before this date.
            max_results: Maximum number of results to return.

        Returns:
            List of object names.
        """
        if not HAS_GCS:
            raise NotImplementedError("list_exports requires google-cloud-storage")

        prefix = self.config.prefix
        if start_date:
            prefix += f"{start_date.year:04d}/"

        blobs = self._bucket.list_blobs(prefix=prefix, max_results=max_results)

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


class BigQueryExporter(BaseCloudExporter):
    """
    Export audit logs directly to BigQuery.

    Provides streaming insert for real-time analytics.
    Requires google-cloud-bigquery package.

    Example:
        >>> config = CloudExporterConfig(
        ...     provider="gcp",
        ...     bucket_name="my-project.my_dataset.audit_logs",
        ... )
        >>> exporter = BigQueryExporter(config)
        >>> result = exporter.export(events)
    """

    def __init__(
        self,
        config: CloudExporterConfig,
        project_id: str | None = None,
        dataset_id: str | None = None,
        table_id: str | None = None,
        create_table: bool = True,
    ) -> None:
        """
        Initialize the BigQuery exporter.

        Args:
            config: Exporter configuration.
            project_id: GCP project ID.
            dataset_id: BigQuery dataset ID.
            table_id: BigQuery table ID.
            create_table: Create table if it doesn't exist.
        """
        super().__init__(config)

        if not HAS_BIGQUERY:
            raise ImportError(
                "google-cloud-bigquery required for BigQueryExporter. "
                "Install with: pip install google-cloud-bigquery"
            )

        # Parse table reference from bucket_name if in format project.dataset.table
        if "." in config.bucket_name:
            parts = config.bucket_name.split(".")
            self.project_id = parts[0] if len(parts) > 0 else project_id
            self.dataset_id = parts[1] if len(parts) > 1 else dataset_id
            self.table_id = parts[2] if len(parts) > 2 else table_id
        else:
            self.project_id = project_id
            self.dataset_id = dataset_id
            self.table_id = table_id or config.bucket_name

        self.create_table = create_table
        self._client = None
        self._table = None
        self._initialize_client()

    def _initialize_client(self) -> None:
        """Initialize BigQuery client."""
        if self.config.credentials_path:
            from google.oauth2 import service_account
            credentials = service_account.Credentials.from_service_account_file(
                self.config.credentials_path,
            )
            self._client = bigquery.Client(
                credentials=credentials,
                project=self.project_id,
            )
        else:
            self._client = bigquery.Client(project=self.project_id)

        # Get or create table
        table_ref = f"{self.project_id}.{self.dataset_id}.{self.table_id}"

        try:
            self._table = self._client.get_table(table_ref)
        except Exception:
            if self.create_table:
                self._create_table(table_ref)
            else:
                raise

    def _create_table(self, table_ref: str) -> None:
        """Create the BigQuery table."""
        schema = [
            bigquery.SchemaField("event_id", "STRING", mode="REQUIRED"),
            bigquery.SchemaField("timestamp", "TIMESTAMP", mode="REQUIRED"),
            bigquery.SchemaField("sequence_number", "INTEGER"),
            bigquery.SchemaField("event_type", "STRING"),
            bigquery.SchemaField("user_id", "STRING"),
            bigquery.SchemaField("user_roles", "STRING", mode="REPEATED"),
            bigquery.SchemaField("session_id", "STRING"),
            bigquery.SchemaField("agent_id", "STRING"),
            bigquery.SchemaField("tool_name", "STRING"),
            bigquery.SchemaField("tool_arguments", "JSON"),
            bigquery.SchemaField("authorization_allowed", "BOOLEAN"),
            bigquery.SchemaField("authorization_reason", "STRING"),
            bigquery.SchemaField("policies_evaluated", "STRING", mode="REPEATED"),
            bigquery.SchemaField("event_hash", "STRING"),
            bigquery.SchemaField("previous_hash", "STRING"),
        ]

        table = bigquery.Table(table_ref, schema=schema)

        # Enable partitioning by timestamp
        table.time_partitioning = bigquery.TimePartitioning(
            type_=bigquery.TimePartitioningType.DAY,
            field="timestamp",
        )

        self._table = self._client.create_table(table)
        logger.info(f"Created BigQuery table: {table_ref}")

    def _event_to_row(self, event: AuditEventV2) -> dict[str, Any]:
        """Convert an audit event to a BigQuery row."""
        data = event.data
        return {
            "event_id": event.event_id,
            "timestamp": event.timestamp.isoformat(),
            "sequence_number": event.sequence_number,
            "event_type": data.event_type.value,
            "user_id": data.user_id,
            "user_roles": data.user_roles or [],
            "session_id": data.session_id,
            "agent_id": data.agent_id,
            "tool_name": data.tool_name,
            "tool_arguments": json.dumps(data.tool_arguments) if data.tool_arguments else None,
            "authorization_allowed": data.authorization_allowed,
            "authorization_reason": data.authorization_reason,
            "policies_evaluated": data.policies_evaluated or [],
            "event_hash": event.event_hash,
            "previous_hash": event.previous_hash,
        }

    def export_batch(self, batch: ExportBatch) -> ExportResult:
        """
        Export a batch to BigQuery.

        Args:
            batch: The batch to export.

        Returns:
            ExportResult with success/failure information.
        """
        start_time = time.time()

        try:
            # Convert events to rows
            rows = [self._event_to_row(event) for event in batch.events]

            # Insert rows
            errors = self._client.insert_rows_json(self._table, rows)

            duration_ms = (time.time() - start_time) * 1000

            if errors:
                error_msg = f"BigQuery insert errors: {errors}"
                logger.error(error_msg)
                return ExportResult(
                    success=False,
                    events_exported=0,
                    batch_id=batch.batch_id,
                    error=error_msg,
                    duration_ms=duration_ms,
                )

            table_ref = f"{self.project_id}.{self.dataset_id}.{self.table_id}"
            logger.info(f"Exported {batch.event_count} events to {table_ref}")

            return ExportResult(
                success=True,
                events_exported=batch.event_count,
                batch_id=batch.batch_id,
                destination=table_ref,
                duration_ms=duration_ms,
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

    def health_check(self) -> bool:
        """
        Check if we can connect to BigQuery.

        Returns:
            True if healthy.
        """
        try:
            self._client.get_table(self._table)
            return True
        except Exception as e:
            logger.warning(f"BigQuery health check failed: {e}")
            return False
