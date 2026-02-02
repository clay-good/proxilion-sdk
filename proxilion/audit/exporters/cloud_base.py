"""
Base classes and protocols for cloud storage exporters.

Provides common interfaces and configuration for exporting audit logs
to cloud storage providers (AWS S3, GCP Cloud Storage, Azure Blob).
"""

from __future__ import annotations

import gzip
import hashlib
import logging
import threading
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Literal, Protocol, runtime_checkable

from proxilion.audit.events import AuditEventV2

logger = logging.getLogger(__name__)


class CompressionType(Enum):
    """Compression types for exported files."""
    NONE = "none"
    GZIP = "gzip"
    ZSTD = "zstd"


class ExportFormat(Enum):
    """Export file formats."""
    JSONL = "jsonl"
    PARQUET = "parquet"


@dataclass
class CloudExporterConfig:
    """
    Configuration for cloud storage exporters.

    Attributes:
        provider: Cloud provider ("aws", "gcp", "azure").
        bucket_name: Name of the bucket/container.
        prefix: Path prefix within the bucket (e.g., "audit-logs/proxilion/").
        region: Cloud region (e.g., "us-west-2", "us-central1").
        credentials_path: Path to service account/credentials file.
        use_instance_credentials: Whether to use instance/managed identity.
        batch_size: Number of events per export batch.
        compression: Compression type for exported files.
        format: Export file format.
        endpoint_url: Custom endpoint URL (for S3-compatible storage).
        connection_timeout: Connection timeout in seconds.
        read_timeout: Read timeout in seconds.
        max_retries: Maximum number of retries for failed operations.
        retry_delay: Initial delay between retries in seconds.
    """
    provider: Literal["aws", "gcp", "azure"]
    bucket_name: str
    prefix: str = ""
    region: str | None = None
    credentials_path: str | None = None
    use_instance_credentials: bool = True
    batch_size: int = 100
    compression: CompressionType = CompressionType.GZIP
    format: ExportFormat = ExportFormat.JSONL
    endpoint_url: str | None = None
    connection_timeout: float = 30.0
    read_timeout: float = 60.0
    max_retries: int = 3
    retry_delay: float = 1.0

    def __post_init__(self) -> None:
        """Validate and normalize configuration."""
        # Ensure prefix ends with / if not empty
        if self.prefix and not self.prefix.endswith("/"):
            self.prefix = self.prefix + "/"

        # Convert string enums if needed
        if isinstance(self.compression, str):
            self.compression = CompressionType(self.compression)
        if isinstance(self.format, str):
            self.format = ExportFormat(self.format)


@dataclass
class ExportResult:
    """
    Result of an export operation.

    Attributes:
        success: Whether the export succeeded.
        events_exported: Number of events successfully exported.
        batch_id: Unique identifier for this export batch.
        destination: Full path/key where data was exported.
        error: Error message if export failed.
        duration_ms: Export duration in milliseconds.
        bytes_written: Number of bytes written.
        checksum: MD5/SHA256 checksum of exported data.
    """
    success: bool
    events_exported: int = 0
    batch_id: str = ""
    destination: str = ""
    error: str | None = None
    duration_ms: float = 0.0
    bytes_written: int = 0
    checksum: str | None = None


@dataclass
class ExportBatch:
    """
    A batch of events to export.

    Attributes:
        batch_id: Unique identifier for this batch.
        events: List of audit events.
        created_at: When the batch was created.
        metadata: Additional metadata for the batch.
    """
    batch_id: str
    events: list[AuditEventV2]
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def event_count(self) -> int:
        """Get the number of events in the batch."""
        return len(self.events)

    def to_jsonl(self) -> str:
        """Convert batch to JSON Lines format."""
        lines = []
        for event in self.events:
            lines.append(event.to_json(pretty=False))
        return "\n".join(lines)

    def to_bytes(self, compression: CompressionType = CompressionType.NONE) -> bytes:
        """
        Convert batch to bytes with optional compression.

        Args:
            compression: Compression type to apply.

        Returns:
            Bytes representation of the batch.
        """
        content = self.to_jsonl().encode("utf-8")

        if compression == CompressionType.GZIP:
            return gzip.compress(content)
        elif compression == CompressionType.ZSTD:
            try:
                import zstandard as zstd
                cctx = zstd.ZstdCompressor()
                return cctx.compress(content)
            except ImportError:
                logger.warning("zstandard not installed, falling back to gzip")
                return gzip.compress(content)

        return content


@runtime_checkable
class CloudExporter(Protocol):
    """
    Protocol for cloud storage exporters.

    All cloud exporters must implement these methods.
    """

    def export(self, events: list[AuditEventV2]) -> ExportResult:
        """
        Export a list of events to cloud storage.

        Args:
            events: List of audit events to export.

        Returns:
            ExportResult with success/failure information.
        """
        ...

    def export_batch(self, batch: ExportBatch) -> ExportResult:
        """
        Export a pre-formed batch to cloud storage.

        Args:
            batch: The batch to export.

        Returns:
            ExportResult with success/failure information.
        """
        ...

    def configure(self, config: dict[str, Any]) -> None:
        """
        Update exporter configuration.

        Args:
            config: Configuration dictionary.
        """
        ...

    def health_check(self) -> bool:
        """
        Check if the exporter can connect to cloud storage.

        Returns:
            True if healthy and connected.
        """
        ...


class BaseCloudExporter(ABC):
    """
    Abstract base class for cloud storage exporters.

    Provides common functionality for all cloud exporters including:
    - Key generation with time-based partitioning
    - Compression handling
    - Retry logic
    - Thread-safe batch accumulation
    """

    def __init__(self, config: CloudExporterConfig) -> None:
        """
        Initialize the base exporter.

        Args:
            config: Exporter configuration.
        """
        self.config = config
        self._lock = threading.RLock()
        self._pending_events: list[AuditEventV2] = []
        self._batch_counter = 0

    def generate_key(
        self,
        timestamp: datetime | None = None,
        batch_id: str | None = None,
    ) -> str:
        """
        Generate an object key with time-based partitioning.

        Format: {prefix}/{year}/{month}/{day}/{hour}/{batch_id}.{ext}

        Args:
            timestamp: Timestamp for partitioning (default: now).
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
        if self.config.compression == CompressionType.GZIP:
            ext += ".gz"
        elif self.config.compression == CompressionType.ZSTD:
            ext += ".zst"

        # Build partitioned path
        key = (
            f"{self.config.prefix}"
            f"{timestamp.year:04d}/"
            f"{timestamp.month:02d}/"
            f"{timestamp.day:02d}/"
            f"{timestamp.hour:02d}/"
            f"{batch_id}.{ext}"
        )

        return key

    def prepare_batch(self, events: list[AuditEventV2]) -> ExportBatch:
        """
        Prepare events as an export batch.

        Args:
            events: Events to include in the batch.

        Returns:
            Prepared ExportBatch.
        """
        import uuid

        batch_id = str(uuid.uuid4())
        return ExportBatch(
            batch_id=batch_id,
            events=events,
            metadata={
                "exporter": self.__class__.__name__,
                "provider": self.config.provider,
                "bucket": self.config.bucket_name,
            },
        )

    def compute_checksum(self, data: bytes) -> str:
        """
        Compute MD5 checksum of data.

        Args:
            data: Bytes to checksum.

        Returns:
            Hex-encoded MD5 checksum.
        """
        return hashlib.md5(data).hexdigest()

    def with_retry(
        self,
        operation: callable,
        *args: Any,
        **kwargs: Any,
    ) -> Any:
        """
        Execute an operation with retry logic.

        Args:
            operation: Function to execute.
            *args: Positional arguments for operation.
            **kwargs: Keyword arguments for operation.

        Returns:
            Result of the operation.

        Raises:
            Last exception if all retries fail.
        """
        last_error: Exception | None = None
        delay = self.config.retry_delay

        for attempt in range(self.config.max_retries + 1):
            try:
                return operation(*args, **kwargs)
            except Exception as e:
                last_error = e
                if attempt < self.config.max_retries:
                    logger.warning(
                        f"Export attempt {attempt + 1} failed: {e}. "
                        f"Retrying in {delay:.1f}s..."
                    )
                    time.sleep(delay)
                    delay *= 2  # Exponential backoff

        raise last_error  # type: ignore

    def export(self, events: list[AuditEventV2]) -> ExportResult:
        """
        Export a list of events to cloud storage.

        Args:
            events: List of audit events to export.

        Returns:
            ExportResult with success/failure information.
        """
        if not events:
            return ExportResult(
                success=True,
                events_exported=0,
                batch_id="",
                destination="",
            )

        batch = self.prepare_batch(events)
        return self.export_batch(batch)

    @abstractmethod
    def export_batch(self, batch: ExportBatch) -> ExportResult:
        """
        Export a batch to cloud storage.

        Must be implemented by subclasses.

        Args:
            batch: The batch to export.

        Returns:
            ExportResult with success/failure information.
        """
        pass

    def configure(self, config: dict[str, Any]) -> None:
        """
        Update exporter configuration.

        Args:
            config: Configuration dictionary.
        """
        for key, value in config.items():
            if hasattr(self.config, key):
                setattr(self.config, key, value)

    @abstractmethod
    def health_check(self) -> bool:
        """
        Check if the exporter can connect to cloud storage.

        Must be implemented by subclasses.

        Returns:
            True if healthy and connected.
        """
        pass

    def add_pending(self, event: AuditEventV2) -> ExportResult | None:
        """
        Add an event to the pending buffer.

        If the buffer reaches batch_size, exports automatically.

        Args:
            event: Event to add.

        Returns:
            ExportResult if batch was exported, None otherwise.
        """
        with self._lock:
            self._pending_events.append(event)

            if len(self._pending_events) >= self.config.batch_size:
                events = self._pending_events
                self._pending_events = []
                return self.export(events)

        return None

    def flush_pending(self) -> ExportResult | None:
        """
        Export any pending events.

        Returns:
            ExportResult if events were exported, None if buffer was empty.
        """
        with self._lock:
            if not self._pending_events:
                return None

            events = self._pending_events
            self._pending_events = []
            return self.export(events)

    def get_content_type(self) -> str:
        """Get the content type for exported files."""
        if self.config.format == ExportFormat.JSONL:
            return "application/x-ndjson"
        elif self.config.format == ExportFormat.PARQUET:
            return "application/vnd.apache.parquet"
        return "application/octet-stream"

    def get_content_encoding(self) -> str | None:
        """Get the content encoding for compressed files."""
        if self.config.compression == CompressionType.GZIP:
            return "gzip"
        elif self.config.compression == CompressionType.ZSTD:
            return "zstd"
        return None
