"""
Cloud storage exporters for Proxilion audit logs.

This module provides exporters for sending audit logs to cloud storage:

- AWS S3 / S3-compatible storage
- GCP Cloud Storage / BigQuery
- Azure Blob Storage / ADLS Gen2
- Multi-cloud redundant export

Example:
    >>> from proxilion.audit.exporters import S3Exporter, CloudExporterConfig
    >>>
    >>> config = CloudExporterConfig(
    ...     provider="aws",
    ...     bucket_name="my-audit-logs",
    ...     prefix="proxilion/prod/",
    ...     region="us-west-2",
    ... )
    >>> exporter = S3Exporter(config)
"""

from __future__ import annotations

from proxilion.audit.exporters.aws_s3 import S3DataLakeExporter, S3Exporter
from proxilion.audit.exporters.azure_storage import AzureBlobExporter, AzureDataLakeExporter
from proxilion.audit.exporters.cloud_base import (
    CloudExporter,
    CloudExporterConfig,
    CompressionType,
    ExportBatch,
    ExportFormat,
    ExportResult,
)
from proxilion.audit.exporters.gcp_storage import BigQueryExporter, GCSExporter
from proxilion.audit.exporters.multi_exporter import FailureStrategy, MultiCloudExporter

__all__ = [
    # Base
    "CloudExporter",
    "CloudExporterConfig",
    "ExportResult",
    "ExportBatch",
    "CompressionType",
    "ExportFormat",
    # AWS
    "S3Exporter",
    "S3DataLakeExporter",
    # GCP
    "GCSExporter",
    "BigQueryExporter",
    # Azure
    "AzureBlobExporter",
    "AzureDataLakeExporter",
    # Multi-cloud
    "MultiCloudExporter",
    "FailureStrategy",
]
