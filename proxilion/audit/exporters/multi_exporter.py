"""
Multi-cloud exporter for redundant audit log export.

Provides resilient export to multiple cloud destinations with
configurable failure handling and retry strategies.
"""

from __future__ import annotations

import logging
import threading
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any

from proxilion.audit.events import AuditEventV2
from proxilion.audit.exporters.cloud_base import (
    BaseCloudExporter,
    CloudExporter,
    CloudExporterConfig,
    ExportBatch,
    ExportResult,
)

logger = logging.getLogger(__name__)


class FailureStrategy(Enum):
    """Strategy for handling export failures."""

    FAIL_FAST = "fail_fast"
    """Stop on first failure."""

    BEST_EFFORT = "best_effort"
    """Continue even if some exporters fail."""

    REQUIRE_ONE = "require_one"
    """Succeed if at least one exporter succeeds."""

    REQUIRE_ALL = "require_all"
    """Only succeed if all exporters succeed."""

    REQUIRE_MAJORITY = "require_majority"
    """Succeed if majority of exporters succeed."""


@dataclass
class MultiExportResult:
    """
    Aggregated result of multi-cloud export.

    Attributes:
        success: Whether the overall export succeeded.
        results: Individual results from each exporter.
        total_events: Total events in the batch.
        successful_destinations: Number of successful destinations.
        failed_destinations: Number of failed destinations.
        duration_ms: Total export duration in milliseconds.
    """
    success: bool
    results: list[ExportResult] = field(default_factory=list)
    total_events: int = 0
    successful_destinations: int = 0
    failed_destinations: int = 0
    duration_ms: float = 0.0

    @property
    def all_succeeded(self) -> bool:
        """Check if all exporters succeeded."""
        return all(r.success for r in self.results)

    @property
    def any_succeeded(self) -> bool:
        """Check if any exporter succeeded."""
        return any(r.success for r in self.results)

    @property
    def majority_succeeded(self) -> bool:
        """Check if majority of exporters succeeded."""
        if not self.results:
            return False
        return self.successful_destinations > len(self.results) / 2

    def get_failed_results(self) -> list[ExportResult]:
        """Get list of failed export results."""
        return [r for r in self.results if not r.success]

    def get_successful_results(self) -> list[ExportResult]:
        """Get list of successful export results."""
        return [r for r in self.results if r.success]


class MultiCloudExporter:
    """
    Export audit logs to multiple cloud destinations.

    Provides redundant export with configurable failure handling,
    parallel execution, and comprehensive result tracking.

    Example:
        >>> from proxilion.audit.exporters import (
        ...     S3Exporter, GCSExporter, MultiCloudExporter, FailureStrategy
        ... )
        >>>
        >>> s3 = S3Exporter(s3_config)
        >>> gcs = GCSExporter(gcs_config)
        >>>
        >>> multi = MultiCloudExporter(
        ...     exporters=[s3, gcs],
        ...     strategy=FailureStrategy.REQUIRE_ONE,
        ...     parallel=True,
        ... )
        >>>
        >>> result = multi.export(events)
        >>> if result.success:
        ...     print(f"Exported to {result.successful_destinations} destinations")
    """

    def __init__(
        self,
        exporters: list[CloudExporter | BaseCloudExporter],
        strategy: FailureStrategy = FailureStrategy.BEST_EFFORT,
        parallel: bool = True,
        timeout: float = 300.0,
        retry_failed: bool = True,
        max_retries: int = 2,
        retry_delay: float = 5.0,
    ) -> None:
        """
        Initialize the multi-cloud exporter.

        Args:
            exporters: List of cloud exporters to use.
            strategy: Strategy for handling failures.
            parallel: Execute exports in parallel.
            timeout: Timeout for parallel exports in seconds.
            retry_failed: Retry failed exports.
            max_retries: Maximum number of retries per exporter.
            retry_delay: Delay between retries in seconds.
        """
        self.exporters = exporters
        self.strategy = strategy
        self.parallel = parallel
        self.timeout = timeout
        self.retry_failed = retry_failed
        self.max_retries = max_retries
        self.retry_delay = retry_delay

        self._pending_events: list[AuditEventV2] = []
        self._lock = threading.RLock()
        self._batch_counter = 0

    @property
    def exporter_count(self) -> int:
        """Get the number of configured exporters."""
        return len(self.exporters)

    def export(self, events: list[AuditEventV2]) -> MultiExportResult:
        """
        Export events to all configured destinations.

        Args:
            events: List of audit events to export.

        Returns:
            MultiExportResult with aggregated results.
        """
        if not events:
            return MultiExportResult(success=True, total_events=0)

        # Prepare batch
        batch = self._prepare_batch(events)

        return self.export_batch(batch)

    def export_batch(self, batch: ExportBatch) -> MultiExportResult:
        """
        Export a batch to all destinations.

        Args:
            batch: The batch to export.

        Returns:
            MultiExportResult with aggregated results.
        """
        start_time = time.time()

        if self.parallel and len(self.exporters) > 1:
            results = self._export_parallel(batch)
        else:
            results = self._export_sequential(batch)

        # Retry failed exports if configured
        if self.retry_failed:
            results = self._retry_failed_exports(batch, results)

        # Aggregate results
        duration_ms = (time.time() - start_time) * 1000
        successful = [r for r in results if r.success]
        failed = [r for r in results if not r.success]

        # Determine overall success based on strategy
        success = self._evaluate_success(len(successful), len(failed))

        return MultiExportResult(
            success=success,
            results=results,
            total_events=batch.event_count,
            successful_destinations=len(successful),
            failed_destinations=len(failed),
            duration_ms=duration_ms,
        )

    def _prepare_batch(self, events: list[AuditEventV2]) -> ExportBatch:
        """Prepare events as an export batch."""

        with self._lock:
            self._batch_counter += 1
            ts = datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')
            batch_id = f"multi_{ts}_{self._batch_counter:06d}"

        return ExportBatch(
            batch_id=batch_id,
            events=events,
            metadata={
                "exporter": "MultiCloudExporter",
                "destinations": self.exporter_count,
                "strategy": self.strategy.value,
            },
        )

    def _export_sequential(self, batch: ExportBatch) -> list[ExportResult]:
        """Export to destinations sequentially."""
        results = []

        for i, exporter in enumerate(self.exporters):
            try:
                result = exporter.export_batch(batch)
                results.append(result)

                # Check for fail-fast
                if self.strategy == FailureStrategy.FAIL_FAST and not result.success:
                    logger.warning(
                        f"Export to destination {i} failed with fail-fast strategy. "
                        f"Skipping remaining {len(self.exporters) - i - 1} destinations."
                    )
                    break

            except Exception as e:
                logger.error(f"Export to destination {i} failed with exception: {e}")
                results.append(ExportResult(
                    success=False,
                    batch_id=batch.batch_id,
                    error=str(e),
                ))

                if self.strategy == FailureStrategy.FAIL_FAST:
                    break

        return results

    def _export_parallel(self, batch: ExportBatch) -> list[ExportResult]:
        """Export to destinations in parallel."""
        import concurrent.futures

        results: list[ExportResult | None] = [None] * len(self.exporters)

        def export_to_destination(index: int, exporter: CloudExporter) -> tuple[int, ExportResult]:
            try:
                result = exporter.export_batch(batch)
                return index, result
            except Exception as e:
                logger.error(f"Export to destination {index} failed: {e}")
                return index, ExportResult(
                    success=False,
                    batch_id=batch.batch_id,
                    error=str(e),
                )

        with concurrent.futures.ThreadPoolExecutor(max_workers=len(self.exporters)) as executor:
            futures = {
                executor.submit(export_to_destination, i, exp): i
                for i, exp in enumerate(self.exporters)
            }

            try:
                for future in concurrent.futures.as_completed(futures, timeout=self.timeout):
                    index, result = future.result()
                    results[index] = result

                    # Check for fail-fast (exit early)
                    if self.strategy == FailureStrategy.FAIL_FAST and not result.success:
                        logger.warning(
                            "Export failed with fail-fast strategy. Cancelling remaining exports."
                        )
                        # Cancel remaining futures
                        for f in futures:
                            f.cancel()
                        break

            except concurrent.futures.TimeoutError:
                logger.error(f"Parallel export timed out after {self.timeout}s")
                # Mark timed out exports as failed
                for i, r in enumerate(results):
                    if r is None:
                        results[i] = ExportResult(
                            success=False,
                            batch_id=batch.batch_id,
                            error="Export timed out",
                        )

        # Replace any remaining None values
        return [
            r if r is not None else ExportResult(
                success=False,
                batch_id=batch.batch_id,
                error="Export did not complete",
            )
            for r in results
        ]

    def _retry_failed_exports(
        self,
        batch: ExportBatch,
        results: list[ExportResult],
    ) -> list[ExportResult]:
        """Retry failed exports."""
        final_results = list(results)

        for retry in range(self.max_retries):
            # Find failed exports
            failed_indices = [
                i for i, r in enumerate(final_results)
                if not r.success
            ]

            if not failed_indices:
                break

            logger.info(
                f"Retrying {len(failed_indices)} failed exports "
                f"(attempt {retry + 1}/{self.max_retries})"
            )

            time.sleep(self.retry_delay * (retry + 1))  # Increasing delay

            for i in failed_indices:
                try:
                    result = self.exporters[i].export_batch(batch)
                    if result.success:
                        final_results[i] = result
                        logger.info(f"Retry succeeded for destination {i}")
                except Exception as e:
                    logger.warning(f"Retry failed for destination {i}: {e}")

        return final_results

    def _evaluate_success(self, successful: int, failed: int) -> bool:
        """Evaluate overall success based on strategy."""
        total = successful + failed

        if self.strategy == FailureStrategy.FAIL_FAST:
            return successful == total and failed == 0

        elif self.strategy == FailureStrategy.BEST_EFFORT:
            return True  # Always succeed, just log failures

        elif self.strategy == FailureStrategy.REQUIRE_ONE:
            return successful >= 1

        elif self.strategy == FailureStrategy.REQUIRE_ALL:
            return failed == 0

        elif self.strategy == FailureStrategy.REQUIRE_MAJORITY:
            return successful > total / 2

        return False

    def health_check(self) -> dict[int, bool]:
        """
        Check health of all exporters.

        Returns:
            Dict mapping exporter index to health status.
        """
        results = {}

        for i, exporter in enumerate(self.exporters):
            try:
                results[i] = exporter.health_check()
            except Exception as e:
                logger.warning(f"Health check failed for exporter {i}: {e}")
                results[i] = False

        return results

    def configure(self, config: dict[str, Any]) -> None:
        """
        Update exporter configuration.

        Args:
            config: Configuration dictionary with optional keys:
                - strategy: FailureStrategy value or string
                - parallel: bool
                - timeout: float
                - retry_failed: bool
                - max_retries: int
                - retry_delay: float
        """
        if "strategy" in config:
            strategy = config["strategy"]
            if isinstance(strategy, str):
                self.strategy = FailureStrategy(strategy)
            else:
                self.strategy = strategy

        if "parallel" in config:
            self.parallel = config["parallel"]

        if "timeout" in config:
            self.timeout = config["timeout"]

        if "retry_failed" in config:
            self.retry_failed = config["retry_failed"]

        if "max_retries" in config:
            self.max_retries = config["max_retries"]

        if "retry_delay" in config:
            self.retry_delay = config["retry_delay"]

    def add_exporter(self, exporter: CloudExporter | BaseCloudExporter) -> None:
        """
        Add an exporter to the list.

        Args:
            exporter: Exporter to add.
        """
        self.exporters.append(exporter)

    def remove_exporter(self, index: int) -> CloudExporter | BaseCloudExporter | None:
        """
        Remove an exporter by index.

        Args:
            index: Index of exporter to remove.

        Returns:
            The removed exporter, or None if index invalid.
        """
        if 0 <= index < len(self.exporters):
            return self.exporters.pop(index)
        return None

    def add_pending(self, event: AuditEventV2) -> MultiExportResult | None:
        """
        Add an event to the pending buffer.

        Exports when buffer reaches the smallest batch_size of any exporter.

        Args:
            event: Event to add.

        Returns:
            MultiExportResult if batch was exported, None otherwise.
        """
        with self._lock:
            self._pending_events.append(event)

            # Get minimum batch size from all exporters
            min_batch_size = min(
                getattr(exp, "config", CloudExporterConfig("aws", "")).batch_size
                for exp in self.exporters
            ) if self.exporters else 100

            if len(self._pending_events) >= min_batch_size:
                events = self._pending_events
                self._pending_events = []
                return self.export(events)

        return None

    def flush_pending(self) -> MultiExportResult | None:
        """
        Export any pending events.

        Returns:
            MultiExportResult if events were exported, None if buffer was empty.
        """
        with self._lock:
            if not self._pending_events:
                return None

            events = self._pending_events
            self._pending_events = []
            return self.export(events)
