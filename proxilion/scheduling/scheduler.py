"""
Request scheduler with worker pool.

Provides concurrent execution of queued requests with
priority-based scheduling.
"""

from __future__ import annotations

import asyncio
import logging
import threading
from collections.abc import Awaitable, Callable
from concurrent.futures import Future, ThreadPoolExecutor
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum, auto
from typing import Any

from proxilion.scheduling.priority_queue import (
    PriorityLevel,
    PriorityQueue,
    QueuedRequest,
)

logger = logging.getLogger(__name__)


class SchedulerState(Enum):
    """Scheduler operational states."""

    RUNNING = auto()
    PAUSED = auto()
    SHUTTING_DOWN = auto()
    STOPPED = auto()


@dataclass
class SchedulerConfig:
    """
    Configuration for the request scheduler.

    Attributes:
        max_concurrent: Maximum concurrent request processing.
        queue_size: Maximum queue size.
        default_timeout: Default request timeout in seconds.
        aging_interval: Queue aging interval in seconds.
        aging_boost: Priority levels to boost on aging.
        worker_idle_timeout: Seconds before idle workers check again.

    Example:
        >>> config = SchedulerConfig(
        ...     max_concurrent=8,
        ...     queue_size=500,
        ...     default_timeout=60.0,
        ... )
    """

    max_concurrent: int = 4
    queue_size: int = 1000
    default_timeout: float | None = 60.0
    aging_interval: float = 60.0
    aging_boost: int = 1
    worker_idle_timeout: float = 1.0


@dataclass
class SchedulerStats:
    """Statistics for the scheduler."""

    requests_submitted: int = 0
    requests_completed: int = 0
    requests_failed: int = 0
    requests_timed_out: int = 0
    total_processing_time: float = 0.0
    active_workers: int = 0
    queue_size: int = 0


class RequestScheduler:
    """
    Request scheduler with worker pool and priority queue.

    Manages concurrent execution of requests, respecting priority
    levels and preventing starvation through aging.

    Example:
        >>> config = SchedulerConfig(max_concurrent=4)
        >>> scheduler = RequestScheduler(config)
        >>>
        >>> # Define a handler
        >>> def handle_request(payload):
        ...     return f"Processed: {payload}"
        >>>
        >>> scheduler.set_handler(handle_request)
        >>>
        >>> # Submit requests
        >>> request = QueuedRequest(
        ...     priority=PriorityLevel.HIGH,
        ...     payload={"task": "important"},
        ... )
        >>> future = scheduler.submit(request)
        >>> result = future.result()
        >>>
        >>> # Cleanup
        >>> scheduler.shutdown()
    """

    def __init__(
        self,
        config: SchedulerConfig | None = None,
        handler: Callable[[Any], Any] | None = None,
        async_handler: Callable[[Any], Awaitable[Any]] | None = None,
    ) -> None:
        """
        Initialize the scheduler.

        Args:
            config: Scheduler configuration.
            handler: Synchronous request handler.
            async_handler: Asynchronous request handler.
        """
        self.config = config or SchedulerConfig()
        self._handler = handler
        self._async_handler = async_handler

        self._queue = PriorityQueue(
            max_size=self.config.queue_size,
            aging_interval=self.config.aging_interval,
            aging_boost=self.config.aging_boost,
        )

        self._executor = ThreadPoolExecutor(
            max_workers=self.config.max_concurrent,
            thread_name_prefix="scheduler-worker",
        )

        self._state = SchedulerState.RUNNING
        self._state_lock = threading.Lock()
        self._stats = SchedulerStats()
        self._stats_lock = threading.Lock()

        # Track pending futures
        self._pending_futures: dict[str, Future] = {}
        self._futures_lock = threading.Lock()

        # Start worker threads
        self._workers: list[threading.Thread] = []
        self._start_workers()

    def _start_workers(self) -> None:
        """Start worker threads."""
        for i in range(self.config.max_concurrent):
            worker = threading.Thread(
                target=self._worker_loop,
                name=f"scheduler-worker-{i}",
                daemon=True,
            )
            worker.start()
            self._workers.append(worker)

    def _worker_loop(self) -> None:
        """Worker loop that processes requests from the queue."""
        while True:
            with self._state_lock:
                if self._state == SchedulerState.STOPPED:
                    return
                if self._state == SchedulerState.SHUTTING_DOWN and self._queue.is_empty():
                    return

            # Wait for state to allow processing
            with self._state_lock:
                while self._state == SchedulerState.PAUSED:
                    # Check periodically while paused
                    pass

            if self._state != SchedulerState.RUNNING:
                if self._state == SchedulerState.STOPPED:
                    return
                continue

            # Try to get a request
            request = self._queue.dequeue(
                block=True,
                timeout=self.config.worker_idle_timeout,
            )

            if request is None:
                continue

            # Process the request
            self._process_request(request)

    def _process_request(self, request: QueuedRequest) -> None:
        """Process a single request."""
        start_time = datetime.now(timezone.utc)
        result = None
        error = None

        with self._stats_lock:
            self._stats.active_workers += 1

        try:
            if self._handler:
                result = self._handler(request.payload)
            elif self._async_handler:
                # Run async handler in event loop
                loop = asyncio.new_event_loop()
                try:
                    result = loop.run_until_complete(
                        self._async_handler(request.payload)
                    )
                finally:
                    loop.close()
            else:
                # No handler, just return the payload
                result = request.payload

            # Call request callback if provided
            if request.callback:
                try:
                    request.callback(result)
                except Exception as e:
                    logger.error(f"Request callback error: {e}")

            with self._stats_lock:
                self._stats.requests_completed += 1

        except Exception as e:
            error = e
            logger.error(f"Request {request.id} failed: {e}")
            with self._stats_lock:
                self._stats.requests_failed += 1

        finally:
            # Update stats
            processing_time = (
                datetime.now(timezone.utc) - start_time
            ).total_seconds()

            with self._stats_lock:
                self._stats.active_workers -= 1
                self._stats.total_processing_time += processing_time

            # Complete the future
            with self._futures_lock:
                future = self._pending_futures.pop(request.id, None)
                if future:
                    if error:
                        future.set_exception(error)
                    else:
                        future.set_result(result)

    def set_handler(self, handler: Callable[[Any], Any]) -> None:
        """
        Set the synchronous request handler.

        Args:
            handler: Function to process request payloads.
        """
        self._handler = handler

    def set_async_handler(self, handler: Callable[[Any], Awaitable[Any]]) -> None:
        """
        Set the asynchronous request handler.

        Args:
            handler: Async function to process request payloads.
        """
        self._async_handler = handler

    def submit(
        self,
        request: QueuedRequest | None = None,
        *,
        priority: PriorityLevel = PriorityLevel.NORMAL,
        payload: Any = None,
        timeout: float | None = None,
        callback: Callable[[Any], None] | None = None,
    ) -> Future:
        """
        Submit a request for processing.

        Args:
            request: Pre-built request object.
            priority: Request priority (if building new request).
            payload: Request payload (if building new request).
            timeout: Request timeout (if building new request).
            callback: Completion callback (if building new request).

        Returns:
            Future that will contain the result.

        Raises:
            RuntimeError: If scheduler is not running.
        """
        with self._state_lock:
            if self._state != SchedulerState.RUNNING:
                raise RuntimeError(f"Scheduler is {self._state.name}")

        # Build request if not provided
        if request is None:
            request = QueuedRequest(
                priority=priority,
                payload=payload,
                timeout=timeout or self.config.default_timeout,
                callback=callback,
            )
        elif timeout is None and self.config.default_timeout:
            request.timeout = self.config.default_timeout

        # Create future for result
        future: Future = Future()

        with self._futures_lock:
            self._pending_futures[request.id] = future

        # Enqueue the request
        if not self._queue.enqueue(request, block=False):
            with self._futures_lock:
                self._pending_futures.pop(request.id, None)
            future.set_exception(RuntimeError("Queue is full"))
            return future

        with self._stats_lock:
            self._stats.requests_submitted += 1
            self._stats.queue_size = self._queue.size()

        return future

    async def submit_async(
        self,
        request: QueuedRequest | None = None,
        *,
        priority: PriorityLevel = PriorityLevel.NORMAL,
        payload: Any = None,
        timeout: float | None = None,
    ) -> Any:
        """
        Submit a request and await the result.

        Args:
            request: Pre-built request object.
            priority: Request priority (if building new request).
            payload: Request payload (if building new request).
            timeout: Request timeout (if building new request).

        Returns:
            The processing result.
        """
        future = self.submit(
            request,
            priority=priority,
            payload=payload,
            timeout=timeout,
        )

        # Wait for future in async context
        loop = asyncio.get_event_loop()
        return await loop.run_in_executor(None, future.result)

    def pause(self) -> None:
        """Pause request processing."""
        with self._state_lock:
            if self._state == SchedulerState.RUNNING:
                self._state = SchedulerState.PAUSED
                logger.info("Scheduler paused")

    def resume(self) -> None:
        """Resume request processing."""
        with self._state_lock:
            if self._state == SchedulerState.PAUSED:
                self._state = SchedulerState.RUNNING
                logger.info("Scheduler resumed")

    def shutdown(self, wait: bool = True, timeout: float | None = None) -> None:
        """
        Shutdown the scheduler.

        Args:
            wait: Whether to wait for pending requests.
            timeout: Maximum time to wait for pending requests.
        """
        with self._state_lock:
            if self._state in (SchedulerState.SHUTTING_DOWN, SchedulerState.STOPPED):
                return
            self._state = SchedulerState.SHUTTING_DOWN

        logger.info("Scheduler shutting down...")

        if wait:
            # Wait for workers to complete
            for worker in self._workers:
                worker.join(timeout=timeout)

        # Force stop
        with self._state_lock:
            self._state = SchedulerState.STOPPED

        # Cancel pending futures
        with self._futures_lock:
            for future in self._pending_futures.values():
                if not future.done():
                    future.cancel()
            self._pending_futures.clear()

        self._executor.shutdown(wait=False)
        logger.info("Scheduler stopped")

    def get_queue_stats(self) -> dict[str, Any]:
        """
        Get queue statistics.

        Returns:
            Dictionary with queue and scheduler statistics.
        """
        queue_stats = self._queue.get_stats()

        with self._stats_lock:
            scheduler_stats = {
                "requests_submitted": self._stats.requests_submitted,
                "requests_completed": self._stats.requests_completed,
                "requests_failed": self._stats.requests_failed,
                "active_workers": self._stats.active_workers,
                "total_processing_time": self._stats.total_processing_time,
            }

        return {
            "state": self._state.name,
            "queue": queue_stats,
            "scheduler": scheduler_stats,
            "config": {
                "max_concurrent": self.config.max_concurrent,
                "queue_size": self.config.queue_size,
                "default_timeout": self.config.default_timeout,
            },
        }

    def get_pending_count(self) -> int:
        """Get number of pending requests."""
        return self._queue.size()

    def is_running(self) -> bool:
        """Check if scheduler is running."""
        with self._state_lock:
            return self._state == SchedulerState.RUNNING

    def is_paused(self) -> bool:
        """Check if scheduler is paused."""
        with self._state_lock:
            return self._state == SchedulerState.PAUSED

    def __enter__(self) -> RequestScheduler:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.shutdown(wait=True)
