"""
Request scheduling and queuing for Proxilion.

This module provides priority-based request queuing to ensure
high-priority requests are processed first while preventing
starvation of lower-priority requests through aging.

Example:
    >>> from proxilion.scheduling import (
    ...     PriorityLevel, QueuedRequest, PriorityQueue,
    ...     RequestScheduler, SchedulerConfig,
    ... )
    >>>
    >>> # Create a priority queue
    >>> queue = PriorityQueue(max_size=1000)
    >>>
    >>> # Enqueue requests with different priorities
    >>> queue.enqueue(QueuedRequest(
    ...     id="req-1",
    ...     priority=PriorityLevel.HIGH,
    ...     payload={"task": "urgent"},
    ... ))
    >>> queue.enqueue(QueuedRequest(
    ...     id="req-2",
    ...     priority=PriorityLevel.LOW,
    ...     payload={"task": "background"},
    ... ))
    >>>
    >>> # High priority dequeued first
    >>> request = queue.dequeue()
    >>> assert request.priority == PriorityLevel.HIGH
    >>>
    >>> # Use scheduler for concurrent processing
    >>> config = SchedulerConfig(max_concurrent=4)
    >>> scheduler = RequestScheduler(config)
    >>> future = scheduler.submit(request)
"""

from proxilion.scheduling.priority_queue import (
    PriorityLevel,
    PriorityQueue,
    QueuedRequest,
)
from proxilion.scheduling.scheduler import (
    RequestScheduler,
    SchedulerConfig,
)

__all__ = [
    # Priority queue
    "PriorityLevel",
    "QueuedRequest",
    "PriorityQueue",
    # Scheduler
    "RequestScheduler",
    "SchedulerConfig",
]
