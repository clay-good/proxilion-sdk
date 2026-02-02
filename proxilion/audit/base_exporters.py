"""
Audit log exporters for Proxilion.

This module provides different export formats for audit logs:

- FileExporter: Write to JSON Lines files
- ConsoleExporter: Pretty-print for development
- StreamExporter: Generic stream output
"""

from __future__ import annotations

import json
import sys
import threading
from abc import ABC, abstractmethod
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any, TextIO

from proxilion.audit.events import AuditEventV2
from proxilion.audit.hash_chain import HashChain, MerkleBatch


class Exporter(ABC):
    """Abstract base class for audit log exporters."""

    @abstractmethod
    def export_event(self, event: AuditEventV2) -> None:
        """Export a single event."""
        pass

    @abstractmethod
    def export_batch(self, batch: MerkleBatch) -> None:
        """Export a batch marker."""
        pass

    def export_chain(self, chain: HashChain) -> None:
        """Export an entire hash chain."""
        for event in chain:
            self.export_event(event)

    @abstractmethod
    def flush(self) -> None:
        """Flush any buffered output."""
        pass

    @abstractmethod
    def close(self) -> None:
        """Close the exporter."""
        pass

    def __enter__(self) -> Exporter:
        """Context manager entry."""
        return self

    def __exit__(self, exc_type: Any, exc_val: Any, exc_tb: Any) -> None:
        """Context manager exit."""
        self.close()


class FileExporter(Exporter):
    """
    Export audit events to JSON Lines files.

    Writes one JSON object per line, making it easy to parse
    with tools like jq or stream-process large files.

    Example:
        >>> with FileExporter("audit.jsonl") as exporter:
        ...     for event in chain:
        ...         exporter.export_event(event)
    """

    def __init__(
        self,
        path: str | Path,
        append: bool = True,
        sync_writes: bool = False,
        pretty: bool = False,
    ) -> None:
        """
        Initialize the file exporter.

        Args:
            path: Path to the output file.
            append: If True, append to existing file.
            sync_writes: If True, flush after each write.
            pretty: If True, use indented JSON (multi-line).
        """
        self.path = Path(path)
        self.append = append
        self.sync_writes = sync_writes
        self.pretty = pretty
        self._file: TextIO | None = None
        self._lock = threading.RLock()

        # Ensure parent directory exists
        self.path.parent.mkdir(parents=True, exist_ok=True)

        # Open file
        mode = "a" if append else "w"
        self._file = open(self.path, mode, encoding="utf-8")

    def export_event(self, event: AuditEventV2) -> None:
        """Export a single event to the file."""
        with self._lock:
            if self._file is None:
                raise RuntimeError("Exporter is closed")

            if self.pretty:
                line = json.dumps(event.to_dict(), indent=2, sort_keys=True, default=str)
                self._file.write(line + "\n")
            else:
                line = event.to_json(pretty=False)
                self._file.write(line + "\n")

            if self.sync_writes:
                self._file.flush()

    def export_batch(self, batch: MerkleBatch) -> None:
        """Export a batch marker."""
        with self._lock:
            if self._file is None:
                raise RuntimeError("Exporter is closed")

            marker = {
                "_type": "batch_marker",
                "batch": batch.to_dict(),
            }

            if self.pretty:
                line = json.dumps(marker, indent=2, sort_keys=True)
            else:
                line = json.dumps(marker, sort_keys=True)

            self._file.write(line + "\n")

            if self.sync_writes:
                self._file.flush()

    def flush(self) -> None:
        """Flush buffered writes to disk."""
        with self._lock:
            if self._file:
                self._file.flush()

    def close(self) -> None:
        """Close the file."""
        with self._lock:
            if self._file:
                self._file.close()
                self._file = None


class ConsoleExporter(Exporter):
    """
    Pretty-print audit events to the console.

    Useful for development and debugging. Formats events
    with colors (if supported) and readable structure.

    Example:
        >>> exporter = ConsoleExporter()
        >>> exporter.export_event(event)
        # Prints formatted event to stdout
    """

    # ANSI color codes
    COLORS = {
        "reset": "\033[0m",
        "bold": "\033[1m",
        "dim": "\033[2m",
        "red": "\033[31m",
        "green": "\033[32m",
        "yellow": "\033[33m",
        "blue": "\033[34m",
        "magenta": "\033[35m",
        "cyan": "\033[36m",
    }

    def __init__(
        self,
        output: TextIO | None = None,
        use_colors: bool = True,
        verbose: bool = False,
    ) -> None:
        """
        Initialize the console exporter.

        Args:
            output: Output stream (default: stdout).
            use_colors: Whether to use ANSI colors.
            verbose: If True, show all fields including hashes.
        """
        self.output = output or sys.stdout
        self.use_colors = use_colors and self._supports_colors()
        self.verbose = verbose
        self._lock = threading.RLock()

    def _supports_colors(self) -> bool:
        """Check if the output supports ANSI colors."""
        if not hasattr(self.output, "isatty"):
            return False
        return self.output.isatty()

    def _color(self, text: str, color: str) -> str:
        """Apply color to text if colors are enabled."""
        if not self.use_colors:
            return text
        return f"{self.COLORS.get(color, '')}{text}{self.COLORS['reset']}"

    def export_event(self, event: AuditEventV2) -> None:
        """Pretty-print an event to the console."""
        with self._lock:
            lines = []

            # Header with timestamp and event type
            event_type = event.data.event_type.value
            if "granted" in event_type:
                type_color = "green"
                status_symbol = "✓"
            elif "denied" in event_type or "violation" in event_type:
                type_color = "red"
                status_symbol = "✗"
            else:
                type_color = "cyan"
                status_symbol = "•"

            header = f"{status_symbol} {event_type.upper()}"
            lines.append(self._color(header, type_color))

            # Timestamp
            timestamp = event.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC")
            lines.append(f"  {self._color('Time:', 'dim')} {timestamp}")

            # User info
            user_info = f"{event.data.user_id}"
            if event.data.user_roles:
                roles = ", ".join(event.data.user_roles)
                user_info += f" [{roles}]"
            lines.append(f"  {self._color('User:', 'dim')} {user_info}")

            # Tool call
            tool_info = f"{event.data.tool_name}"
            lines.append(f"  {self._color('Tool:', 'dim')} {tool_info}")

            # Arguments (truncated for readability)
            if event.data.tool_arguments:
                args_str = json.dumps(event.data.tool_arguments, default=str)
                if len(args_str) > 80:
                    args_str = args_str[:77] + "..."
                lines.append(f"  {self._color('Args:', 'dim')} {args_str}")

            # Authorization result
            if event.data.authorization_allowed:
                result = self._color("ALLOWED", "green")
            else:
                result = self._color("DENIED", "red")
            lines.append(f"  {self._color('Result:', 'dim')} {result}")

            # Reason
            if event.data.authorization_reason:
                lines.append(f"  {self._color('Reason:', 'dim')} {event.data.authorization_reason}")

            # Verbose output
            if self.verbose:
                lines.append(f"  {self._color('Event ID:', 'dim')} {event.event_id}")
                lines.append(f"  {self._color('Sequence:', 'dim')} {event.sequence_number}")
                if event.event_hash:
                    hash_short = event.event_hash[:30] + "..."
                    lines.append(f"  {self._color('Hash:', 'dim')} {hash_short}")

            # Empty line for separation
            lines.append("")

            self.output.write("\n".join(lines) + "\n")

    def export_batch(self, batch: MerkleBatch) -> None:
        """Pretty-print a batch marker."""
        with self._lock:
            lines = []

            header = self._color("═══ BATCH FINALIZED ═══", "magenta")
            lines.append(header)
            lines.append(f"  {self._color('Batch ID:', 'dim')} {batch.batch_id}")
            seq_range = f"{batch.start_sequence}-{batch.end_sequence}"
            lines.append(f"  {self._color('Events:', 'dim')} {batch.event_count} (seq {seq_range})")

            if self.verbose:
                root_short = batch.merkle_root[:30] + "..."
                lines.append(f"  {self._color('Merkle Root:', 'dim')} {root_short}")

            lines.append("")

            self.output.write("\n".join(lines) + "\n")

    def flush(self) -> None:
        """Flush the output stream."""
        with self._lock:
            self.output.flush()

    def close(self) -> None:
        """No-op for console exporter."""
        pass


class StreamExporter(Exporter):
    """
    Generic stream exporter for custom output destinations.

    Allows writing audit events to any TextIO stream
    in JSON Lines format.

    Example:
        >>> import io
        >>> buffer = io.StringIO()
        >>> with StreamExporter(buffer) as exporter:
        ...     exporter.export_event(event)
        >>> print(buffer.getvalue())
    """

    def __init__(
        self,
        stream: TextIO,
        close_on_exit: bool = False,
    ) -> None:
        """
        Initialize the stream exporter.

        Args:
            stream: The output stream.
            close_on_exit: If True, close stream on exit.
        """
        self.stream = stream
        self.close_on_exit = close_on_exit
        self._lock = threading.RLock()

    def export_event(self, event: AuditEventV2) -> None:
        """Export an event to the stream."""
        with self._lock:
            line = event.to_json(pretty=False)
            self.stream.write(line + "\n")

    def export_batch(self, batch: MerkleBatch) -> None:
        """Export a batch marker to the stream."""
        with self._lock:
            marker = {"_type": "batch_marker", "batch": batch.to_dict()}
            line = json.dumps(marker, sort_keys=True)
            self.stream.write(line + "\n")

    def flush(self) -> None:
        """Flush the stream."""
        with self._lock:
            self.stream.flush()

    def close(self) -> None:
        """Close the stream if configured."""
        with self._lock:
            if self.close_on_exit:
                self.stream.close()


class CallbackExporter(Exporter):
    """
    Exporter that calls a callback function for each event.

    Useful for integrating with external systems, metrics,
    or custom processing pipelines.

    Example:
        >>> def handle_event(event):
        ...     send_to_siem(event.to_dict())
        >>>
        >>> exporter = CallbackExporter(handle_event)
        >>> exporter.export_event(event)
    """

    def __init__(
        self,
        event_callback: Callable[[AuditEventV2], None],
        batch_callback: Callable[[MerkleBatch], None] | None = None,
    ) -> None:
        """
        Initialize the callback exporter.

        Args:
            event_callback: Function to call for each event.
            batch_callback: Optional function for batch markers.
        """
        self.event_callback = event_callback
        self.batch_callback = batch_callback

    def export_event(self, event: AuditEventV2) -> None:
        """Call the event callback."""
        self.event_callback(event)

    def export_batch(self, batch: MerkleBatch) -> None:
        """Call the batch callback if provided."""
        if self.batch_callback:
            self.batch_callback(batch)

    def flush(self) -> None:
        """No-op for callback exporter."""
        pass

    def close(self) -> None:
        """No-op for callback exporter."""
        pass


class MultiExporter(Exporter):
    """
    Exporter that writes to multiple destinations.

    Useful for simultaneously logging to file and console,
    or sending to multiple external systems.

    Example:
        >>> file_exp = FileExporter("audit.jsonl")
        >>> console_exp = ConsoleExporter()
        >>> multi = MultiExporter([file_exp, console_exp])
        >>> multi.export_event(event)  # Writes to both
    """

    def __init__(self, exporters: list[Exporter]) -> None:
        """
        Initialize with multiple exporters.

        Args:
            exporters: List of exporters to write to.
        """
        self.exporters = exporters

    def export_event(self, event: AuditEventV2) -> None:
        """Export to all exporters."""
        for exporter in self.exporters:
            exporter.export_event(event)

    def export_batch(self, batch: MerkleBatch) -> None:
        """Export batch to all exporters."""
        for exporter in self.exporters:
            exporter.export_batch(batch)

    def flush(self) -> None:
        """Flush all exporters."""
        for exporter in self.exporters:
            exporter.flush()

    def close(self) -> None:
        """Close all exporters."""
        for exporter in self.exporters:
            exporter.close()


def read_jsonl_events(path: str | Path) -> Iterator[AuditEventV2]:
    """
    Read audit events from a JSON Lines file.

    Args:
        path: Path to the JSON Lines file.

    Yields:
        AuditEventV2 instances.

    Example:
        >>> for event in read_jsonl_events("audit.jsonl"):
        ...     print(event.event_id)
    """
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue

            data = json.loads(line)

            # Skip batch markers
            if data.get("_type") == "batch_marker":
                continue

            yield AuditEventV2.from_dict(data)


def verify_jsonl_chain(path: str | Path) -> tuple[bool, str | None]:
    """
    Verify the hash chain in a JSON Lines audit log.

    Args:
        path: Path to the JSON Lines file.

    Returns:
        Tuple of (is_valid, error_message).

    Example:
        >>> valid, error = verify_jsonl_chain("audit.jsonl")
        >>> if not valid:
        ...     print(f"Chain verification failed: {error}")
    """
    from proxilion.audit.hash_chain import GENESIS_HASH

    expected_previous = GENESIS_HASH
    line_number = 0

    try:
        for event in read_jsonl_events(path):
            line_number += 1

            # Check chain linkage
            if event.previous_hash != expected_previous:
                return False, (
                    f"Chain broken at line {line_number}: "
                    f"expected {expected_previous}, got {event.previous_hash}"
                )

            # Verify event hash
            if not event.verify_hash():
                return False, f"Invalid hash at line {line_number}: event tampered"

            expected_previous = event.event_hash

    except json.JSONDecodeError as e:
        return False, f"JSON parse error at line {line_number}: {e}"
    except Exception as e:
        return False, f"Verification error: {e}"

    return True, None
