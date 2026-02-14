"""
SpectreFlow Dynamic Analysis — File System Monitor
Uses *watchdog* to observe file creation / modification / deletion
in directories of interest during the analysis window.
"""

import os
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

from . import config

logger = logging.getLogger("spectreflow.dynamic.file")


class _EventHandler(FileSystemEventHandler):
    """Collect file-system events into a shared list."""

    def __init__(self, events: list[dict]):
        super().__init__()
        self._events = events
        self._seen: set[tuple] = set()

    # helpers ──────────────────────────────────────────────────────────
    def _record(self, action: str, path: str):
        basename = os.path.basename(path)
        key = (action, basename)
        if key not in self._seen:
            self._seen.add(key)
            entry = {"action": action, "file": basename}
            self._events.append(entry)
            logger.info("File event: %s %s", action, basename)

    # watchdog callbacks ──────────────────────────────────────────────
    def on_created(self, event: FileSystemEvent):
        if not event.is_directory:
            self._record("created", event.src_path)

    def on_modified(self, event: FileSystemEvent):
        if not event.is_directory:
            self._record("modified", event.src_path)

    def on_deleted(self, event: FileSystemEvent):
        if not event.is_directory:
            self._record("deleted", event.src_path)

    def on_moved(self, event):
        self._record("moved", getattr(event, "dest_path", event.src_path))


class FileMonitor:
    """Watch configured directories for file activity."""

    def __init__(self):
        self.events: list[dict] = []
        self._observer = Observer()
        self._handler = _EventHandler(self.events)

    # ── public API ───────────────────────────────────────────────────
    def start(self):
        for directory in config.WATCHED_DIRS:
            if os.path.isdir(directory):
                self._observer.schedule(
                    self._handler, directory, recursive=False
                )
                logger.info("Watching directory: %s", directory)
        self._observer.start()

    def stop(self):
        self._observer.stop()
        self._observer.join(timeout=5)

    # ── results ──────────────────────────────────────────────────────
    def get_results(self) -> dict:
        flagged = []

        # Check for suspicious file extensions
        for event in self.events:
            filename = event["file"]
            _, ext = os.path.splitext(filename)
            if ext.lower() in config.SUSPICIOUS_EXTENSIONS:
                if "file_write" not in flagged:
                    flagged.append("file_write")
                break

        # Any file activity at all is still worth recording,
        # but only flag if extensions are suspicious.
        if self.events and not flagged:
            flagged.append("file_write")

        return {
            "file_activity": self.events,
            "flagged_functions": flagged,
        }
