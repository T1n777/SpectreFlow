"""
SpectreFlow Dynamic Analysis — File System Monitor
Uses *watchdog* to observe file creation / modification / deletion
in directories of interest during the analysis window.
"""

import os
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent

import config

logger = logging.getLogger("spectreflow.dynamic.file")

# Pre-compute for fast lookup in event callbacks
_SUSPICIOUS_EXTENSIONS = config.SUSPICIOUS_EXTENSIONS


class _EventHandler(FileSystemEventHandler):
    """Collect file-system events into a shared list."""

    def __init__(self, events: list[dict]):
        super().__init__()
        self._events = events
        self._seen: set[tuple] = set()
        self.has_suspicious_ext = False  # Track at record time, not at results time

    # helpers ──────────────────────────────────────────────────────────
    def _record(self, action: str, path: str):
        basename = os.path.basename(path)
        key = (action, basename)
        if key not in self._seen:
            self._seen.add(key)
            self._events.append({"action": action, "file": basename})
            logger.info("File event: %s %s", action, basename)

            # Check extension once at recording time instead of re-scanning later
            if not self.has_suspicious_ext:
                _, ext = os.path.splitext(basename)
                if ext.lower() in _SUSPICIOUS_EXTENSIONS:
                    self.has_suspicious_ext = True

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
        # Suspicious-extension check was done incrementally in _record(),
        # so no need to re-scan the entire events list here.
        return {
            "file_activity": self.events,
            "flagged_functions": ["file_write"] if self.events else [],
        }
