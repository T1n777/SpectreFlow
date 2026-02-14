import os
import logging

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileSystemEvent
import config

logger = logging.getLogger("spectreflow.dynamic.file")

_SUSPICIOUS_EXTENSIONS = config.SUSPICIOUS_EXTENSIONS


class _EventHandler(FileSystemEventHandler):
    def __init__(self, events: list[dict]):
        super().__init__()
        self._events = events
        self._seen: set[tuple] = set()
        self.has_suspicious_ext = False

    def _record(self, action: str, path: str):
        basename = os.path.basename(path)
        key = (action, basename)
        if key not in self._seen:
            self._seen.add(key)
            self._events.append({"action": action, "file": basename})
            logger.info("File event: %s %s", action, basename)
            if not self.has_suspicious_ext:
                _, ext = os.path.splitext(basename)
                if ext.lower() in _SUSPICIOUS_EXTENSIONS:
                    self.has_suspicious_ext = True

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
    def __init__(self):
        self.events: list[dict] = []
        self._observer = Observer()
        self._handler = _EventHandler(self.events)

    def start(self):
        for directory in config.WATCHED_DIRS:
            if os.path.isdir(directory):
                self._observer.schedule(self._handler, directory, recursive=False)
                logger.info("Watching directory: %s", directory)
        self._observer.start()

    def stop(self):
        self._observer.stop()
        self._observer.join(timeout=5)

    def get_results(self) -> dict:
        flagged = ["file_write"] if self._handler.has_suspicious_ext else []
        return {
            "file_activity": self.events,
            "flagged_functions": flagged,
        }
