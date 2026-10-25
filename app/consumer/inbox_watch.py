"""Wake the consumer as soon as a zip arrives in the inbox (watchdog), instead of waiting
for the next timed scan. The timed scan stays as a fallback.

Local disks: native notifications (inotify / ReadDirectoryChangesW). Network shares
(SMB / NFS) usually do not report writes made by another machine, so use polling there:
`watch_polling: true` in consumer.yaml.
"""

import asyncio
import re
from pathlib import Path

from watchdog.events import FileSystemEvent, FileSystemEventHandler
from watchdog.observers import Observer
from watchdog.observers.polling import PollingObserver

from ..logs import logger

ZIP_NAME = re.compile(r"^openiam-.+-\d{8}T\d{12}Z\.zip(\.age)?$")


class _Handler(FileSystemEventHandler):
    def __init__(self, loop: asyncio.AbstractEventLoop, arrived: asyncio.Event):
        self.loop, self.arrived = loop, arrived

    def _maybe(self, path: str) -> None:
        name = Path(path).name
        if ZIP_NAME.match(name):   # final names only; ".x.partial" never matches
            logger.debug("zip arrived: {}", name)
            self.loop.call_soon_threadsafe(self.arrived.set)

    def on_created(self, event: FileSystemEvent) -> None:
        if not event.is_directory:
            self._maybe(event.src_path)

    def on_moved(self, event: FileSystemEvent) -> None:   # the producer's atomic rename
        if not event.is_directory:
            self._maybe(event.dest_path)

    def on_closed(self, event: FileSystemEvent) -> None:  # copy finished (Linux)
        if not event.is_directory:
            self._maybe(event.src_path)


class InboxWatcher:
    def __init__(self, inbox: str, arrived: asyncio.Event, polling: bool, poll_seconds: float = 5.0):
        self.inbox, self.arrived = inbox, arrived
        self.observer = PollingObserver(timeout=poll_seconds) if polling else Observer()
        self.polling = polling

    def start(self) -> None:
        Path(self.inbox).mkdir(parents=True, exist_ok=True)
        self.observer.schedule(_Handler(asyncio.get_running_loop(), self.arrived), self.inbox,
                               recursive=True)
        self.observer.daemon = True
        self.observer.start()
        logger.info("watching {} for zips ({})", self.inbox, "polling" if self.polling else "events")

    def stop(self) -> None:
        self.observer.stop()
        self.observer.join(timeout=5)
