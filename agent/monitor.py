import os
import threading
from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler


class LogHandler(FileSystemEventHandler):
    def __init__(self, log_files):
        super().__init__()
        self.log_files = log_files
        self.positions = {log: 0 for log in log_files}
        self.failed_logins = 0
        self.successful_logins = 0
        self.lock = threading.Lock()

    def on_modified(self, event):
        path = os.path.abspath(event.src_path)
        if path in self.log_files:
            try:
                with open(path, "r", encoding="utf-8", errors="ignore") as f:
                    f.seek(self.positions[path])
                    lines = f.readlines()
                    self.positions[path] = f.tell()
                for line in lines:
                    if "Failed password" in line:
                        with self.lock:
                            self.failed_logins += 1
                    if "Accepted password" in line:
                        with self.lock:
                            self.successful_logins += 1
            except OSError:
                return


def start_log_monitor(log_paths):
    abs_paths = list(map(os.path.abspath, log_paths))
    event_handler = LogHandler(abs_paths)
    observer = Observer()

    # Watch directories containing each log file
    watched_dirs = set(os.path.dirname(p) for p in abs_paths)
    for wdir in watched_dirs:
        if wdir and os.path.isdir(wdir):
            observer.schedule(event_handler, path=wdir, recursive=False)

    observer_thread = threading.Thread(target=observer.start)
    observer_thread.daemon = True
    observer_thread.start()

    # Attach stop and join to thread object for graceful shutdown
    def stop():
        observer.stop()

    def join():
        observer.join()

    observer_thread.stop = stop
    observer_thread.join = join

    return observer_thread


def _parse_log_file(path):
    failed = 0
    successful = 0

    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                if "Failed password" in line:
                    failed += 1
                if "Accepted password" in line:
                    successful += 1
    except OSError:
        # Missing or unreadable log file should not crash collection.
        pass

    return {"failed_logins": failed, "successful_logins": successful}


def get_log_events(log_paths):
    abs_paths = [os.path.abspath(p) for p in log_paths]
    per_log = {path: _parse_log_file(path) for path in abs_paths}

    total_failed = sum(item["failed_logins"] for item in per_log.values())
    total_successful = sum(item["successful_logins"] for item in per_log.values())

    return {
        "log_events": per_log,
        "failed_logins": total_failed,
        "successful_logins": total_successful,
    }
