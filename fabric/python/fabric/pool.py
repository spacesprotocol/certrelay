import random
import threading


class RelayPool:
    def __init__(self):
        self._lock = threading.Lock()
        self._entries: list[dict] = []  # [{"url": str, "failures": int}]

    def is_empty(self) -> bool:
        with self._lock:
            return len(self._entries) == 0

    def urls(self) -> list[str]:
        with self._lock:
            return [e["url"] for e in self._entries]

    def shuffled_urls(self, n: int) -> list[str]:
        with self._lock:
            random.shuffle(self._entries)
            self._entries.sort(key=lambda e: e["failures"])
            limit = n if n > 0 else len(self._entries)
            if limit > len(self._entries):
                limit = len(self._entries)
            return [self._entries[i]["url"] for i in range(limit)]

    def mark_failed(self, url: str):
        with self._lock:
            for e in self._entries:
                if e["url"] == url:
                    e["failures"] += 1
                    return

    def mark_alive(self, url: str):
        with self._lock:
            for e in self._entries:
                if e["url"] == url:
                    e["failures"] = 0
                    return

    def refresh(self, urls: list[str]):
        with self._lock:
            existing = {e["url"] for e in self._entries}
            for url in urls:
                if url not in existing:
                    self._entries.append({"url": url, "failures": 0})
