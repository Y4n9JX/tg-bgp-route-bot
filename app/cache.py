import time
from typing import Any, Dict, Tuple

class TTLCache:
    def __init__(self, ttl_seconds: int = 3600):
        self.ttl = ttl_seconds
        self._data: Dict[str, Tuple[float, Any]] = {}

    def get(self, key: str):
        v = self._data.get(key)
        if not v:
            return None
        ts, val = v
        if time.time() - ts > self.ttl:
            self._data.pop(key, None)
            return None
        return val

    def set(self, key: str, value: Any):
        self._data[key] = (time.time(), value)
