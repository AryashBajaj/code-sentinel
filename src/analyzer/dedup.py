class DedupMixin:
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self._dedup_seen = set()

    def _dedup_key(self, pattern_id: str, lineno: int) -> tuple:
        return (pattern_id, str(self.file_path), lineno)

    def _dedup_should_emit(self, pattern_id: str, lineno: int) -> bool:
        key = self._dedup_key(pattern_id, lineno)
        if key in self._dedup_seen:
            return False
        self._dedup_seen.add(key)
        return True
