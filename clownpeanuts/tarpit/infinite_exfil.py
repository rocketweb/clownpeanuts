"""Synthetic infinite exfiltration stream generator."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterator


@dataclass(slots=True)
class InfiniteExfilConfig:
    chunk_size_bytes: int = 768
    max_chunks: int = 0


class InfiniteExfilStream:
    def __init__(self, config: InfiniteExfilConfig | None = None) -> None:
        self.config = config or InfiniteExfilConfig()

    def iter_chunks(self) -> Iterator[bytes]:
        index = 0
        while self.config.max_chunks <= 0 or index < self.config.max_chunks:
            yield self._build_chunk(index)
            index += 1

    def _build_chunk(self, index: int) -> bytes:
        prefix = (
            f"-- stream chunk {index + 1}\n"
            f"INSERT INTO transactions VALUES({index + 1},'acct-{index:06d}','wire',"
            f"{1000 + index}.42,'approved');\n"
        ).encode("utf-8")
        size = max(64, int(self.config.chunk_size_bytes))
        if len(prefix) >= size:
            return prefix[:size]
        return prefix + (b"x" * (size - len(prefix)))
