from __future__ import annotations

import logging
import time
from contextlib import contextmanager
from typing import Iterator


@contextmanager
def timed_step(label: str) -> Iterator[None]:
    logger = logging.getLogger("ad_analyzer.timer")
    start = time.perf_counter()
    try:
        yield
    finally:
        elapsed = time.perf_counter() - start
        logger.info("%s finished in %.2fs", label, elapsed)

