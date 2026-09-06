"""Optional multiprocessing pool for testing candidate batches against the matcher.

Gated behind --jobs N (N > 1). Relies on the default 'fork' start method
(this project only targets the headless Linux VM it runs on) so worker
processes inherit the matcher -- including a bcrypt module reference for
--algo bcrypt -- via copy-on-write at Pool creation time, instead of needing
it to be picklable. Only plain candidate-string batches (and matched
candidates coming back) cross the pool's task queue.

One ParallelExecutor / pool is created for the whole run and reused across
modules, so per-module overhead is just a handful of batch submissions to an
already-running pool -- cheap enough that small modules don't need special
casing.
"""

from __future__ import annotations

import multiprocessing as mp
import time

from core import term

_matcher = None
_found = None


def _init_worker(matcher, found_event) -> None:
    global _matcher, _found
    _matcher = matcher
    _found = found_event


def _test_batch(batch: list[str]) -> tuple[int, str] | None:
    """Return (index_in_batch, candidate) for the first match, else None."""
    if _found.is_set():
        return None
    for i, cand in enumerate(batch):
        if _matcher.matches(cand):
            _found.set()
            return i, cand
        if _found.is_set():  # another worker found it while we were mid-batch
            return None
    return None


class ParallelExecutor:
    def __init__(self, jobs: int, matcher, batch_size: int = 2_000):
        self.batch_size = batch_size
        self.found = mp.Event()
        self.pool = mp.Pool(jobs, initializer=_init_worker, initargs=(matcher, self.found))

    def run_module(self, gen, budget: int, remaining_global: int,
                    progress_every: int | None = None, mod_name: str = "",
                    t0: float | None = None) -> tuple[str | None, int]:
        """Drain gen (a module's candidate generator) through the pool in batches.

        Stops at whichever of budget / remaining_global / a match comes
        first. Returns (found_candidate_or_None, tried_count).
        """
        self.found.clear()
        lengths: list[int] = []

        def batches():
            batch: list[str] = []
            n = 0
            for cand in gen:
                if self.found.is_set():
                    return
                batch.append(cand)
                n += 1
                if len(batch) >= self.batch_size:
                    lengths.append(len(batch))
                    yield batch
                    batch = []
                if n >= budget or n >= remaining_global:
                    break
            if batch:
                lengths.append(len(batch))
                yield batch

        tried = 0
        last_print = 0
        found = None
        idx = 0
        for result in self.pool.imap(_test_batch, batches()):
            if result is not None:
                offset, cand = result
                found = cand
                tried += offset + 1
                break
            tried += lengths[idx]
            idx += 1
            if progress_every and t0 is not None and tried - last_print >= progress_every:
                last_print = tried
                rate = tried / (time.time() - t0 + 1e-9)
                print(term.dim(f"    [{mod_name}] {tried:,} tried ({rate:,.0f}/s)"))
        return found, tried
