"""Ordered pipeline: run each module cheapest-first, within budgets."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core import term


@dataclass
class ModuleStat:
    name: str
    tried: int
    elapsed: float
    budget_hit: bool


@dataclass
class Result:
    found: str | None
    module: str | None
    rank: int | None
    total_tried: int
    elapsed: float
    stats: list = field(default_factory=list)


class Runner:
    def __init__(self, modules, ctx, progress_every: int = 1_000_000, jobs: int = 1):
        self.modules = modules
        self.ctx = ctx
        self.matcher = ctx.matcher
        self.progress_every = progress_every
        self.jobs = jobs
        self.executor = None
        if jobs > 1:
            from core.parallel import ParallelExecutor
            self.executor = ParallelExecutor(jobs, ctx.matcher)

    def _budget_for(self, mod) -> int:
        return getattr(mod, "budget", None) or self.ctx.limits.module_budget

    def _run_sequential(self, mod, budget: int, remaining_global: int, m0: float):
        tried = 0
        for cand in mod.generate(self.ctx):
            tried += 1
            if self.matcher.matches(cand):
                return cand, tried
            if tried >= budget or tried >= remaining_global:
                break
            if tried % self.progress_every == 0:
                rate = tried / (time.time() - m0 + 1e-9)
                print(term.dim(f"    [{mod.name}] {tried:,} tried ({rate:,.0f}/s)"))
        return None, tried

    def _run_parallel(self, mod, budget: int, remaining_global: int, m0: float):
        return self.executor.run_module(
            mod.generate(self.ctx), budget, remaining_global,
            progress_every=self.progress_every, mod_name=mod.name, t0=m0,
        )

    def run(self) -> Result:
        try:
            return self._run()
        finally:
            if self.executor is not None:
                self.executor.pool.close()
                self.executor.pool.join()

    def _run(self) -> Result:
        t0 = time.time()
        total = 0
        stats: list[ModuleStat] = []
        gbudget = self.ctx.limits.global_budget

        for mod in self.modules:
            if self.ctx.mode == "hash" and getattr(mod, "plaintext_only", False):
                print(term.dim(f"  [{mod.name}] skipped (needs plaintext target)"))
                continue

            note_fn = getattr(mod, "note", None)
            if note_fn:
                msg = note_fn(self.ctx)
                if msg:
                    print(term.dim(f"  [{mod.name}] {msg}"))

            budget = self._budget_for(mod)
            remaining_global = gbudget - total
            m0 = time.time()
            try:
                if self.executor is not None:
                    found, mtried = self._run_parallel(mod, budget, remaining_global, m0)
                else:
                    found, mtried = self._run_sequential(mod, budget, remaining_global, m0)
            except Exception as exc:  # a bad module shouldn't kill the run
                print(term.warn(f"    [{mod.name}] error: {exc!r}"))
                found, mtried = None, 0

            total += mtried
            if found is not None:
                stats.append(ModuleStat(mod.name, mtried, time.time() - m0, False))
                return Result(found, mod.name, total, total, time.time() - t0, stats)

            hit = mtried >= budget or total >= gbudget
            stats.append(ModuleStat(mod.name, mtried, time.time() - m0, hit))
            tag = " (budget hit)" if hit and total < gbudget else ""
            print(term.dim(f"  [{mod.name}] done: {mtried:,} tried "
                           f"in {time.time() - m0:.1f}s{tag}"))
            if total >= gbudget:
                print(term.dim("  global budget reached -- stopping."))
                break

        return Result(None, None, None, total, time.time() - t0, stats)
