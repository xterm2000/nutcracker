"""Ordered pipeline: run each module cheapest-first, within budgets."""

from __future__ import annotations

import time
from dataclasses import dataclass, field


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
    def __init__(self, modules, ctx, progress_every: int = 500_000):
        self.modules = modules
        self.ctx = ctx
        self.matcher = ctx.matcher
        self.progress_every = progress_every

    def _budget_for(self, mod) -> int:
        return getattr(mod, "budget", None) or self.ctx.limits.module_budget

    def run(self) -> Result:
        t0 = time.time()
        total = 0
        stats: list[ModuleStat] = []
        gbudget = self.ctx.limits.global_budget

        for mod in self.modules:
            if self.ctx.mode == "hash" and getattr(mod, "plaintext_only", False):
                print(f"  [{mod.name}] skipped (needs plaintext target)")
                continue

            note_fn = getattr(mod, "note", None)
            if note_fn:
                msg = note_fn(self.ctx)
                if msg:
                    print(f"  [{mod.name}] {msg}")

            budget = self._budget_for(mod)
            m0 = time.time()
            mtried = 0
            hit = False
            try:
                for cand in mod.generate(self.ctx):
                    mtried += 1
                    total += 1
                    if self.matcher.matches(cand):
                        stats.append(ModuleStat(mod.name, mtried, time.time() - m0, False))
                        return Result(cand, mod.name, total, total, time.time() - t0, stats)
                    if mtried >= budget or total >= gbudget:
                        hit = True
                        break
                    if mtried % self.progress_every == 0:
                        rate = mtried / (time.time() - m0 + 1e-9)
                        print(f"    [{mod.name}] {mtried:,} tried ({rate:,.0f}/s)")
            except Exception as exc:  # a bad module shouldn't kill the run
                print(f"    [{mod.name}] error: {exc!r}")

            stats.append(ModuleStat(mod.name, mtried, time.time() - m0, hit))
            tag = " (budget hit)" if hit and total < gbudget else ""
            print(f"  [{mod.name}] done: {mtried:,} tried in {time.time() - m0:.1f}s{tag}")
            if total >= gbudget:
                print("  global budget reached -- stopping.")
                break

        return Result(None, None, None, total, time.time() - t0, stats)
