"""Ordered pipeline: run each module cheapest-first, within budgets."""

from __future__ import annotations

import time
from dataclasses import dataclass, field

from core import term

# one-line, plain-language description of the candidates each module streams --
# printed before the module runs so a long session stays legible ("what is it
# chewing on right now?"). Keyed by module .name; unknown modules fall back to
# a generic string.
_MODULE_ACTION = {
    "context":    "your hint words glued together, in case and separator variants",
    "permute":    "your hint words in every order, glued with each separator",
    "phone":      "phone-number-shaped digit strings built from the hints",
    "pins":       "numeric PINs -- 4-6 digits, dates, repeats, keypad walks",
    "dictionary": "each wordlist entry unchanged",
    "sequences":  "runs and repeats -- 123456, abcabc, aaaa, doubled words",
    "keyboard":   "keyboard walks and finger-mash patterns (qwerty, asdasd, q1w2e3)",
    "dates":      "years, full calendar dates, season+year, month names",
    "rules":      "each wordlist word mangled -- case flips, leet, digit and year tails",
    "wordchain":  "several dictionary words run together, with a separator or none",
    "dobwords":   "hint words glued to dates around the given birthday",
    "hybrid":     "each top word glued to every string the mask expands to",
    "fuzz":       "wordlist words (and hints) with one or two characters swapped",
    "mask":       "every string that fits the mask / brute charset",
}


class _Progress:
    """Emits '[mod] N tried (rate/s)' lines while a module runs, and *widens*
    the interval the longer it drags on -- so a 25M-candidate module prints a
    handful of lines, not 25. Each widening is announced so the reduction is
    visible in the log."""

    _WIDEN_AFTER = 5           # progress lines at one interval, then double it
    _MAX_INTERVAL = 64_000_000

    def __init__(self, mod_name: str, base_every: int, t0: float, *,
                 mod_budget: int | None = None, global_budget: int | None = None,
                 prior_total: int = 0):
        self.mod = mod_name
        self.every = max(1, base_every)
        self.t0 = t0
        self.mod_budget = mod_budget
        self.global_budget = global_budget
        self.prior_total = prior_total
        self.next_at = self.every
        self.since_widen = 0

    def _pct(self, tried: int) -> str:
        parts = []
        if self.mod_budget:
            parts.append(f"module {min(100.0, tried / self.mod_budget * 100):.0f}%")
        if self.global_budget:
            done = self.prior_total + tried
            parts.append(f"total {min(100.0, done / self.global_budget * 100):.0f}%")
        return ("  " + " / ".join(parts)) if parts else ""

    def tick(self, tried: int) -> None:
        if tried < self.next_at:
            return
        rate = tried / (time.time() - self.t0 + 1e-9)
        print(term.dim(f"    [{self.mod}] {tried:,} tried "
                       f"({rate:,.0f}/s){self._pct(tried)}"))
        self.since_widen += 1
        if self.since_widen >= self._WIDEN_AFTER and self.every < self._MAX_INTERVAL:
            self.every *= 2
            self.since_widen = 0
            print(term.dim(f"    [{self.mod}] large keyspace -- reducing progress "
                           f"updates to every {self.every:,} candidates"))
        self.next_at = tried + self.every


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

    def _target_clause(self) -> str:
        """A sentence describing how every candidate is checked this run."""
        m = self.matcher
        cls = m.__class__.__name__
        if cls == "PlaintextMatcher":
            return "comparing each candidate directly against the known target string"
        if cls == "ZipMatcher":
            kind = "AES" if getattr(m, "_aes", False) else "ZipCrypto"
            return f"trying each candidate as the password for {kind} archive entry {m._entry!r}"
        if cls == "HashMatcher":
            n = len(m.targets)
            plural = "es" if n != 1 else ""
            if getattr(m, "bcrypt", False):
                return f"running bcrypt.checkpw on each candidate against {n} target hash{plural}"
            salt = ""
            if m.salt_prefix or m.salt_suffix:
                salt = f" ({m.salt_prefix!r} + candidate + {m.salt_suffix!r})"
            return (f"hashing each candidate with {m.algo}{salt} and comparing the "
                    f"digest to {n} target hash{plural}")
        return "comparing each candidate against the target"

    def _progress_for(self, mod, budget, remaining_global, m0, prior_total):
        return _Progress(mod.name, self.progress_every, m0,
                         mod_budget=min(budget, remaining_global),
                         global_budget=self.ctx.limits.global_budget,
                         prior_total=prior_total)

    def _run_sequential(self, mod, budget: int, remaining_global: int, m0: float,
                        prior_total: int = 0):
        tried = 0
        prog = self._progress_for(mod, budget, remaining_global, m0, prior_total)
        for cand in mod.generate(self.ctx):
            tried += 1
            if self.matcher.matches(cand):
                return cand, tried
            if tried >= budget or tried >= remaining_global:
                break
            prog.tick(tried)
        return None, tried

    def _run_parallel(self, mod, budget: int, remaining_global: int, m0: float,
                      prior_total: int = 0):
        return self.executor.run_module(
            mod.generate(self.ctx), budget, remaining_global,
            progress=self._progress_for(mod, budget, remaining_global, m0, prior_total),
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

        print(term.dim(f"  each step: {self._target_clause()}"))

        for mod in self.modules:
            if self.ctx.mode == "hash" and getattr(mod, "plaintext_only", False):
                print(term.dim(f"  [{mod.name}] skipped (needs plaintext target)"))
                continue

            action = _MODULE_ACTION.get(mod.name, "generated candidates")
            print(f"  {term.label('[' + mod.name + ']')} {term.dim('trying ' + action)}")

            note_fn = getattr(mod, "note", None)
            if note_fn:
                msg = note_fn(self.ctx)
                if msg:
                    print(term.dim(f"    -> {msg}"))

            budget = self._budget_for(mod)
            remaining_global = gbudget - total
            m0 = time.time()
            try:
                if self.executor is not None:
                    found, mtried = self._run_parallel(mod, budget, remaining_global, m0, total)
                else:
                    found, mtried = self._run_sequential(mod, budget, remaining_global, m0, total)
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
            tot_pct = min(100.0, total / gbudget * 100) if gbudget else 0.0
            print(term.dim(f"  [{mod.name}] done: {mtried:,} tried "
                           f"in {time.time() - m0:.1f}s  (total {tot_pct:.0f}%){tag}"))
            if total >= gbudget:
                print(term.dim("  global budget reached -- stopping."))
                break

        return Result(None, None, None, total, time.time() - t0, stats)
