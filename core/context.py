"""Shared state handed to every module."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from datetime import datetime

CURRENT_YEAR = datetime.now().year


@dataclass
class Hints:
    """Target-specific knowledge an attacker might realistically have."""

    username: str | None = None
    email: str | None = None
    name: str | None = None
    dob: str | None = None
    extra: list[str] = field(default_factory=list)

    def tokens(self) -> list[str]:
        out: list[str] = []
        if self.username:
            out.append(self.username)
        if self.email:
            local = self.email.split("@")[0]
            out.append(local)
            out += re.split(r"[._+\-]", local)
            domain = self.email.split("@")[-1].split(".")[0]
            if domain:
                out.append(domain)
        if self.name:
            parts = self.name.split()
            out += parts
            if len(parts) >= 2:
                out += [
                    "".join(parts),
                    parts[0] + parts[-1],
                    parts[0][0] + parts[-1],
                    parts[-1] + parts[0],
                    parts[0] + parts[-1][0],
                ]
        out += self.extra
        seen: set[str] = set()
        res: list[str] = []
        for t in out:
            t = t.strip()
            if len(t) >= 2 and t.lower() not in seen:
                seen.add(t.lower())
                res.append(t)
        return res

    def dob_parts(self) -> tuple[int, int, int] | None:
        if not self.dob:
            return None
        raw = self.dob.strip()
        fmts = [
            "%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%m/%d/%Y",
            "%d-%m-%Y", "%d.%m.%Y", "%d %B %Y", "%d %b %Y", "%B %d %Y",
        ]
        # separator-less digit strings, dispatched by length so a 4-digit
        # year can't be mistaken for a 2-digit one (day-first preferred)
        if raw.isdigit():
            if len(raw) == 8:
                fmts += ["%d%m%Y", "%m%d%Y", "%Y%m%d"]
            elif len(raw) == 6:
                fmts += ["%d%m%y", "%m%d%y", "%y%m%d"]
        for fmt in fmts:
            try:
                dt = datetime.strptime(raw, fmt)
                return (dt.day, dt.month, dt.year)
            except ValueError:
                continue
        return None


@dataclass
class Limits:
    word_cap: int | None = None       # per-wordlist load cap
    module_budget: int = 3_000_000    # max candidates per module
    global_budget: int = 10_000_000   # hard stop across all modules
    chain_vocab: int = 800            # top-N words fed to the word-chain generator
    chain_words: int = 3              # max words per chain (hash mode)
    dob_depth: int = 1               # dobwords structure depth (needs --dob)
    pin_six_digit: bool = False       # also sweep the full 6-digit PIN space


@dataclass
class CrackContext:
    matcher: object
    wordlists: object
    hints: Hints
    limits: Limits
    data_dir: str
    plaintext_target: str | None = None

    @property
    def mode(self) -> str:
        return getattr(self.matcher, "mode", "plaintext")
