"""Tiny ANSI colour helper -- muted 256-colour palette, off unless stdout is a
real terminal (honours NO_COLOR and TERM=dumb; `--color always/never` overrides).

Import and call `configure()` once from main; everything else just calls the
style shortcuts, which return the text unchanged when colour is disabled.
"""

from __future__ import annotations

import os
import sys

_enabled = False

# deliberately low-saturation (foreground 256-colour tones, no bright/bold spam)
_STYLES = {
    "head":   "38;5;188",   # near-white, section headers
    "label":  "38;5;109",   # dusty blue, "Target :" style labels
    "ok":     "38;5;108",   # muted sage green
    "warn":   "38;5;179",   # soft amber
    "bad":    "38;5;174",   # dusty rose
    "accent": "38;5;146",   # pale lavender-grey, numbers
    "dim":    "38;5;245",   # grey, secondary text
}


def configure(mode: str = "auto") -> None:
    global _enabled
    if mode == "always":
        _enabled = True
    elif mode == "never":
        _enabled = False
    else:
        _enabled = (
            sys.stdout.isatty()
            and not os.environ.get("NO_COLOR")
            and os.environ.get("TERM", "") not in ("", "dumb")
        )


def enabled() -> bool:
    return _enabled


def style(text: str, name: str) -> str:
    if not _enabled:
        return text
    return f"\033[{_STYLES[name]}m{text}\033[0m"


def head(t: str) -> str:
    return style(t, "head")


def label(t: str) -> str:
    return style(t, "label")


def ok(t: str) -> str:
    return style(t, "ok")


def warn(t: str) -> str:
    return style(t, "warn")


def bad(t: str) -> str:
    return style(t, "bad")


def accent(t: str) -> str:
    return style(t, "accent")


def dim(t: str) -> str:
    return style(t, "dim")


configure()
