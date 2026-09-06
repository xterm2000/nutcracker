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


_RESET_RE = None


def _visible_len(s: str) -> int:
    global _RESET_RE
    if _RESET_RE is None:
        import re
        _RESET_RE = re.compile(r"\033\[[0-9;]*m")
    return len(_RESET_RE.sub("", s))


def table(rows, *, title: str | None = None, kw: int | None = None,
          vw: int = 56, style_name: str = "dim") -> str:
    """A plain-ASCII box table from (key, value) pairs. Values wider than `vw`
    are truncated with a '~'. Colour is applied per whole line (alignment-safe);
    cell text should be plain."""
    rows = [(str(k), str(v)) for k, v in rows]
    kw = kw or max((len(k) for k, _ in rows), default=4)

    def _fit(s: str, w: int) -> str:
        n = _visible_len(s)
        if n > w:
            return s[:w - 1] + "~"
        return s + " " * (w - n)

    span = kw + vw + 3          # inner width of a merged (title) row
    bar = "+" + "-" * (kw + 2) + "+" + "-" * (vw + 2) + "+"
    out: list[str] = []
    if title:
        out.append("+" + "-" * (span + 2) + "+")
        out.append("| " + _fit(title, span) + " |")
    out.append(bar)
    for k, v in rows:
        out.append(f"| {_fit(k, kw)} | {_fit(v, vw)} |")
    out.append(bar)
    body = "\n".join(out)
    return style(body, style_name) if _enabled else body


def panel(body: str, *, title: str | None = None, width: int = 72,
          style_name: str = "dim") -> str:
    """A bordered box holding free-flowing text (word-wrapped to `width`), with
    an optional header row. `title` may carry its own ANSI codes (e.g. a
    coloured verdict) -- it is measured by visible width and left un-restyled."""
    import textwrap

    def _bar() -> str:
        return "+" + "-" * (width + 2) + "+"

    def _row(s: str) -> str:
        return "| " + s + " " * max(0, width - _visible_len(s)) + " |"

    out = [_bar()]
    if title:
        out.append(_row(title))
        out.append(_bar())
    for para in body.strip().split("\n"):
        if not para.strip():
            out.append(_row(""))
            continue
        for line in textwrap.wrap(para.strip(), width) or [""]:
            out.append(_row(line))
    out.append(_bar())

    if not _enabled:
        return "\n".join(out)
    title_idx = 1 if title else -1
    return "\n".join(ln if i == title_idx else style(ln, style_name)
                     for i, ln in enumerate(out))


configure()
