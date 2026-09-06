"""Minimal .env loader -- stdlib only.

Handles `KEY=value`, `KEY="value"`, `KEY='value'`, `export KEY=value`, `#`
comments, blank lines, and `$VAR` / `${VAR}` expansion (against values already
loaded, or the real environment) for unquoted and double-quoted values.

Does NOT override a variable already set in the real environment, so an
explicit `OLLAMA_MODEL=x ./crack.py` still wins over the file.
"""

from __future__ import annotations

import os
import re

_LINE = re.compile(r"^\s*(?:export\s+)?([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(.*?)\s*$")
_VAR = re.compile(r"\$\{?([A-Za-z_][A-Za-z0-9_]*)\}?")


def load(path: str, *, override: bool = False) -> dict[str, str]:
    """Parse `path` and merge into os.environ. Returns the parsed pairs.
    A missing/unreadable file is not an error -- returns {}."""
    loaded: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8") as fh:
            raw = fh.readlines()
    except OSError:
        return loaded

    for line in raw:
        if not line.strip() or line.lstrip().startswith("#"):
            continue
        m = _LINE.match(line)
        if not m:
            continue
        key, val = m.group(1), m.group(2)
        q = val[:1] if val[:1] in ("'", '"') else ""
        if q and val[-1:] == q:
            val = val[1:-1]
        elif not q:                       # strip a trailing inline comment
            val = val.split(" #", 1)[0].rstrip()
        if q != "'":                      # expand $VAR except in single quotes
            val = _VAR.sub(lambda mm: os.environ.get(
                mm.group(1), loaded.get(mm.group(1), "")), val)
        loaded[key] = val
        if override or key not in os.environ:
            os.environ[key] = val
    return loaded
