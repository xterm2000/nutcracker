"""Optional second opinion on a finished run, from a local Ollama model.

OFF by default -- it does nothing unless ``OLLAMA_MODEL`` is set in the
environment. Pure standard library (``urllib`` against Ollama's HTTP API) --
no ``ollama`` package, nothing to pip install.

`crack.py` loads a project `.env` first (`core/dotenv.py`), so these can live
there; a real environment variable still overrides the file.

Environment:

  OLLAMA_MODEL        model tag, e.g. 'llama3.2' or 'gemma2:latest'  (REQUIRED to enable)
  OLLAMA_URL          full endpoint URL -- wins if set, e.g.
                      http://box:11434/api/chat  (or .../api/generate)
  OLLAMA_HOST         host or base URL if OLLAMA_URL is unset; a bare host/IP is
                      fine ('192.168.1.5' -> http://192.168.1.5:11434/api/chat)
  OLLAMA_TEMPERATURE  sampling temperature            (default 0.2)
  OLLAMA_TIMEOUT      seconds to wait for the reply   (default 60)
  OLLAMA_NUM_CTX      context-window override         (optional)

The model is handed the run's report text (which already carries the tool's own
crack-time ladder) and asked for a JSON object with three keys -- a one-word
``verdict``, a short ``crack_time`` phrase, and a free-text ``opinion`` paragraph
that also comments on the timing. `consult()` parses that and returns
``({verdict, crack_time, opinion, model}, None)`` for `crack.py` to render as a
bordered panel -- or ``(None, reason)`` on any failure (model unset, server down,
timeout, bad JSON). It never raises.

Note: in plaintext (``-p``) mode the report contains the password itself, so
the plaintext is sent to your local Ollama instance. It is localhost by
default and nothing leaves the machine, but point ``OLLAMA_HOST`` somewhere
remote and that stops being true.
"""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.request
from urllib.parse import urlsplit

# The answer template: (json key, what the model should put there) -- the
# contract shown to the model.
_FIELDS: list[tuple[str, str]] = [
    ("verdict",    "one word only: trivial | weak | moderate | strong | excellent"),
    ("crack_time", "your own rough estimate of offline crack time, one short phrase "
                   "(e.g. 'seconds on a GPU', 'a few days', 'centuries')"),
    ("opinion",    "3-5 plain sentences: whether you agree with the tool and its "
                   "timing figures, the single biggest weakness, how long a "
                   "realistic attacker needs and why, and the one change that "
                   "would help most"),
]

_SYSTEM = (
    "You are a password-security reviewer. You receive a report from a "
    "dictionary/pattern password-auditing tool -- including its own crack-time "
    "estimates for several attacker scenarios -- and give a brief, sober second "
    "opinion. Explicitly address the timing: say whether the tool's estimates "
    "look right and what a realistic attacker's wall-clock time is. Do not repeat "
    "the report back. Reply with ONLY a JSON object with exactly the keys "
    '"verdict", "crack_time" and "opinion" -- no prose, no markdown, no code '
    "fence. Keep the opinion to a short paragraph of full sentences."
)


def _prompt(report: str) -> str:
    shape = ",\n".join(f'  "{k}": "<{desc}>"' for k, desc in _FIELDS)
    return (
        f"{_SYSTEM}\n\n"
        f"--- AUDIT REPORT ---\n{report.strip()}\n--- END REPORT ---\n\n"
        f"Return exactly this JSON shape and nothing else:\n{{\n{shape}\n}}\n"
    )


def _env_float(name: str, default: float) -> float:
    try:
        return float(os.environ[name])
    except (KeyError, ValueError):
        return default


def enabled() -> bool:
    return bool(os.environ.get("OLLAMA_MODEL", "").strip())


def _endpoint() -> tuple[str, str]:
    """(url, api) -- api is 'chat' or 'generate'. OLLAMA_URL wins if set; else
    build from OLLAMA_HOST (a bare host/IP is fine), defaulting to /api/chat."""
    url = os.environ.get("OLLAMA_URL", "").strip()
    if url:
        return url, ("generate" if url.rstrip("/").endswith("/api/generate") else "chat")
    host = os.environ.get("OLLAMA_HOST", "").strip() or "http://localhost:11434"
    if "://" not in host:
        host = "http://" + host
    parts = urlsplit(host)
    netloc = parts.netloc or parts.path          # tolerate 'host' with no scheme slip
    if ":" not in netloc:
        netloc = f"{netloc}:11434"
    return f"{parts.scheme or 'http'}://{netloc}/api/chat", "chat"


def consult(report: str) -> tuple[dict[str, str] | None, str | None]:
    """Ask the configured Ollama model for an opinion on `report`.

    Returns ({verdict, crack_time, opinion, model}, None) on success, or (None, reason) if
    disabled or anything goes wrong. Never raises.
    """
    try:
        return _consult(report)
    except Exception as exc:  # last-resort guard -- an opinion must never be fatal
        return None, f"opinion failed ({type(exc).__name__}: {exc})"


def _consult(report: str) -> tuple[dict[str, str] | None, str | None]:
    model = os.environ.get("OLLAMA_MODEL", "").strip()
    if not model:
        return None, "set OLLAMA_MODEL (+ optionally OLLAMA_HOST) for a local LLM opinion"

    url, api = _endpoint()
    timeout = _env_float("OLLAMA_TIMEOUT", 60.0)
    options: dict[str, object] = {"temperature": _env_float("OLLAMA_TEMPERATURE", 0.2)}
    if os.environ.get("OLLAMA_NUM_CTX", "").strip():
        try:
            options["num_ctx"] = int(os.environ["OLLAMA_NUM_CTX"])
        except ValueError:
            pass

    if api == "chat":
        payload = {"model": model, "stream": False, "format": "json",
                   "options": options,
                   "messages": [{"role": "system", "content": _SYSTEM},
                                {"role": "user", "content": _prompt(report)}]}
    else:
        payload = {"model": model, "prompt": _prompt(report), "stream": False,
                   "format": "json", "options": options}

    req = urllib.request.Request(
        url, data=json.dumps(payload).encode(),
        headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            envelope = json.loads(resp.read())
    except urllib.error.HTTPError as exc:
        detail = ""
        try:
            detail = f": {json.loads(exc.read()).get('error', '')}"
        except Exception:
            pass
        return None, f"Ollama HTTP {exc.code} for model {model!r}{detail}"
    except urllib.error.URLError as exc:
        return None, f"Ollama unreachable at {url} ({exc.reason})"
    except (TimeoutError, OSError) as exc:
        return None, f"Ollama request failed ({exc})"
    except json.JSONDecodeError:
        return None, "Ollama returned a non-JSON envelope"

    if api == "chat":
        raw = ((envelope.get("message") or {}).get("content") or "").strip()
    else:
        raw = (envelope.get("response") or "").strip()
    try:
        answer = json.loads(raw)
    except (json.JSONDecodeError, TypeError):
        return None, f"model reply was not valid JSON: {raw[:120]!r}"
    if not isinstance(answer, dict):
        return None, "model reply was JSON but not an object"

    data = {key: str(answer.get(key, "")).strip() for key, _desc in _FIELDS}
    data["model"] = model
    if not data["opinion"]:
        return None, f"model reply had no opinion text: {raw[:120]!r}"
    return data, None
