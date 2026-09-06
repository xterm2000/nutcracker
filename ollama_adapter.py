import os
import sys
import json

import requests


_REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _cfg(key, default):
    """Read key from config.json (repo root, optional); fall back to default."""
    try:
        with open(os.path.join(_REPO_ROOT, "config.json")) as f:
            return json.load(f).get(key, default)
    except (FileNotFoundError, ValueError):
        return default


# where the local ollama server lives, and which model to narrate with --
# override in config.json ("ollama_url" / "ollama_model").
OLLAMA_URL = _cfg("ollama_url", "http://localhost:11434/api/chat")
DEFAULT_MODEL = _cfg("ollama_model", "gemma2:2b")


def send_to_ollama(
    message: str,
    model: str = None,
    system: str | None = None,
    history: list[dict] | None = None,
    options: dict | None = None,
) -> str:
    messages = list(history or [])
    if system and not any(m.get("role") == "system" for m in messages):
        messages.insert(0, {"role": "system", "content": system})
    messages.append({"role": "user", "content": message})

    r = requests.post(
        OLLAMA_URL,
        json={
            "model": model or DEFAULT_MODEL,
            "messages": messages,
            "stream": False,
            "think": False,
            "keep_alive": "5m",
            "options": options or {},
        },
        timeout=300,
    )
    r.raise_for_status()
    return r.json()["message"]["content"]


class Conversation:
    """Multi-turn chat against the local ollama model -- keeps history so each
    send() sees prior turns."""

    def __init__(self, model: str = None, system: str | None = None, options: dict | None = None):
        self.model = model
        self.system = system
        self.options = options
        self.history: list[dict] = []

    def send(self, message: str) -> str:
        reply = send_to_ollama(
            message, model=self.model, system=self.system,
            history=self.history, options=self.options,
        )
        self.history.append({"role": "user", "content": message})
        self.history.append({"role": "assistant", "content": reply})
        return reply

    def send_file(self, path: str, message: str = "") -> str:
        """Read a text file and send its content as part of the message."""
        with open(path, encoding="utf-8", errors="replace") as f:
            content = f.read()
        prompt = f"FILE: {path}\n---\n{content}\n---\n{message}".strip()
        return self.send(prompt)


def main():
    convo = Conversation()
    print("ollama chat -- empty line or Ctrl-D to quit, /load <path> to attach a file")
    while True:
        try:
            msg = input("> ").strip()
        except EOFError:
            break
        if not msg:
            break
        if msg.startswith("/load "):
            path = msg[len("/load "):].strip()
            try:
                print(convo.send_file(path))
            except OSError as e:
                print(f"[could not read {path}: {e}]")
            continue
        print(convo.send(msg))


if __name__ == "__main__":
    sys.exit(main())
