"""Load and hold the dictionary wordlists from ./data."""

from __future__ import annotations

import os
import sys

# Order matters: cheaper / more-likely lists first.
WORDLISTS = [
    "passwords.txt",
    "female_names.txt",
    "male_names.txt",
    "surnames.txt",
    "us_tv_and_film.txt",
    "english_wikipedia.txt",
]


class WordlistBundle:
    """A de-duplicated, best-order-first list of base words."""

    def __init__(self, words: list[str]):
        self.words = words

    def __iter__(self):
        return iter(self.words)

    def __len__(self):
        return len(self.words)

    def top(self, n: int) -> list[str]:
        return self.words[:n]


def load(data_dir: str, cap: int | None = None) -> WordlistBundle:
    seen: set[str] = set()
    words: list[str] = []
    for name in WORDLISTS:
        path = os.path.join(data_dir, name)
        if not os.path.isfile(path):
            print(f"  ! missing wordlist: {path}", file=sys.stderr)
            continue
        count = 0
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for line in fh:
                token = line.strip().split()  # "word" or "word <freq>"
                if not token:
                    continue
                w = token[0]
                if w and w not in seen:
                    seen.add(w)
                    words.append(w)
                    count += 1
                    if cap and count >= cap:
                        break
    return WordlistBundle(words)
