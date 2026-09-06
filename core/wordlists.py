"""Load and hold the dictionary wordlists from ./data."""

from __future__ import annotations

import os
import sys

# Order matters: cheaper / more-likely lists first.
WORDLISTS = [
    "passwords.txt",
    "female_names.txt",
    "male_names.txt",
    "given_names_intl.txt",
    "surnames.txt",
    "us_tv_and_film.txt",
    "world_cities.txt",
    "english_wikipedia.txt",
]


# the frequency-sorted English list -- its line number is a usable "how common
# is this word in ordinary English" rank, which `wordchain` uses to keep its
# run-together decomposition from tiling a password out of rare 2-3 char cruft.
_RANK_LIST = "english_wikipedia.txt"

# first-name lists are popularity-ordered too; fold them into the commonness
# rank (best-of, so a name that is also a common English word keeps the better
# rank) -- this lets `wordchain` accept short first names (eve, ana, kim, sam)
# as real segments instead of "cruft". Surnames are deliberately left out.
_NAME_RANK_LISTS = ("female_names.txt", "male_names.txt")


class WordlistBundle:
    """A de-duplicated, best-order-first list of base words."""

    def __init__(self, words: list[str], wiki_rank: dict[str, int] | None = None):
        self.words = words
        self.wiki_rank = wiki_rank or {}

    def __iter__(self):
        return iter(self.words)

    def __len__(self):
        return len(self.words)

    def top(self, n: int) -> list[str]:
        return self.words[:n]

    def is_common(self, word: str, cutoff: int = 25_000) -> bool:
        """True if `word` is within the top `cutoff` of the English frequency
        list -- i.e. a word an ordinary person actually uses, not list cruft."""
        return self.wiki_rank.get(word.lower(), 1 << 30) < cutoff


def load(data_dir: str, cap: int | None = None,
         extra: list[str] | None = None) -> WordlistBundle:
    seen: set[str] = set()
    words: list[str] = []
    wiki_rank: dict[str, int] = {}
    # user-supplied lists load first so they take priority in dictionary/rules order
    paths = list(extra or []) + [os.path.join(data_dir, n) for n in WORDLISTS]
    for path in paths:
        name = os.path.basename(path)
        if not os.path.isfile(path):
            print(f"  ! missing wordlist: {path}", file=sys.stderr)
            continue
        count = 0
        with open(path, encoding="utf-8", errors="ignore") as fh:
            for idx, line in enumerate(fh):
                token = line.strip().split()  # "word" or "word <freq>"
                if not token:
                    continue
                w = token[0]
                if name == _RANK_LIST or name in _NAME_RANK_LISTS:
                    lw = w.lower()
                    prev = wiki_rank.get(lw)
                    if prev is None or idx < prev:
                        wiki_rank[lw] = idx
                if w and w not in seen:
                    seen.add(w)
                    words.append(w)
                    count += 1
                    if cap and count >= cap:
                        break
    return WordlistBundle(words, wiki_rank)
