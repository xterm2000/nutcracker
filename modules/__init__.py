"""Module registry + builder.

Each module exposes:
  name             -- str, unique
  order            -- int, lower runs first (cheapest / highest-value first)
  generate(ctx)    -- iterator of candidate plaintext strings
  plaintext_only   -- optional bool, skipped in hash mode
  note(ctx)        -- optional, returns an advisory string printed before running
  budget           -- optional int, overrides limits.module_budget
"""

from __future__ import annotations

from modules.combinator import CombinatorModule
from modules.context_based import ContextModule
from modules.dates import DateModule
from modules.dictionary import DictionaryModule
from modules.keyboard import KeyboardModule
from modules.mask import MaskModule
from modules.passphrase import PassphraseModule
from modules.phone import PhoneModule
from modules.pins import PinModule
from modules.rules import RulesModule
from modules.sequences import SequenceModule

ALWAYS = [
    PassphraseModule, ContextModule, PhoneModule, PinModule, DictionaryModule,
    SequenceModule, KeyboardModule, DateModule, RulesModule,
]


def build(only=None, skip=None, *, combinator_words=800, mask=None, brute=False,
          charset="d", min_len=1, max_len=8):
    insts = [cls() for cls in ALWAYS]
    insts.append(CombinatorModule(words=combinator_words))
    if mask or brute:
        insts.append(MaskModule(mask=mask, brute=brute, charset=charset,
                                min_len=min_len, max_len=max_len))
    if only:
        only = set(only)
        insts = [m for m in insts if m.name in only]
    if skip:
        skip = set(skip)
        insts = [m for m in insts if m.name not in skip]
    insts.sort(key=lambda m: m.order)
    return insts


def names():
    return [cls().name for cls in ALWAYS] + ["combinator", "mask"]
