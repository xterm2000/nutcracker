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

from modules.bip39 import Bip39Module
from modules.context_based import ContextModule
from modules.dates import DateModule
from modules.dictionary import DictionaryModule
from modules.dobwords import DobWordsModule
from modules.fuzz import FuzzModule
from modules.hybrid import HybridModule
from modules.keyboard import KeyboardModule
from modules.mask import MaskModule
from modules.permute import PermuteModule
from modules.phone import PhoneModule
from modules.pins import PinModule
from modules.rules import RulesModule
from modules.sequences import SequenceModule
from modules.wordchain import WordChainModule

ALWAYS = [
    ContextModule, PhoneModule, PinModule, DictionaryModule,
    SequenceModule, KeyboardModule, DateModule, RulesModule,
]


def build(only=None, skip=None, *, mode="plaintext", chain_words=3, chain_vocab=800,
          dob_depth=1, mask=None, brute=False, charset="d", min_len=1, max_len=8,
          ruleset=None, hybrid_mask=None, hybrid_side="both", hybrid_vocab=2000,
          fuzz=None, fuzz_vocab=2000, fuzz_charset="sub",
          permute=False, permute_seps=None, permute_fill=0, permute_vocab=200):
    insts = [cls() for cls in ALWAYS]

    if ruleset is not None:
        for m in insts:
            if m.name == "rules":
                m.ruleset = ruleset
                # words x rules multiplies fast; give it room under the global cap
                m.budget = 25_000_000

    if hybrid_mask:
        insts.append(HybridModule(mask=hybrid_mask, side=hybrid_side, vocab=hybrid_vocab))

    if fuzz:
        insts.append(FuzzModule(n=fuzz, vocab=fuzz_vocab, charset=fuzz_charset))

    if permute:
        insts.append(PermuteModule(seps=permute_seps, fill=permute_fill,
                                   vocab=permute_vocab))

    bip = Bip39Module()
    if mode == "hash":
        bip.order = 27          # same reason as wordchain below -- 2048**k blows up
    insts.append(bip)

    wc = WordChainModule(chain_words=chain_words, vocab=chain_vocab)
    if mode == "hash":
        # hash-mode wordchain is a big generator with low relative yield --
        # run it after dictionary/rules rather than ahead of them
        wc.order = 26
    insts.append(wc)

    insts.append(DobWordsModule(depth=dob_depth))
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
    return [cls().name for cls in ALWAYS] + [
        "bip39", "wordchain", "dobwords", "hybrid", "fuzz", "permute", "mask"]
