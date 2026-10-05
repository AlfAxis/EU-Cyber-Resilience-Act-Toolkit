"""Simplified, ecosystem-agnostic version ordering.

Used only by the *offline* vulnerability matcher. The online path delegates
matching to OSV.dev, which implements each ecosystem's native ordering.

The comparison tokenises versions into numbers and words and handles the
patterns shared by SemVer, PEP 440, Maven and Composer well enough for typical
advisory ranges: ``1.0 == 1.0.0``, ``1.0-rc1 < 1.0``, ``1.0 < 1.0.1``. It is
intentionally *not* a full implementation of any single scheme; exotic
versions (PEP 440 epochs, Maven qualifier edge cases) can mis-order.
"""

from __future__ import annotations

import re

_TOKEN = re.compile(r"\d+|[A-Za-z]+")

# Words that sort *before* the release they qualify (pre-releases).
_PRE_RELEASE_RANK = {
    "dev": -6.0,
    "snapshot": -6.0,
    "alpha": -5.0,
    "a": -5.0,
    "beta": -4.0,
    "b": -4.0,
    "milestone": -3.0,
    "m": -3.0,
    "pre": -2.0,
    "preview": -2.0,
    "rc": -1.0,
    "cr": -1.0,
}
# Words that sort *after* the release they qualify.
_POST_RELEASE_RANK = {"post": 1.0, "sp": 1.0, "patch": 1.0, "pl": 1.0, "p": 1.0}
# Words that mean "the plain release" and carry no ordering information.
_NEUTRAL = {"final", "ga", "release", "stable"}
# Unknown words are treated as pre-release markers, ranked just below the release.
_UNKNOWN_RANK = -0.5

_Element = tuple[int, float, int, str]
_PAD: _Element = (0, 0.0, 0, "")


def version_key(version: str) -> tuple[_Element, ...]:
    text = version.strip()
    if text[:1] in ("v", "V"):
        text = text[1:]
    text = text.split("+", 1)[0]  # build metadata (and Go's "+incompatible") never orders
    elements: list[_Element] = []
    for token in _TOKEN.findall(text):
        if token.isdigit():
            elements.append((0, 0.0, int(token), ""))
            continue
        word = token.lower()
        if word in _NEUTRAL:
            continue
        if word in _POST_RELEASE_RANK:
            elements.append((1, _POST_RELEASE_RANK[word], 0, word))
        else:
            elements.append((-1, _PRE_RELEASE_RANK.get(word, _UNKNOWN_RANK), 0, word))
    return tuple(elements)


def compare_versions(left: str, right: str) -> int:
    """Return -1, 0 or 1 as ``left`` is older than, equal to, or newer than ``right``."""
    a, b = version_key(left), version_key(right)
    size = max(len(a), len(b))
    a += (_PAD,) * (size - len(a))
    b += (_PAD,) * (size - len(b))
    return (a > b) - (a < b)
