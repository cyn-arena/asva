"""Keyword (BM25) search over the same cheat-sheet sections the similarity search ranks.

A fallback only. Similarity search matches meaning and usually wins, but when its best score
for a finding is low it has often latched onto the wrong topic: NodeGoat's "Use of Hardcoded
Passwords" finding ranked brute-force and credential-stuffing advice first, while the exact
words of the finding ("hardcoded", "secret") lead straight to the secrets-management sections.
"""

import math
import re
from collections import Counter

import numpy as np

K1 = 1.5   # term-frequency saturation
B = 0.75   # length normalisation

_WORD = re.compile(r"[a-z0-9][a-z0-9\-.]*[a-z0-9]|[a-z0-9]")
STOPWORDS = frozenset(
    "a an and are as at be by for from has have in is it its may of on or that the this to was "
    "where which with into how can will used using use result".split())


def tokenize(text: str) -> list[str]:
    return [word for word in _WORD.findall(text.lower()) if word not in STOPWORDS]


class KeywordIndex:
    """BM25 over a fixed list of texts; `scores(query)` returns one score per text."""

    def __init__(self, texts: list[str]):
        documents = [tokenize(text) for text in texts]
        self.size = len(documents)
        lengths = np.array([len(d) for d in documents], dtype=np.float32)
        average = float(lengths.mean()) if self.size else 1.0
        self._norm = K1 * (1 - B + B * lengths / (average or 1.0))
        self._postings: dict[str, tuple[np.ndarray, np.ndarray]] = {}
        postings: dict[str, list[tuple[int, int]]] = {}
        for index, document in enumerate(documents):
            for word, count in Counter(document).items():
                postings.setdefault(word, []).append((index, count))
        for word, entries in postings.items():
            self._postings[word] = (np.array([i for i, _ in entries]), np.array([c for _, c in entries], dtype=np.float32))

    def scores(self, query: str) -> np.ndarray:
        out = np.zeros(self.size, dtype=np.float32)
        for word in set(tokenize(query)):
            if word not in self._postings:
                continue
            where, counts = self._postings[word]
            idf = math.log(1 + (self.size - len(where) + 0.5) / (len(where) + 0.5))
            out[where] += idf * counts * (K1 + 1) / (counts + self._norm[where])
        return out
