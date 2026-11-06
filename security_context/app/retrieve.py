"""OWASP guidance retrieval (similarity search) and CWE entry helpers.

For a file's findings, one "how to prevent and fix ..." query per distinct finding is ranked
against whole cheat-sheet sections, with small adjustments tuned on NodeGoat's 11 own-code
SAST issues:
  - intro/overview headings down-weighted, prevention headings up-weighted;
  - cheat sheets written for another language down-weighted when the finding's language is known;
  - a cheat sheet whose title clearly matches the finding is boosted (fixes SSRF vs CSRF mix-ups).
With 3 sections of <= 800 chars this covered more key fix advice (86% vs 77%) at half the
size (~1.9k vs ~3.7k chars) of the untuned version. See README "Retrieval tuning".

Keyword fallback: when a finding's best similarity score is low, its lowest-ranked sections
are swapped for the best keyword (BM25) matches, see app/keyword.py.
"""

import re
from collections import deque

import numpy as np

from app import config, store
from app.keyword import KeywordIndex
from app.sources import cwe as cwe_source
from app.sources import owasp
from app.text import truncate

MAX_HIERARCHY_DEPTH = 6
COMPACT_DESCRIPTION_CHARS = 250
COMPACT_MITIGATION_CHARS = 260
COMPACT_MITIGATIONS = 2

INTRO_HEADINGS = re.compile(
    r"^(introduction|context|overview|description|background|references|objective|recommendations|"
    r"summary|scope|purpose)\b", re.IGNORECASE)
FIX_HEADINGS = re.compile(
    r"prevent|defen|mitigat|protection|safe|avoid|recommend|do not|don't|validat|stay away|\buse |\bset |disable",
    re.IGNORECASE)
INTRO_WEIGHT = 0.85
FIX_WEIGHT = 1.05
OTHER_LANGUAGE_WEIGHT = 0.85
TITLE_MATCH_WEIGHT = 1.10
TITLE_MATCH_MIN = 0.5      # the best-matching cheat sheet title must be this similar...
TITLE_MATCH_MARGIN = 0.05  # ...and clearly ahead of the runner-up

_CWE = re.compile(r"^(?:CWE-)?(\d+)$", re.IGNORECASE)

# Prefixing the search query with the platform steers it away from other languages' cheat
# sheets (without it, NodeGoat's eval finding ranked the Java Security cheat sheet first).
LANGUAGE_HINTS = {
    "javascript": "JavaScript Node.js", "typescript": "TypeScript Node.js", "python": "Python",
    "java": "Java", "kotlin": "Kotlin", "csharp": "C# .NET", "php": "PHP", "go": "Go",
    "ruby": "Ruby", "swift": "Swift iOS", "cpp": "C++",
}
LANGUAGE_FAMILIES = {"typescript": "javascript"}


def normalise_cwe(value) -> str | None:
    match = _CWE.match(str(value).strip()) if value else None
    return f"CWE-{match.group(1)}" if match else None


def language_of(finding: dict) -> str | None:
    """Explicit `language`, else the prefix of a SAST rule_id ("javascript/CodeInjection")."""
    language = finding.get("language")
    rule_id = finding.get("rule_id") or ""
    if not language and "/" in rule_id:
        language = rule_id.split("/", 1)[0]
    return language.strip().lower() if language else None


def language_hint(finding: dict) -> str | None:
    language = language_of(finding)
    return LANGUAGE_HINTS.get(language, language) if language else None


def section_weight(section: str | None) -> float:
    last = section.split(" > ")[-1] if section else ""
    if not section or INTRO_HEADINGS.match(last):
        return INTRO_WEIGHT
    return FIX_WEIGHT if FIX_HEADINGS.search(section) else 1.0


def title_match(similarities: np.ndarray, doc_ids: list[str]) -> str | None:
    """The cheat sheet whose title clearly matches the finding, if there is one."""
    if len(doc_ids) < 2:
        return None
    best, second = np.argsort(-similarities)[:2]
    if similarities[best] >= TITLE_MATCH_MIN and similarities[best] - similarities[second] >= TITLE_MATCH_MARGIN:
        return doc_ids[best]
    return None


def item(source, key, kind, title, text, url, license, fetched_at, section=None, score=None, matched_by=None) -> dict:
    """One piece of prompt context."""
    return {"source": source, "key": key, "kind": kind, "title": title, "section": section,
            "text": text, "url": url, "license": license, "fetched_at": fetched_at, "score": score,
            "matched_by": matched_by}


def cwe_ancestors(conn, cwe: str):
    """Parent CWEs, nearest first (breadth-first up the hierarchy)."""
    seen, queue = {cwe}, deque([(cwe, 0)])
    while queue:
        current, depth = queue.popleft()
        if depth >= MAX_HIERARCHY_DEPTH:
            continue
        for parent in store.linked(conn, current, "child_of"):
            if parent not in seen:
                seen.add(parent)
                yield parent
                queue.append((parent, depth + 1))


def _mitigation_lines(text: str) -> list[str]:
    _, _, block = text.partition(f"\n{cwe_source.MITIGATIONS_HEADER}:\n")
    return [line for line in block.splitlines() if line.startswith("- ")]


def cwe_details(conn, cwe: str) -> dict | None:
    """A CWE entry's parts: {"record", "name_line", "description", "mitigations", "inherited_from"}.
    Mitigations are Implementation-phase first; a CWE with none borrows its nearest parent's."""
    record = store.get_record(conn, cwe, cwe_source.SOURCE)
    if record is None:
        return None
    name_line, _, rest = record["text"].partition("\n")
    description = rest.split(f"\n{cwe_source.MITIGATIONS_HEADER}:", 1)[0]
    lines, inherited_from = _mitigation_lines(record["text"]), None
    if not lines:
        for parent in cwe_ancestors(conn, cwe):
            parent_record = store.get_record(conn, parent, cwe_source.SOURCE)
            if parent_record and (lines := _mitigation_lines(parent_record["text"])):
                inherited_from = f"{parent}: {parent_record['title']}"
                break
    return {"record": record, "name_line": name_line, "description": description, "mitigations": lines,
            "inherited_from": inherited_from}


def cwe_compact_item(conn, cwe: str) -> dict | None:
    """The CWE's definition plus up to 2 mitigations (Implementation first), inheriting the
    mitigations of the nearest parent CWE if it has none. Used when no OWASP guidance matched."""
    details = cwe_details(conn, cwe)
    if details is None:
        return None
    record = details["record"]
    text = f"{details['name_line']}\n{truncate(details['description'], COMPACT_DESCRIPTION_CHARS)}"
    header = cwe_source.MITIGATIONS_HEADER
    if details["inherited_from"]:
        header += f" (inherited from parent {details['inherited_from']})"
    if details["mitigations"]:
        text += f"\n{header}:\n" + "\n".join(
            truncate(line, COMPACT_MITIGATION_CHARS) for line in details["mitigations"][:COMPACT_MITIGATIONS])
    return item(cwe_source.SOURCE, cwe, "cwe", record["title"], text, record["url"], record["license"],
                record["fetched_at"])


class Retriever:
    """Similarity search over the embedded OWASP cheat-sheet sections (held in memory)."""

    def __init__(self, embedder, chunks: list[store.ChunkMeta], matrix: np.ndarray,
                 min_similarity: float = config.MIN_SIMILARITY, top_k: int = config.GUIDANCE_TOP_K,
                 passage_max_chars: int = config.PASSAGE_MAX_CHARS,
                 fallback_below: float | None = None, fallback_results: int | None = None):
        self.embedder = embedder
        self.chunks = chunks
        self.matrix = matrix
        self.min_similarity = min_similarity
        self.top_k = top_k
        self.passage_max_chars = passage_max_chars
        # Keyword fallback: a best similarity under `fallback_below` is low confidence, and
        # `fallback_results` keyword sections are swapped in then (0 = never).
        self.fallback_below = config.KEYWORD_FALLBACK_BELOW if fallback_below is None else fallback_below
        self.fallback_results = config.KEYWORD_FALLBACK_RESULTS if fallback_results is None else fallback_results

        # A cheat-sheet section split into several chunks is returned as one unit.
        self.section_of = [(c.doc_id, c.section) for c in chunks]
        self.sections: dict[tuple, list[int]] = {}
        for idx, key in enumerate(self.section_of):
            self.sections.setdefault(key, []).append(idx)
        self.section_weights = np.array([section_weight(c.section) for c in chunks], dtype=np.float32)
        self.doc_ids = np.array([c.doc_id for c in chunks])
        self.title_docs = list(dict.fromkeys(c.doc_id for c in chunks))
        self._doc_titles = {c.doc_id: c.doc_title for c in chunks}
        self._title_vectors = None
        self._language_weights: dict[str, np.ndarray] = {}
        self._section_keys = list(self.sections)
        self._section_first = np.array([indices[0] for indices in self.sections.values()], dtype=np.int64)
        self._keyword_index: KeywordIndex | None = None  # built on first use

    @classmethod
    def from_db(cls, conn, embedder, **kwargs) -> "Retriever":
        chunks, matrix = store.load_chunks(conn)
        return cls(embedder, chunks, matrix, **kwargs)

    def _queries(self, conn, findings: list[dict], use_cwe: bool = True) -> list[dict]:
        """One query per distinct finding: [language:] how to prevent and fix <title>. <summary> <CWE name>."""
        queries, seen = [], set()
        for f in findings:
            title = f.get("title") or ""
            body = f.get("summary") or f.get("description") or ""
            if not (title or body):
                continue
            cwe = normalise_cwe(f.get("cwe")) if use_cwe else None
            record = store.get_record(conn, cwe, cwe_source.SOURCE) if cwe else None
            cwe_name = record["title"] if record else ""
            core = f"how to prevent and fix {title}. {body}" if title else f"how to prevent and fix: {body}"
            text = f"{core} {cwe_name}".strip()
            if hint := language_hint(f):
                text = f"{hint}: {text}"
            if text in seen:
                continue
            seen.add(text)
            queries.append({
                "label": title or body[:60],
                "text": text,
                "keyword_text": text,
                "title_text": " ".join(x for x in (title, cwe_name) if x) or body[:200],
                "language": LANGUAGE_FAMILIES.get(language_of(f), language_of(f)),
            })
        return queries

    def _title_similarities(self, texts: list[str]) -> np.ndarray:
        if self._title_vectors is None:
            self._title_vectors = self.embedder.embed([self._doc_titles[d] for d in self.title_docs])
        return self.embedder.embed(texts) @ self._title_vectors.T

    def _language_weight_vector(self, language: str | None) -> np.ndarray | float:
        if not language:
            return 1.0
        if language not in self._language_weights:
            self._language_weights[language] = np.array([
                OTHER_LANGUAGE_WEIGHT if (doc_lang := owasp.DOC_LANGUAGES.get(d)) and doc_lang != language else 1.0
                for d in self.doc_ids
            ], dtype=np.float32)
        return self._language_weights[language]

    def guidance(self, conn, findings: list[dict], warnings: list[str], trace: dict, *,
                 use_cwe: bool = True, keyword_fallback: bool = True) -> list[dict]:
        """The top cheat-sheet sections for these findings, best first."""
        if not self.chunks:
            warnings.append("No guidance passages loaded; run `python -m app.sync` first")
            return []
        queries = self._queries(conn, findings, use_cwe)
        trace["queries"] = []
        if not queries:
            return []
        similarities = self.embedder.embed([q["text"] for q in queries]) @ self.matrix.T
        title_similarities = self._title_similarities([q["title_text"] for q in queries])

        # Sections found per issue type (findings with the same title, e.g. two SQL injections at
        # different lines): [(section, rank score, "similarity" | "keyword")].
        by_type: dict[str, list[tuple[tuple, float, str]]] = {}
        for qi, query in enumerate(queries):
            language_weights = self._language_weight_vector(query["language"])
            scores = similarities[qi] * self.section_weights * language_weights
            matched = title_match(title_similarities[qi], self.title_docs)
            if matched:
                scores = np.where(self.doc_ids == matched, scores * TITLE_MATCH_WEIGHT, scores)
            picked: list[tuple[tuple, float]] = []
            for idx in np.argsort(-scores):
                score = float(scores[idx])
                if score < self.min_similarity or len(picked) >= self.top_k:
                    break
                key = self.section_of[idx]
                if all(key != chosen for chosen, _ in picked):
                    picked.append((key, score))

            top = float(scores.max())
            by_keyword = []
            # Low confidence: the lowest-ranked sections make way for keyword matches. With no
            # similarity match at all there is nothing to supplement (the CWE entry is used instead).
            if keyword_fallback and picked and top < self.fallback_below:
                by_keyword = self._keyword_sections(query, language_weights, {key for key, _ in picked})
                picked = picked[: max(self.top_k - len(by_keyword), 0)]
            trace["queries"].append({
                "text": query["text"], "language": query["language"], "title_match": matched,
                "best_similarity": round(top, 3),
                "keyword_fallback": [f"{doc} > {section or '(intro)'}" for doc, section in by_keyword]})
            found = by_type.setdefault(query["label"], [])
            found += [(key, score, "similarity") for key, score in picked]
            floor = min((score for _, score in picked), default=top)
            # keyword matches rank just below this finding's similarity matches
            found += [(key, floor - rank * 1e-4, "keyword") for rank, key in enumerate(by_keyword, 1)]
            if not picked and not by_keyword:
                warnings.append(f"No OWASP guidance above similarity {self.min_similarity} for: {query['label']}")

        # Ordered by each section's rank within its issue type first, then by score: every issue
        # type in the file gets its best section before any gets a second one, so the size limit
        # cuts depth, not whole issue types. A section several types share keeps its best rank.
        best: dict[tuple, tuple[int, float, str]] = {}
        for found in by_type.values():
            ranked_here = sorted({key: entry for key, *entry in sorted(found, key=lambda e: e[1])}.items(),
                                 key=lambda pair: -pair[1][0])
            for rank, (key, (score, matched_by)) in enumerate(ranked_here):
                if key not in best or (rank, -score) < (best[key][0], -best[key][1]):
                    best[key] = (rank, score, matched_by)
        ranked = sorted(best.items(), key=lambda pair: (pair[1][0], -pair[1][1]))
        return [self._section_item(key, score, matched_by) for key, (_, score, matched_by) in ranked]

    def _keyword_sections(self, query: dict, language_weights, exclude: set[tuple]) -> list[tuple]:
        """The best keyword matches for a query, weighted like the similarity ranking (section
        headings, language), skipping sections the similarity search already picked."""
        if self.fallback_results <= 0:
            return []
        if self._keyword_index is None:
            self._keyword_index = KeywordIndex([
                f"{self.chunks[indices[0]].doc_title} {self.chunks[indices[0]].section or ''} "
                + " ".join(self.chunks[i].text for i in indices) for indices in self.sections.values()])
        scores = self._keyword_index.scores(query["keyword_text"]) * self.section_weights[self._section_first]
        if isinstance(language_weights, np.ndarray):
            scores = scores * language_weights[self._section_first]
        found = []
        for unit in np.argsort(-scores):
            if scores[unit] <= 0 or len(found) >= self.fallback_results:
                break
            if self._section_keys[unit] not in exclude:
                found.append(self._section_keys[unit])
        return found

    def _section_item(self, key: tuple, score: float, matched_by: str = "similarity") -> dict:
        indices = self.sections[key]
        first = self.chunks[indices[0]]
        text = truncate("\n\n".join(self.chunks[i].text for i in indices), self.passage_max_chars)
        return item(first.source, first.doc_id, "guidance", first.doc_title, text, first.url,
                    first.license, first.fetched_at, section=first.section,
                    score=round(score, 3) if matched_by == "similarity" else None, matched_by=matched_by)
