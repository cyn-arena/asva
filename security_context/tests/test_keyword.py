"""Keyword (BM25) search, and its use as a fallback when the similarity search is unsure."""

import pytest

from app.keyword import KeywordIndex, tokenize
from app.retrieve import Retriever
from conftest import load_guidance

SECTIONS = [
    "Secrets Management: keep passwords and API keys in a vault or environment variable, never hardcoded in code.",
    "Brute force: lock accounts after repeated failed password attempts and add rate limiting.",
    "Transport security: use TLS certificates from a trusted authority.",
]


def test_tokenize_lowercases_keeps_identifiers_and_drops_stopwords():
    assert tokenize("Use of the X-Powered-By header in Node.js") == ["x-powered-by", "header", "node.js"]


def test_keyword_scores_rank_the_section_sharing_rare_words_first():
    scores = KeywordIndex(SECTIONS).scores("Use of hardcoded passwords in code, with a password")
    assert scores.argmax() == 0 and scores[0] > scores[1] > scores[2] == 0


def test_keyword_matching_is_on_exact_words():
    # no stemming: light stemming was measured and did not help (see README, keyword fallback)
    scores = KeywordIndex(SECTIONS).scores("passwords")
    assert scores[0] > 0 and scores[1] == 0  # section 2 says "password"


def test_keyword_scores_are_zero_without_a_shared_word():
    assert not KeywordIndex(SECTIONS).scores("cross-site scripting").any()


def test_keyword_index_handles_no_texts():
    assert KeywordIndex([]).scores("anything").shape == (0,)


# -- the fallback in the retriever ---------------------------------------------------------------

FINDING = {"finding_type": "sast", "rule_id": "javascript/NoHardcodedPasswords", "title": "Use of Hardcoded Passwords",
           "summary": "Do not hardcode passwords in code."}
DOCS = {
    "Authentication_Cheat_Sheet": [("Protect against brute force", "Lock accounts after repeated failed password attempts."),
                                   ("Password strength", "Require long passwords and check them against breached password lists.")],
    "Secrets_Management_Cheat_Sheet": [("Where to keep secrets", "Keep API keys in a vault. Hardcoded credentials in code leak through the repository.")],
}


@pytest.fixture
def retriever(conn, fake_embedder):
    load_guidance(conn, fake_embedder, DOCS)
    # every similarity score of the fake embedder is "low", so the fallback always applies
    return Retriever.from_db(conn, fake_embedder, min_similarity=0.01, top_k=2, fallback_below=2.0, fallback_results=1)


def run(retriever, conn, **kwargs):
    trace = {}
    return retriever.guidance(conn, [FINDING], [], trace, **kwargs), trace["queries"][0]


def test_low_confidence_swaps_the_lowest_similarity_match_for_a_keyword_match(retriever, conn):
    items, query = run(retriever, conn)
    assert [i["matched_by"] for i in items] == ["similarity", "keyword"]
    assert items[0]["score"] is not None and items[1]["score"] is None
    assert query["keyword_fallback"] and query["best_similarity"] < 2.0
    assert len(items) == 2  # the response does not grow


def test_keyword_match_is_never_a_section_the_similarity_search_already_returned(retriever, conn):
    items, _ = run(retriever, conn)
    assert len({(i["key"], i["section"]) for i in items}) == len(items)


def test_fallback_can_be_switched_off_per_request(retriever, conn):
    items, query = run(retriever, conn, keyword_fallback=False)
    assert all(i["matched_by"] == "similarity" for i in items) and query["keyword_fallback"] == []


def test_confident_similarity_results_are_left_alone(conn, fake_embedder):
    load_guidance(conn, fake_embedder, DOCS)
    confident = Retriever.from_db(conn, fake_embedder, min_similarity=0.01, top_k=2, fallback_below=0.0, fallback_results=1)
    items, query = run(confident, conn)
    assert all(i["matched_by"] == "similarity" for i in items) and query["keyword_fallback"] == []


def test_no_fallback_when_nothing_is_similar_enough(conn, fake_embedder):
    # with no similarity match at all there is nothing to supplement: the caller uses the CWE entry
    load_guidance(conn, fake_embedder, DOCS)
    strict = Retriever.from_db(conn, fake_embedder, min_similarity=0.99, fallback_below=2.0, fallback_results=2)
    warnings = []
    assert strict.guidance(conn, [FINDING], warnings, {}) == []
    assert any("No OWASP guidance" in w for w in warnings)
