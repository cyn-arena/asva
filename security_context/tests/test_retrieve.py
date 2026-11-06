import numpy as np
import pytest

from app import store
from app.retrieve import (FIX_WEIGHT, INTRO_WEIGHT, Retriever, cwe_compact_item, language_hint, language_of,
                          normalise_cwe, section_weight, title_match)
from conftest import load_guidance

EVAL_FINDING = {
    "finding_type": "sast", "cwe": "CWE-94", "rule_id": "javascript/CodeInjection",
    "title": "Code Injection", "summary": "User input flows into eval, where it is executed as code.",
}


@pytest.fixture
def retriever(conn, fake_embedder):
    return Retriever.from_db(conn, fake_embedder, min_similarity=0.1, top_k=3)


def guidance(retriever, conn, findings, warnings=None):
    return retriever.guidance(conn, findings, [] if warnings is None else warnings, {})


# -- helpers ------------------------------------------------------------------

@pytest.mark.parametrize("value", ["CWE-94", "cwe-94", " 94 ", 94])
def test_normalise_cwe_accepts_common_spellings(value):
    assert normalise_cwe(value) == "CWE-94"


@pytest.mark.parametrize("value", [None, "", "abc", "CWE-"])
def test_normalise_cwe_rejects_non_ids(value):
    assert normalise_cwe(value) is None


def test_language_from_rule_id_prefix():
    assert language_of({"rule_id": "javascript/CodeInjection"}) == "javascript"
    assert language_hint({"rule_id": "javascript/CodeInjection"}) == "JavaScript Node.js"


def test_explicit_language_wins_over_rule_id():
    assert language_hint({"language": "Python", "rule_id": "javascript/X"}) == "Python"


def test_no_language_without_field_or_rule_prefix():
    assert language_of({"rule_id": "SNYK-JS-QS-123"}) is None


@pytest.mark.parametrize("section, weight", [
    (None, INTRO_WEIGHT),
    ("Introduction", INTRO_WEIGHT),
    ("Cases > Context", INTRO_WEIGHT),
    ("Recommendations", INTRO_WEIGHT),
    ("Recommendations > Platform Security > Do not use dangerous functions", FIX_WEIGHT),
    ("Preventing Unvalidated Redirects and Forwards", FIX_WEIGHT),
    ("Dangerous URL Redirects > Example 1", 1.0),
])
def test_section_weight_downweights_intros_and_upweights_fixes(section, weight):
    assert section_weight(section) == weight


def test_title_match_needs_a_clear_winner():
    docs = ["A", "B", "C"]
    assert title_match(np.array([0.60, 0.50, 0.1]), docs) == "A"
    assert title_match(np.array([0.60, 0.58, 0.1]), docs) is None  # too close to call
    assert title_match(np.array([0.45, 0.10, 0.1]), docs) is None  # not similar enough


# -- guidance search ------------------------------------------------------------

def test_matching_guidance_comes_first(conn, retriever):
    items = guidance(retriever, conn, [EVAL_FINDING])
    assert items[0]["key"] == "Nodejs_Security_Cheat_Sheet"
    assert items[0]["section"] == "Do not use dangerous functions"
    assert all(i["kind"] == "guidance" and i["url"] and i["license"] and i["score"] > 0 for i in items)


def test_trace_records_the_search_query(conn, retriever):
    trace = {}
    retriever.guidance(conn, [EVAL_FINDING], [], trace)
    assert trace["queries"][0]["text"].startswith("JavaScript Node.js: how to prevent and fix Code Injection.")
    assert trace["queries"][0]["language"] == "javascript"


def test_passages_are_trimmed_to_the_passage_limit(conn, fake_embedder):
    load_guidance(conn, fake_embedder, {"Nodejs_Security_Cheat_Sheet": [
        ("Do not use dangerous functions", "Never pass user input to the JavaScript eval function. " * 40)]})
    retriever = Retriever.from_db(conn, fake_embedder, min_similarity=0.1, passage_max_chars=300)
    assert all(len(i["text"]) <= 300 for i in guidance(retriever, conn, [EVAL_FINDING]))


def test_a_split_section_is_returned_once_as_one_passage(conn, fake_embedder):
    load_guidance(conn, fake_embedder, {"Nodejs_Security_Cheat_Sheet": [
        ("Do not use dangerous functions", "Never pass user input to the JavaScript eval function: eval executes code."),
        ("Do not use dangerous functions", "Tools such as eslint can flag eval calls that execute user input as code."),
    ]})
    retriever = Retriever.from_db(conn, fake_embedder, min_similarity=0.1, top_k=5)
    matches = [i for i in guidance(retriever, conn, [EVAL_FINDING]) if i["section"] == "Do not use dangerous functions"]
    assert len(matches) == 1
    assert "Never pass user input" in matches[0]["text"] and "Tools such as eslint" in matches[0]["text"]


def test_fix_sections_outrank_intro_sections_with_the_same_text(conn, fake_embedder):
    text = "Unvalidated redirects send users to an untrusted site when user input controls the redirect target."
    load_guidance(conn, fake_embedder, {"Redirect_Guide_Cheat_Sheet": [("Introduction", text), ("Preventing redirects", text)]})
    retriever = Retriever.from_db(conn, fake_embedder, min_similarity=0.1, top_k=5)
    finding = {"title": "Open Redirect", "summary": "User input controls the redirect target, sending users to an untrusted site."}
    sections = [i["section"] for i in guidance(retriever, conn, [finding]) if i["key"] == "Redirect_Guide_Cheat_Sheet"]
    assert sections == ["Preventing redirects", "Introduction"]


def test_other_language_cheat_sheets_rank_below_same_text_elsewhere(conn, fake_embedder):
    text = "Avoid executing dynamic code built from request data; parse values instead."
    load_guidance(conn, fake_embedder, {"Java_Security_Cheat_Sheet": [("Dynamic code", text)],
                                        "Generic_Code_Cheat_Sheet": [("Dynamic code", text)]})
    retriever = Retriever.from_db(conn, fake_embedder, min_similarity=0.05, top_k=10)
    keys = [i["key"] for i in guidance(retriever, conn, [{**EVAL_FINDING, "summary": "Request data is used to build dynamic code."}])]
    assert keys.index("Generic_Code_Cheat_Sheet") < keys.index("Java_Security_Cheat_Sheet")


def test_cheat_sheet_with_matching_title_is_preferred(conn, fake_embedder):
    text = "Request forgery protections: validate the target and use an allowlist."
    load_guidance(conn, fake_embedder, {"Server_Side_Request_Forgery_Prevention_Cheat_Sheet": [("Protections", text)],
                                        "Cross-Site_Request_Forgery_Prevention_Cheat_Sheet": [("Protections", text)]})
    retriever = Retriever.from_db(conn, fake_embedder, min_similarity=0.05, top_k=10)
    finding = {"title": "Server-Side Request Forgery (SSRF)", "summary": "Request forgery via a user-supplied URL."}
    keys = [i["key"] for i in guidance(retriever, conn, [finding])]
    assert keys.index("Server_Side_Request_Forgery_Prevention_Cheat_Sheet") < \
        keys.index("Cross-Site_Request_Forgery_Prevention_Cheat_Sheet")


def test_nothing_above_threshold_is_a_warning(conn, fake_embedder):
    warnings = []
    retriever = Retriever.from_db(conn, fake_embedder, min_similarity=0.99)
    assert guidance(retriever, conn, [EVAL_FINDING], warnings) == []
    assert any("No OWASP guidance above similarity 0.99" in w for w in warnings)


def test_description_only_finding_still_gets_guidance(conn, retriever):
    finding = {"finding_type": "logic", "description": "User-controlled redirect target sends users to an untrusted site."}
    assert guidance(retriever, conn, [finding])[0]["key"] == "Unvalidated_Redirects_and_Forwards_Cheat_Sheet"


def test_empty_store_warns_to_run_a_sync(tmp_path, fake_embedder):
    conn = store.connect(tmp_path / "empty.db")
    warnings = []
    assert Retriever.from_db(conn, fake_embedder).guidance(conn, [EVAL_FINDING], warnings, {}) == []
    conn.close()
    assert any("run `python -m app.sync`" in w for w in warnings)


# -- compact CWE entry ---------------------------------------------------------------

def test_compact_cwe_lists_implementation_mitigations_first(conn):
    text = cwe_compact_item(conn, "CWE-94")["text"]
    assert text.startswith("CWE-94: Improper Control of Generation of Code ('Code Injection')")
    assert text.index("[Implementation; Input Validation]") < text.index("[Architecture and Design; Refactoring]")


def test_compact_cwe_inherits_mitigations_from_nearest_parent(conn):
    text = cwe_compact_item(conn, "CWE-95")["text"]
    assert "inherited from parent CWE-94" in text
    assert "Assume all input is malicious" in text


def test_compact_cwe_unknown_is_none(conn):
    assert cwe_compact_item(conn, "CWE-424242") is None
