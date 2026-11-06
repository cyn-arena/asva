"""PR-comment delivery is independent of candidate validation results."""

import json
import sys

import pytest

from gitops import post_pr_check_comment as reporter
from gitops.git_gh_ops import GitOpError

pytestmark = pytest.mark.unit


@pytest.mark.parametrize("failing,delivery_error,draft_error", [
    (False, False, False), (True, False, False),
    (True, True, False), (True, False, True),
])
def test_delivery_output_does_not_mask_check_or_posting_failures(
        tmp_path, monkeypatch, failing, delivery_error, draft_error):
    smoke = tmp_path / "smoke.xml"
    smoke.write_text('<testsuite><testcase name="login"/></testsuite>')
    matched = tmp_path / "matched.json"
    matched.write_text(json.dumps({"changed_files": [], "matched_tests": []}))
    output = tmp_path / "outputs"
    monkeypatch.setenv("GITHUB_OUTPUT", str(output))
    monkeypatch.setattr(sys, "argv", ["report", "--smoke-xml", str(smoke),
        "--matched-json", str(matched), "--pr", "258", "--sha", "abc",
        "--app-started", "false" if failing else "true", "--execute"])
    def draft(*args, **kwargs):
        if draft_error:
            raise GitOpError("Draft conversion failed")
    def post(*args, **kwargs):
        if delivery_error:
            raise GitOpError("Comment rejected")
        return "https://github.test/comment/1"
    monkeypatch.setattr(reporter, "convert_pr_to_draft", draft)
    monkeypatch.setattr(reporter, "comment_on_pr", post)
    if delivery_error:
        with pytest.raises(GitOpError, match="Comment rejected"):
            reporter.main()
        assert not output.exists()
    elif failing:
        with pytest.raises(SystemExit) as error:
            reporter.main()
        assert error.value.code == 1
        assert output.read_text() == "comment_result=success\n"
    else:
        reporter.main()
        assert output.read_text() == "comment_result=success\n"
