"""Small text helpers shared by sources and retrieval."""


def squash(text: str) -> str:
    """Collapse all runs of whitespace to single spaces."""
    return " ".join(text.split())


def truncate(text: str, limit: int) -> str:
    """Cut text to at most `limit` characters, at a word boundary, marking the cut with '…'."""
    if len(text) <= limit:
        return text
    cut = text[: max(limit - 1, 0)]
    space = cut.rfind(" ")
    if space > limit * 0.6:
        cut = cut[:space]
    return cut.rstrip() + "…"
