"""Package version helpers: semver-style numbers are enough for upgrade decisions. Up to four
numbers are read (RubyGems and Maven use versions such as 2.2.3.1 and 2.9.10.8)."""

import re

_SEMVER = re.compile(r"^v?(\d+)(?:\.(\d+))?(?:\.(\d+))?(?:\.(\d+))?")


def split_package(spec: str | None) -> tuple[str | None, str | None]:
    """"@scope/name@1.2.3" -> ("@scope/name", "1.2.3"); "name" -> ("name", None)."""
    if not spec:
        return None, None
    name, sep, version = spec.rpartition("@")
    if not sep or not name:  # no version, or only a scope "@" at position 0
        return spec, None
    return name, version


def parse(version: str | None) -> tuple[int, int, int, int] | None:
    match = _SEMVER.match(version.strip()) if version else None
    if not match:
        return None
    return tuple(int(part or 0) for part in match.groups())  # type: ignore[return-value]


def is_newer(version: str | None, than: str | None) -> bool:
    """True if `version` is a later version than `than` (False if either can't be parsed)."""
    a, b = parse(version), parse(than)
    return bool(a and b and a > b)


def is_calendar(version: str | None) -> bool:
    """A version that starts with a year, e.g. certifi 2023.7.22 or pytz 2024.1. The first
    number is a date, so a change in it says nothing about compatibility."""
    v = parse(version)
    return bool(v and 1990 <= v[0] <= 2100)


def is_breaking(current: str | None, target: str | None) -> bool:
    """A major version change; for 0.x versions a minor change also counts (semver).
    Calendar versions are never a major change by their number alone."""
    a, b = parse(current), parse(target)
    if not a or not b or b <= a or (is_calendar(current) and is_calendar(target)):
        return False
    return a[0] != b[0] or (a[0] == 0 and a[1] != b[1])


def same_major(a: str | None, b: str | None) -> bool:
    """True if moving between the two versions is not a breaking change by semver: the same
    major version (for 0.x versions, the same minor version too)."""
    x, y = parse(a), parse(b)
    if x and y and is_calendar(a) and is_calendar(b):
        return True
    return bool(x and y and x[0] == y[0] and (x[0] != 0 or x[1] == y[1]))


def newest(versions: list[str]) -> str | None:
    parsed = [(parse(v), v) for v in versions if parse(v)]
    return max(parsed)[1] if parsed else None


def major_label(version: str | None) -> str:
    v = parse(version)
    if not v:
        return version or "?"
    return f"{v[0]}.{v[1]}.x" if v[0] == 0 else f"{v[0]}.x"
