import httpx
import pytest

from app import net, versions


@pytest.mark.parametrize("spec, expected", [
    ("marked@0.3.5", ("marked", "0.3.5")),
    ("@scope/pkg@1.2.3", ("@scope/pkg", "1.2.3")),
    ("glibc/libc-bin@2.23-0ubuntu11.3", ("glibc/libc-bin", "2.23-0ubuntu11.3")),
    ("express", ("express", None)),
    (None, (None, None)),
])
def test_split_package(spec, expected):
    assert versions.split_package(spec) == expected


@pytest.mark.parametrize("current, target, breaking", [
    ("2.2.36", "3.1.13", True),
    ("0.15.3", "2.0.0", True),
    ("0.3.5", "0.4.0", True),     # 0.x minor change is breaking in semver
    ("0.3.5", "0.3.18", False),
    ("1.18.3", "1.20.4", False),
    ("2.0.0", "2.0.0", False),
    (None, "3.0.0", False),
])
def test_is_breaking(current, target, breaking):
    assert versions.is_breaking(current, target) is breaking


def test_newest_and_major_label():
    assert versions.newest(["3.1.3", "3.1.13", "2.9.9"]) == "3.1.13"
    assert versions.major_label("3.1.13") == "3.x"
    assert versions.major_label("0.3.5") == "0.3.x"


def test_is_newer_is_safe_with_unparseable_versions():
    assert versions.is_newer("4.0.10", "0.3.18")
    assert not versions.is_newer("garbage", "1.0.0")


def test_request_retries_5xx_then_succeeds():
    responses = iter([httpx.Response(503), httpx.Response(502), httpx.Response(200, json={"ok": True})])
    with net.make_client(transport=httpx.MockTransport(lambda r: next(responses))) as client:
        assert net.request(client, "GET", "https://example.test/x").json() == {"ok": True}


def test_request_gives_up_after_retries():
    with net.make_client(transport=httpx.MockTransport(lambda r: httpx.Response(503))) as client:
        with pytest.raises(net.LookupFailed, match="HTTP 503"):
            net.request(client, "GET", "https://example.test/x", retries=2)


def test_request_does_not_retry_client_errors_but_can_accept_them():
    calls = []

    def handler(request):
        calls.append(request)
        return httpx.Response(404)

    with net.make_client(transport=httpx.MockTransport(handler)) as client:
        assert net.request(client, "GET", "https://example.test/x", ok_statuses=(404,)).status_code == 404
        with pytest.raises(net.LookupFailed):
            net.request(client, "GET", "https://example.test/x")
    assert len(calls) == 2


def test_rate_limiter_waits_when_the_window_is_full(monkeypatch):
    clock = {"now": 0.0}
    monkeypatch.setattr(net.time, "monotonic", lambda: clock["now"])
    monkeypatch.setattr(net.time, "sleep", lambda s: clock.__setitem__("now", clock["now"] + s))
    limiter = net.RateLimiter(2, 10)
    for _ in range(3):
        limiter.wait()
    assert clock["now"] >= 10  # the third call had to wait for the window


@pytest.mark.parametrize("a, b, same", [
    ("2.2.36", "2.9.0", True), ("2.2.36", "3.1.13", False), ("0.3.5", "0.3.18", True), ("0.3.5", "0.4.0", False),
    ("4.4", "4.8", True), ("4.4", "8.0", False), ("1.0.0", None, False), ("latest", "1.0.0", False)])
def test_same_major_follows_semver(a, b, same):
    assert versions.same_major(a, b) is same


@pytest.mark.parametrize("version, calendar", [("2023.7.22", True), ("2022.12.7", True), ("4.2.28", False), ("65.13.0", False), (None, False)])
def test_is_calendar_spots_versions_that_start_with_a_year(version, calendar):
    assert versions.is_calendar(version) is calendar


def test_a_calendar_version_change_is_not_a_major_change():
    assert versions.is_breaking("2022.12.7", "2023.7.22") is False
    assert versions.same_major("2022.12.7", "2024.7.4") is True
    assert versions.is_breaking("1.26.9", "2023.1.0") is True   # only when both are calendar versions
