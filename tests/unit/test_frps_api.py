"""frps's admin API as doctor reads it: authentication, filters, paging and the signal that a page is incomplete."""

import base64
import json

import httpx
import pytest

from ctl.doctor import frps_api
from ctl.doctor.frps_api import Client, FrpsApiError, Proxy

BASE = "http://127.0.0.1:7500"
PASSWORD = "correct-horse-battery_staple"


def proxy(name: str = "alpha.ssh", user: str = "alpha", phase: str = "online", client_id: str = "c-alpha") -> dict:
    return {"name": name, "user": user, "clientID": client_id, "status": {"phase": phase}}


def client(key: str = "alpha", user: str = "alpha", client_id: str = "c-alpha", online: bool = True) -> dict:
    return {"key": key, "user": user, "clientID": client_id, "online": online}


def envelope(items: list[dict], total: int | None = None) -> dict:
    return {"code": 200, "data": {"total": len(items) if total is None else total, "items": items}}


def serving(*pages: dict, requests: list[httpx.Request] | None = None) -> httpx.MockTransport:
    """Answer page N with `pages[N - 1]`; a page past the last is an error, so a runaway loop fails the test."""

    def handler(request: httpx.Request) -> httpx.Response:
        if requests is not None:
            requests.append(request)
        number = int(request.url.params.get("page", "1"))
        assert number <= len(pages), f"asked for page {number} of {len(pages)}"
        return httpx.Response(200, json=pages[number - 1])

    return httpx.MockTransport(handler)


# Authentication =======================================================================================================


def test_authenticates_with_an_empty_username():
    seen: list[httpx.Request] = []
    frps_api.list_proxies(BASE, PASSWORD, transport=serving(envelope([]), requests=seen))
    scheme, _, encoded = seen[0].headers["authorization"].partition(" ")
    assert scheme == "Basic"
    assert base64.b64decode(encoded).decode() == f":{PASSWORD}"


def test_a_rejected_password_is_an_error_naming_the_empty_username():

    def deny(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text="Unauthorized")

    with pytest.raises(FrpsApiError, match="empty username"):
        frps_api.list_proxies(BASE, PASSWORD, transport=httpx.MockTransport(deny))


# Paging ===============================================================================================================


def test_pages_until_total_is_reached():
    first = envelope([proxy("a.ssh", "a"), proxy("b.ssh", "b")], total=3)
    second = envelope([proxy("c.ssh", "c")], total=3)
    page = frps_api.list_proxies(BASE, PASSWORD, transport=serving(first, second))
    assert [p.name for p in page.items] == ["a.ssh", "b.ssh", "c.ssh"]
    assert page.complete is True


def test_stops_on_an_empty_page_even_when_total_still_exceeds_the_count():
    first = envelope([proxy("a.ssh", "a")], total=5)
    page = frps_api.list_proxies(BASE, PASSWORD, transport=serving(first, envelope([], total=5)))
    assert [p.name for p in page.items] == ["a.ssh"]


def test_an_empty_page_short_of_total_reports_complete_false():
    first = envelope([proxy("a.ssh", "a")], total=5)
    page = frps_api.list_proxies(BASE, PASSWORD, transport=serving(first, envelope([], total=5)))
    assert page.complete is False


def test_a_server_that_ignores_the_page_number_ends_the_loop_incomplete():
    only = envelope([proxy("a.ssh", "a")], total=2)
    page = frps_api.list_proxies(BASE, PASSWORD, transport=serving(only, only))
    assert [p.name for p in page.items] == ["a.ssh"]
    assert page.complete is False


def test_a_total_that_shrinks_between_requests_does_not_loop_on_or_mislabel_the_result():
    first = envelope([proxy("a.ssh", "a"), proxy("b.ssh", "b")], total=3)
    second = envelope([], total=2)  # a proxy went away in between: total fell to what was already seen
    page = frps_api.list_proxies(BASE, PASSWORD, transport=serving(first, second))
    assert [p.name for p in page.items] == ["a.ssh", "b.ssh"]
    assert page.complete is True


def test_no_entries_at_all_is_a_complete_empty_page():
    page = frps_api.list_proxies(BASE, PASSWORD, transport=serving(envelope([])))
    assert page.items == [] and page.complete is True


def test_an_item_seen_on_two_pages_is_counted_once():
    first = envelope([proxy("a.ssh", "a"), proxy("b.ssh", "b")], total=3)
    second = envelope([proxy("b.ssh", "b"), proxy("c.ssh", "c")], total=3)
    page = frps_api.list_proxies(BASE, PASSWORD, transport=serving(first, second))
    assert [p.name for p in page.items] == ["a.ssh", "b.ssh", "c.ssh"]
    assert page.complete is True


# Filters ==============================================================================================================


@pytest.mark.parametrize("lister", [frps_api.list_proxies, frps_api.list_clients])
def test_passes_status_online_and_the_user_filter(lister):
    seen: list[httpx.Request] = []
    lister(BASE, PASSWORD, user="alpha", transport=serving(envelope([]), requests=seen))
    params = seen[0].url.params
    assert params["status"] == "online" and params["user"] == "alpha"


@pytest.mark.parametrize("lister", [frps_api.list_proxies, frps_api.list_clients])
def test_without_a_user_the_query_carries_no_user_filter(lister):
    seen: list[httpx.Request] = []
    lister(BASE, PASSWORD, transport=serving(envelope([]), requests=seen))
    assert "user" not in seen[0].url.params and seen[0].url.params["status"] == "online"


def test_proxies_and_clients_are_read_from_their_own_v2_endpoints():
    seen: list[httpx.Request] = []
    frps_api.list_proxies(BASE, PASSWORD, transport=serving(envelope([]), requests=seen))
    frps_api.list_clients(BASE, PASSWORD, transport=serving(envelope([]), requests=seen))
    assert [r.url.path for r in seen] == ["/api/v2/proxies", "/api/v2/clients"]


# Parsing ==============================================================================================================


def test_parses_the_v2_envelope():
    page = frps_api.list_proxies(
        BASE, PASSWORD, transport=serving(envelope([proxy("alpha.ssh", "alpha", "offline", "c-9")]))
    )
    assert page.items == [Proxy(name="alpha.ssh", user="alpha", client_id="c-9", phase="offline")]


def test_parses_clients():
    page = frps_api.list_clients(
        BASE,
        PASSWORD,
        transport=serving(envelope([client("k1", "alpha", "c-1", True),
                                    client("k2", "alpha", "c-2", False)]))
    )
    assert page.items == [Client("k1", "alpha", "c-1", True), Client("k2", "alpha", "c-2", False)]


def test_a_missing_user_is_the_empty_string():
    item = {"name": "x.ssh", "clientID": "c", "status": {"phase": "online"}}
    assert frps_api.list_proxies(BASE, PASSWORD, transport=serving(envelope([item]))).items[0].user == ""


# Malformed answers ====================================================================================================


def answering(response: httpx.Response) -> httpx.MockTransport:
    return httpx.MockTransport(lambda request: response)


@pytest.mark.parametrize(
    "response",
    [
        httpx.Response(200, text="<html>not json</html>"),
        httpx.Response(200, json=[1, 2]),
        httpx.Response(200, json={"code": 500, "msg": "boom"}),
        httpx.Response(200, json={"code": 200}),
        httpx.Response(200, json={"code": 200, "data": {"total": "many", "items": []}}),
        httpx.Response(200, json={"code": 200, "data": {"total": 1, "items": "x"}}),
        httpx.Response(200, json={"code": 200, "data": {"total": 1, "items": [{"user": "alpha"}]}}),
        httpx.Response(200, json={"code": 200, "data": {"total": 1, "items": [{"name": "x", "status": {}}]}}),
        httpx.Response(500, text="oops"),
    ],
    ids=["html", "list", "code", "no-data", "total", "items", "no-name", "no-phase", "http-500"],
)
def test_a_malformed_answer_is_an_error_not_an_empty_result(response):
    with pytest.raises(FrpsApiError):
        frps_api.list_proxies(BASE, PASSWORD, transport=answering(response))


def test_a_client_without_an_online_flag_is_an_error():
    item = {"key": "k", "user": "alpha"}
    with pytest.raises(FrpsApiError, match="online"):
        frps_api.list_clients(BASE, PASSWORD, transport=serving(envelope([item])))


def test_an_unreachable_admin_api_is_an_error_naming_the_url():

    def refuse(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("connection refused", request=request)

    with pytest.raises(FrpsApiError, match="127.0.0.1:7500"):
        frps_api.list_proxies(BASE, PASSWORD, transport=httpx.MockTransport(refuse))


def test_the_error_never_repeats_the_password():

    def deny(request: httpx.Request) -> httpx.Response:
        return httpx.Response(401, text=json.dumps({"echo": PASSWORD}))

    with pytest.raises(FrpsApiError) as raised:
        frps_api.list_proxies(BASE, PASSWORD, transport=httpx.MockTransport(deny))
    assert PASSWORD not in str(raised.value)


# Unreachable versus wrong =============================================================================================


def raising(error_for):

    def handler(request: httpx.Request) -> httpx.Response:
        raise error_for(request)

    return httpx.MockTransport(handler)


@pytest.mark.parametrize(
    "error",
    [
        lambda r: httpx.ConnectError("connection refused", request=r),
        lambda r: httpx.ConnectTimeout("timed out", request=r),
        lambda r: httpx.ReadError("connection reset by peer", request=r),
        lambda r: httpx.ReadTimeout("timed out", request=r),
        lambda r: httpx.RemoteProtocolError("Server disconnected without sending a response.", request=r),
    ],
    ids=["connect", "connect-timeout", "read-error", "read-timeout", "closed-before-any-response"],
)
def test_no_answer_at_all_is_unreachable(error):
    with pytest.raises(frps_api.FrpsUnreachable):
        frps_api.list_proxies(BASE, PASSWORD, transport=raising(error))


@pytest.mark.parametrize(
    "error",
    [
        lambda r: httpx.RemoteProtocolError("illegal status line: bad HTTP/1.1 request", request=r),
        lambda r: httpx.DecodingError("invalid gzip data", request=r),
        lambda r: httpx.TooManyRedirects("too many", request=r),
        lambda r: httpx.UnsupportedProtocol("unknown scheme", request=r),
    ],
    ids=["not-http", "decoding", "redirects", "protocol"],
)
def test_an_answer_that_is_wrong_is_a_real_failure_not_unreachable(error):
    with pytest.raises(FrpsApiError) as raised:
        frps_api.list_proxies(BASE, PASSWORD, transport=raising(error))
    assert not isinstance(raised.value, frps_api.FrpsUnreachable)
    assert "127.0.0.1:7500" in str(raised.value)
