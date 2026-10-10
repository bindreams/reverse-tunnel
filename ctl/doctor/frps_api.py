# This file is part of reverse-tunnel, licensed under AGPL-3.0-or-later; see LICENSE.md.
"""frps's admin API, read the way doctor needs it: authenticated, filtered to what is online, and paged to the end.

Measured on frp 0.71.0, and what the shapes below rest on: the admin password goes with an empty username; `status` and
`user` are server-side filters; `total` is recomputed after filtering on every request, so it moves between pages; and a
label collision shows only in `/api/v2/clients`, where `/api/v2/proxies` lists the winner alone.

`total` can fall or grow while pages are read, so paging has no page size and no page cap: it stops when it has seen
`total` entries or when a page adds nothing new. The second is indistinguishable from a read that was cut short, so
`Page.complete` says which it was, and a consumer must treat an incomplete page as a failure.

Residual: frps pages by offset, so a fleet that changes between two page requests can shift an entry across the boundary
(read twice, deduplicated here, or not at all, reported as incomplete only if `total` shows it). A listing of the whole
fleet is therefore informational; a verdict about one label asks for `user=<label>`, a result set of one or two entries
that fits in a single page.
"""

import dataclasses
from collections.abc import Callable
from typing import Generic, TypeVar

import httpx

T = TypeVar("T")  # yapf cannot parse the PEP 695 `class Page[T]` spelling
ONLINE = "online"
# external-bound: frps's admin API answering on the bridge's own loopback; a human reads the failure.
TIMEOUT = httpx.Timeout(10.0)


class FrpsApiError(Exception):
    """The admin API could not be read, or answered with something that is not its documented shape."""


class FrpsUnreachable(FrpsApiError):
    """Nothing answered: the connection was refused, reset, or timed out. Distinct from an answer that is wrong."""


@dataclasses.dataclass(frozen=True)
class Proxy:
    name: str
    user: str
    client_id: str
    phase: str


@dataclasses.dataclass(frozen=True)
class Client:
    key: str
    user: str
    client_id: str
    online: bool


@dataclasses.dataclass(frozen=True)
class Page(Generic[T]):
    items: list[T]
    complete: bool  # False when paging stopped short of the last-seen total


# Shapes ===============================================================================================================


def _text(item: dict, *keys: str) -> str:
    for key in keys:
        value = item.get(key)
        if isinstance(value, str):
            return value
    return ""


def _proxy(item: dict) -> Proxy:
    name = item.get("name")
    status = item.get("status")
    phase = status.get("phase") if isinstance(status, dict) else None
    if not isinstance(name, str) or not name:
        raise FrpsApiError(f"a proxy entry has no name: {item!r}")
    if not isinstance(phase, str):
        raise FrpsApiError(f"proxy {name} has no status.phase")
    return Proxy(name, _text(item, "user"), _text(item, "clientID", "client_id"), phase)


def _client(item: dict) -> Client:
    key = item.get("key")
    online = item.get("online")
    if not isinstance(key, str) or not key:
        raise FrpsApiError(f"a client entry has no key: {item!r}")
    if not isinstance(online, bool):
        raise FrpsApiError(f"client {key} has no boolean online flag")
    return Client(key, _text(item, "user"), _text(item, "clientID", "client_id"), online)


# Reading ==============================================================================================================


def _no_answer(exc: httpx.HTTPError) -> bool:
    """Whether nothing answered: the connection was refused, reset or timed out, or closed before any response.

    A peer that answers with something else than HTTP, a body that cannot be decoded, or a redirect loop did answer, so
    those are failures of what was said, not of reaching it.
    """
    if isinstance(exc, (httpx.NetworkError, httpx.TimeoutException)):
        return True
    return isinstance(exc, httpx.RemoteProtocolError) and "without sending a response" in str(exc)


def _get(client: httpx.Client, base_url: str, path: str, params: dict[str, str]) -> dict:
    url = f"{base_url.rstrip('/')}{path}"
    try:
        response = client.get(url, params=params)
    except httpx.HTTPError as exc:
        if _no_answer(exc):
            raise FrpsUnreachable(f"cannot reach the frps admin API at {base_url}: {exc}") from exc
        raise FrpsApiError(f"the frps admin API at {base_url}{path} gave an answer that cannot be read: {exc}") from exc
    if response.status_code == 401:
        raise FrpsApiError(
            f"the frps admin API at {base_url} rejected RT_ADMIN_PASSWORD (it is sent with an empty username)"
        )
    if response.status_code != 200:
        raise FrpsApiError(f"the frps admin API at {base_url}{path} answered HTTP {response.status_code}")
    try:
        document = response.json()
    except ValueError:
        raise FrpsApiError(f"{base_url}{path} did not answer JSON") from None
    if not isinstance(document, dict) or document.get("code") != 200 or not isinstance(document.get("data"), dict):
        raise FrpsApiError(f"{base_url}{path} answered something other than the v2 envelope")
    data = document["data"]
    if not isinstance(data.get("total"), int) or isinstance(
        data["total"], bool
    ) or not isinstance(data.get("items"), list) or not all(isinstance(item, dict) for item in data["items"]):
        raise FrpsApiError(f"{base_url}{path} answered a page without an integer total and a list of entries")
    return data


def _list(
    base_url: str, password: str, path: str, parse: Callable[[dict], T], identify: Callable[[T], str], user: str | None,
    transport: httpx.BaseTransport | None
) -> Page[T]:
    query = {"status": ONLINE} | ({"user": user} if user is not None else {})
    seen: dict[str, T] = {}
    total = 0
    with httpx.Client(auth=httpx.BasicAuth("", password), timeout=TIMEOUT, transport=transport) as client:
        number = 1
        while True:
            data = _get(client, base_url, path, query | {"page": str(number)})
            total = data["total"]
            added = 0
            for item in map(parse, data["items"]):
                if identify(item) not in seen:
                    seen[identify(item)] = item
                    added += 1
            if added == 0 or len(seen) >= total:
                break
            number += 1
    return Page(list(seen.values()), complete=len(seen) >= total)


def list_proxies(
    base_url: str,
    password: str,
    *,
    user: str | None = None,
    transport: httpx.BaseTransport | None = None
) -> Page[Proxy]:
    """The proxies frps reports online (for `user`, if given). Offline records are retained by frps, hence the filter."""
    return _list(base_url, password, "/api/v2/proxies", _proxy, lambda proxy: proxy.name, user, transport)


def list_clients(
    base_url: str,
    password: str,
    *,
    user: str | None = None,
    transport: httpx.BaseTransport | None = None
) -> Page[Client]:
    """The clients frps reports online (for `user`, if given). This, not the proxies, is where a collision shows."""
    return _list(base_url, password, "/api/v2/clients", _client, lambda client: client.key, user, transport)
