"""SSRF-resistant outbound HTTP fetch helper.

Used by operator-side components that may fetch from a URL whose destination is
influenced by request-time input (for example the optional profile-sharing
endpoints). The goal is to stop attacker-reachable code from driving the
platform to read local files (``file://``), reach cloud metadata
(``169.254.169.254``), or talk to loopback/RFC1918 internal services.

Defenses applied:

* Scheme allow-list restricted to ``http``/``https``.
* A dedicated opener that registers only the HTTP/HTTPS handlers, so
  ``file://``, ``ftp://``, and ``data:`` are not reachable even if the scheme
  check were bypassed.
* Redirects are refused (a permitted public host cannot 30x the request to an
  internal target).
* Embedded credentials and non-ASCII (IDN homoglyph) hosts are rejected.
* Hostnames are resolved and every resulting address must be public; a literal
  IP is checked directly. Resolution is repeated immediately before the fetch
  and the second result must be a subset of the first to narrow the
  DNS-rebinding window.
* Response bodies are read with a hard byte cap to bound memory.

This mirrors the validation already present in
``services/vuln_llm/inference/hosted.py`` and ``intel/rotation.py`` so the
behaviour is consistent across every outbound path.
"""

from __future__ import annotations

import ipaddress
import socket
from collections.abc import Mapping
from urllib import request as urlrequest
from urllib.error import URLError
from urllib.parse import urlparse

_ALLOWED_SCHEMES = frozenset({"http", "https"})

#: Default ceiling for a fetched response body (5 MiB).
DEFAULT_MAX_RESPONSE_BYTES = 5 * 1024 * 1024


class SafeFetchError(RuntimeError):
    """Raised when a URL fails egress validation or a safe fetch fails."""


def sanitize_error(value: object, *, max_len: int = 200) -> str:
    """Strip control characters and bound the length of an error string.

    Transport error messages can echo the target URL or resolved address; keep
    them from spoofing logs or leaking internal detail back to a caller.
    """

    text = value if isinstance(value, str) else repr(value)
    text = text.replace("\r", " ").replace("\n", " ").replace("\t", " ")
    if len(text) > max_len:
        text = text[:max_len] + "...(truncated)"
    return text


def _is_blocked_ip(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_multicast
        or ip.is_reserved
        or ip.is_unspecified
    )


def _resolve_public_addresses(host: str, port: int) -> set[str]:
    """Resolve ``host`` and return its addresses iff every one is public.

    Returns an empty set if resolution fails or any address is non-public, so a
    split-horizon name that maps to both a public and a private address is
    rejected.
    """

    try:
        infos = socket.getaddrinfo(host, port, type=socket.SOCK_STREAM)
    except OSError:
        return set()
    public: set[str] = set()
    for info in infos:
        ip_raw = str(info[4][0]).strip()
        try:
            ip = ipaddress.ip_address(ip_raw)
        except ValueError:
            return set()
        if _is_blocked_ip(ip):
            return set()
        public.add(str(ip))
    return public


class _NoRedirectHandler(urlrequest.HTTPRedirectHandler):
    """Refuse every HTTP redirect so a 30x cannot pivot to an internal host."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # type: ignore[override]
        raise URLError(f"refusing redirect to {newurl!r} (code {code})")


# Opener with ONLY the http/https handlers (no FileHandler/FTPHandler/
# DataHandler) and redirects disabled. file:// and 30x-to-internal are both
# blocked here as defense in depth behind the scheme allow-list.
_OPENER = urlrequest.build_opener(
    urlrequest.HTTPHandler,
    urlrequest.HTTPSHandler,
    _NoRedirectHandler,
)


def validate_public_url(url: str, *, allow_private: bool = False) -> tuple[str, int, frozenset[str]]:
    """Validate ``url`` for safe outbound fetching.

    Returns ``(host, port, resolved_public_ips)``; ``resolved_public_ips`` is
    empty for a literal-IP host or when ``allow_private`` is set. Raises
    :class:`SafeFetchError` if the URL is not safe to fetch.
    """

    parsed = urlparse(url.strip())
    scheme = (parsed.scheme or "").lower()
    if scheme not in _ALLOWED_SCHEMES:
        raise SafeFetchError(
            f"unsupported URL scheme {scheme or '(none)'!r}; only http and https are allowed"
        )
    if parsed.username or parsed.password:
        raise SafeFetchError("URL must not contain embedded credentials")
    host = (parsed.hostname or "").strip()
    if not host:
        raise SafeFetchError("URL has no host")
    try:
        host.encode("ascii")
    except UnicodeEncodeError:
        raise SafeFetchError("non-ASCII hostname rejected (IDN homoglyph risk)") from None
    try:
        port = parsed.port or (443 if scheme == "https" else 80)
    except ValueError as exc:
        raise SafeFetchError("URL has an invalid port") from exc

    if allow_private:
        return host, port, frozenset()

    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        if _is_blocked_ip(literal):
            raise SafeFetchError(f"host {host!r} is a private, loopback, or reserved address")
        return host, port, frozenset()

    public = _resolve_public_addresses(host, port)
    if not public:
        raise SafeFetchError(
            f"host {host!r} does not resolve to an allowed public address"
        )
    return host, port, frozenset(public)


def safe_fetch(
    url: str,
    *,
    data: bytes | None = None,
    headers: Mapping[str, str] | None = None,
    method: str = "GET",
    timeout: float = 5.0,
    max_bytes: int = DEFAULT_MAX_RESPONSE_BYTES,
    allow_private: bool = False,
) -> bytes:
    """Fetch ``url`` with SSRF protections and a response byte cap.

    Returns the response body (at most ``max_bytes`` bytes). Raises
    :class:`SafeFetchError` on validation failure, transport error, or when the
    response exceeds ``max_bytes``.
    """

    host, port, first = validate_public_url(url, allow_private=allow_private)
    if first:
        # Re-resolve immediately before connecting and require the second
        # result to be a subset of the first, narrowing the DNS-rebind window.
        second = _resolve_public_addresses(host, port)
        if not second or not second.issubset(first):
            raise SafeFetchError(
                f"host {host!r} resolution changed or became non-public (possible DNS rebinding)"
            )

    req = urlrequest.Request(url.strip(), data=data, headers=dict(headers or {}), method=method)
    try:
        with _OPENER.open(req, timeout=timeout) as response:
            body = response.read(max_bytes + 1)
    except SafeFetchError:
        raise
    except Exception as exc:  # normalize and sanitize every transport error
        raise SafeFetchError(sanitize_error(str(exc))) from exc
    if len(body) > max_bytes:
        raise SafeFetchError(
            f"response exceeded the {max_bytes}-byte cap"
        )
    return body
