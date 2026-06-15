"""Fetch a user-supplied URL on the server without opening an SSRF hole.

The moment a server feature accepts a URL from a user and fetches it
(logo grabbers, link previews, webhook testers, RSS imports, avatar-from-URL),
it becomes a way to make your own server send requests. Point it at
``http://169.254.169.254/`` on a cloud box and it reads your instance
credentials. Point it at ``http://localhost:6379`` and it talks to your Redis.
That class of bug is called SSRF (server-side request forgery), and it is one
of the most common ways internal systems get reached from the outside.

This module is the guard I put in front of every such fetch. It is small on
purpose. The rules are:

1. Scheme allowlist: http and https only. Kills file://, gopher://, data://.
2. Resolve EVERY IP the hostname maps to and refuse if ANY of them is not a
   public, globally-routable address. Using ``ipaddress.is_global`` instead of
   a hand-written private-range list also catches carrier-grade NAT, 0.0.0.0/8,
   and reserved ranges, with no list to maintain.
3. Follow redirects by hand and re-validate every single hop. An open redirect
   that bounces to an internal IP is the classic bypass of a one-shot check.
4. Cap the timeout, the response size, and the number of redirect hops.

Accepted residual risk (documented on purpose): validation resolves the host,
then the HTTP client resolves it again at connect time, so a TTL=0 DNS-rebind
can in theory pass validation and then connect to a private IP. That matters
only if the response body is returned to the caller. If you only surface, say,
a brand color or a final URL, a successful internal hit is a near-empty oracle.
If you ever return the full body to untrusted callers, pin the validated IP and
connect to it directly. See ``README.md`` for the longer version.

No dependencies beyond ``requests`` at fetch time. The validation logic and the
whole test suite run with only the standard library.
"""

from __future__ import annotations

import ipaddress
import socket
from urllib.parse import urljoin, urlsplit

__all__ = ["SafeURLError", "validate_url", "fetch"]

ALLOWED_SCHEMES = ("http", "https")

DEFAULT_TIMEOUT = 5.0          # seconds, per hop
DEFAULT_MAX_BYTES = 5 * 1024 * 1024   # 5 MiB
DEFAULT_MAX_REDIRECTS = 5
_REDIRECT_STATUSES = (301, 302, 303, 307, 308)
_CHUNK = 8192


class SafeURLError(Exception):
    """Raised when a URL is unsafe to fetch, or a fetch exceeds its limits.

    Always fail closed: anything we cannot prove safe raises this.
    """


def _ip_is_blocked(ip_text: str) -> bool:
    """True if this IP is anything other than a public, global address.

    Unparseable input is blocked (fail closed). IPv4-mapped IPv6 addresses
    (``::ffff:127.0.0.1``) are unwrapped first so the embedded v4 address is
    judged on its own merits.
    """
    try:
        addr = ipaddress.ip_address(ip_text)
    except ValueError:
        return True
    if addr.version == 6 and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped
    return not addr.is_global


def _resolve(host: str) -> list[str]:
    """Return every IP a hostname resolves to, or raise SafeURLError.

    Checking *all* records (not just the first) defeats multi-record DNS
    tricks where one answer is public and another is internal.
    """
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise SafeURLError(f"cannot resolve host: {host!r}") from exc
    ips = {info[4][0] for info in infos}
    if not ips:
        raise SafeURLError(f"no addresses for host: {host!r}")
    return sorted(ips)


def _host_is_safe(host: str) -> bool:
    """True only if the host resolves and EVERY resolved IP is global."""
    if not host:
        return False
    return all(not _ip_is_blocked(ip) for ip in _resolve(host))


def validate_url(url: str) -> str:
    """Validate a URL and return it, or raise SafeURLError.

    Enforces the scheme allowlist and the resolve-all-IPs rule. Letting
    ``getaddrinfo`` canonicalize the host means decimal/octal/hex IP literals
    (``http://2130706433/`` is 127.0.0.1) still resolve and then get blocked.
    """
    parts = urlsplit(url)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise SafeURLError(f"scheme not allowed: {parts.scheme!r}")
    host = parts.hostname
    if host is None:
        raise SafeURLError("URL has no host")
    if not _host_is_safe(host):
        raise SafeURLError(f"host resolves to a non-public address: {host!r}")
    return url


def _raw_get(url: str, timeout: float):
    """Issue one GET with redirects disabled. Lazy-imports requests.

    Isolated so the rest of the module (and the entire test suite) needs no
    network and no third-party package. Tests monkeypatch this function.
    Returns a streaming response with ``status_code``, ``headers``,
    ``iter_content``, and ``close``.
    """
    import requests  # noqa: PLC0415 — lazy on purpose

    return requests.get(
        url, allow_redirects=False, timeout=timeout, stream=True
    )


def _read_capped(response, max_bytes: int) -> bytes:
    """Read a streaming response body, aborting if it exceeds max_bytes.

    A Content-Length header is a hint, not a promise, so the real enforcement
    is counting bytes as they arrive.
    """
    body = bytearray()
    try:
        for chunk in response.iter_content(_CHUNK):
            if not chunk:
                continue
            body.extend(chunk)
            if len(body) > max_bytes:
                raise SafeURLError(f"response exceeded {max_bytes} bytes")
    finally:
        close = getattr(response, "close", None)
        if callable(close):
            close()
    return bytes(body)


def fetch(
    url: str,
    *,
    timeout: float = DEFAULT_TIMEOUT,
    max_bytes: int = DEFAULT_MAX_BYTES,
    max_redirects: int = DEFAULT_MAX_REDIRECTS,
) -> bytes:
    """Safely fetch a user-supplied URL and return its body as bytes.

    Validates the URL, then follows redirects by hand, re-validating the
    destination of every hop before connecting to it. Raises SafeURLError on
    any unsafe URL, unsafe redirect, or exceeded limit.
    """
    current = validate_url(url)
    for _ in range(max_redirects + 1):
        response = _raw_get(current, timeout)
        status = response.status_code
        if status in _REDIRECT_STATUSES:
            location = response.headers.get("Location")
            close = getattr(response, "close", None)
            if callable(close):
                close()
            if not location:
                raise SafeURLError(f"redirect {status} with no Location header")
            # Resolve relative redirects against the URL that issued them,
            # then re-run the full validation on the absolute result.
            current = validate_url(urljoin(current, location))
            continue
        return _read_capped(response, max_bytes)
    raise SafeURLError(f"too many redirects (> {max_redirects})")
