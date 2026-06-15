"""Tests for safe_url_fetch. No network: DNS and HTTP are monkeypatched.

Run with: python3 test_safe_url_fetch.py  (or: python3 -m unittest)
"""

import socket
import unittest

import safe_url_fetch as suf


def fake_dns(mapping):
    """Build a getaddrinfo replacement from {hostname: [ip, ...]}.

    Unknown hosts raise gaierror, like the real resolver.
    """
    def _getaddrinfo(host, *args, **kwargs):
        if host not in mapping:
            raise socket.gaierror(f"unknown host {host}")
        out = []
        for ip in mapping[host]:
            family = socket.AF_INET6 if ":" in ip else socket.AF_INET
            sockaddr = (ip, 0, 0, 0) if family == socket.AF_INET6 else (ip, 0)
            out.append((family, socket.SOCK_STREAM, 0, "", sockaddr))
        return out
    return _getaddrinfo


class FakeResponse:
    """Minimal stand-in for a streaming requests.Response."""

    def __init__(self, status_code=200, headers=None, body=b"", chunks=None):
        self.status_code = status_code
        self.headers = headers or {}
        self._chunks = chunks if chunks is not None else [body]
        self.closed = False

    def iter_content(self, chunk_size):
        for chunk in self._chunks:
            yield chunk

    def close(self):
        self.closed = True


class FakeHTTP:
    """Replacement for _raw_get that serves scripted responses per-URL.

    Records every URL it was asked for, so tests can assert the redirect
    chain actually re-fetched each hop.
    """

    def __init__(self, routes):
        self.routes = routes
        self.requested = []

    def __call__(self, url, timeout):
        self.requested.append(url)
        resp = self.routes[url]
        return resp() if callable(resp) else resp


# ── IP classification ────────────────────────────────────────────────────

class TestIPBlocking(unittest.TestCase):
    def test_public_ips_allowed(self):
        for ip in ("8.8.8.8", "1.1.1.1", "93.184.216.34"):
            self.assertFalse(suf._ip_is_blocked(ip), ip)

    def test_private_and_special_ips_blocked(self):
        for ip in (
            "127.0.0.1",         # loopback
            "10.0.0.5",          # private
            "192.168.1.1",       # private
            "172.16.0.1",        # private
            "169.254.169.254",   # link-local / cloud metadata
            "100.64.0.1",        # carrier-grade NAT
            "0.0.0.0",           # this-network
            "::1",               # ipv6 loopback
            "fd00::1",           # ipv6 unique-local
        ):
            self.assertTrue(suf._ip_is_blocked(ip), ip)

    def test_ipv4_mapped_ipv6_loopback_blocked(self):
        self.assertTrue(suf._ip_is_blocked("::ffff:127.0.0.1"))

    def test_garbage_fails_closed(self):
        self.assertTrue(suf._ip_is_blocked("not-an-ip"))
        self.assertTrue(suf._ip_is_blocked(""))


# ── URL validation ───────────────────────────────────────────────────────

class TestValidateURL(unittest.TestCase):
    def setUp(self):
        self._orig = socket.getaddrinfo
        socket.getaddrinfo = fake_dns({
            "example.com": ["93.184.216.34"],
            "internal.local": ["10.0.0.5"],
            "split-horizon.com": ["93.184.216.34", "10.0.0.5"],
        })
        self.addCleanup(lambda: setattr(socket, "getaddrinfo", self._orig))

    def test_public_url_passes(self):
        self.assertEqual(
            suf.validate_url("https://example.com/logo.png"),
            "https://example.com/logo.png",
        )

    def test_non_http_schemes_blocked(self):
        for url in (
            "file:///etc/passwd",
            "gopher://example.com/",
            "data:text/html,hi",
            "ftp://example.com/x",
        ):
            with self.assertRaises(suf.SafeURLError):
                suf.validate_url(url)

    def test_internal_host_blocked(self):
        with self.assertRaises(suf.SafeURLError):
            suf.validate_url("http://internal.local/")

    def test_any_internal_record_blocks_whole_host(self):
        # One public answer and one internal answer must still be refused.
        with self.assertRaises(suf.SafeURLError):
            suf.validate_url("http://split-horizon.com/")

    def test_unresolvable_host_blocked(self):
        with self.assertRaises(suf.SafeURLError):
            suf.validate_url("http://nope.invalid/")

    def test_missing_host_blocked(self):
        with self.assertRaises(suf.SafeURLError):
            suf.validate_url("http:///path-only")


# ── fetch: redirects and size caps ───────────────────────────────────────

class TestFetch(unittest.TestCase):
    def setUp(self):
        self._dns = socket.getaddrinfo
        socket.getaddrinfo = fake_dns({
            "good.com": ["93.184.216.34"],
            "evil-redirect.com": ["93.184.216.34"],  # public host...
            "internal.local": ["10.0.0.5"],          # ...that redirects here
            "hop1.com": ["8.8.8.8"],
            "hop2.com": ["1.1.1.1"],
        })
        self._raw = suf._raw_get
        self.addCleanup(lambda: setattr(socket, "getaddrinfo", self._dns))
        self.addCleanup(lambda: setattr(suf, "_raw_get", self._raw))

    def _install(self, routes):
        http = FakeHTTP(routes)
        suf._raw_get = http
        return http

    def test_simple_body_returned(self):
        self._install({"https://good.com/": FakeResponse(body=b"hello")})
        self.assertEqual(suf.fetch("https://good.com/"), b"hello")

    def test_redirect_to_internal_is_blocked(self):
        # The bypass that one-shot validators miss: a public host that 302s
        # to an internal address. Re-validation on the hop must catch it.
        self._install({
            "https://evil-redirect.com/": FakeResponse(
                status_code=302,
                headers={"Location": "http://internal.local/secrets"},
            ),
        })
        with self.assertRaises(suf.SafeURLError):
            suf.fetch("https://evil-redirect.com/")

    def test_safe_redirect_chain_followed(self):
        http = self._install({
            "https://hop1.com/": FakeResponse(
                status_code=301, headers={"Location": "https://hop2.com/final"}
            ),
            "https://hop2.com/final": FakeResponse(body=b"arrived"),
        })
        self.assertEqual(suf.fetch("https://hop1.com/"), b"arrived")
        self.assertEqual(
            http.requested, ["https://hop1.com/", "https://hop2.com/final"]
        )

    def test_relative_redirect_resolved_against_current(self):
        http = self._install({
            "https://good.com/a": FakeResponse(
                status_code=302, headers={"Location": "/b"}
            ),
            "https://good.com/b": FakeResponse(body=b"relative-ok"),
        })
        self.assertEqual(suf.fetch("https://good.com/a"), b"relative-ok")
        self.assertEqual(http.requested[-1], "https://good.com/b")

    def test_redirect_loop_capped(self):
        self._install({
            "https://good.com/": FakeResponse(
                status_code=302, headers={"Location": "https://good.com/"}
            ),
        })
        with self.assertRaises(suf.SafeURLError):
            suf.fetch("https://good.com/", max_redirects=3)

    def test_redirect_without_location_errors(self):
        self._install({"https://good.com/": FakeResponse(status_code=302)})
        with self.assertRaises(suf.SafeURLError):
            suf.fetch("https://good.com/")

    def test_oversize_body_aborted(self):
        big = [b"x" * 1000 for _ in range(10)]  # 10 KB in 1 KB chunks
        resp = FakeResponse(chunks=big)
        self._install({"https://good.com/": resp})
        with self.assertRaises(suf.SafeURLError):
            suf.fetch("https://good.com/", max_bytes=4096)
        self.assertTrue(resp.closed)  # stream closed even on abort

    def test_body_at_limit_allowed(self):
        self._install({"https://good.com/": FakeResponse(body=b"x" * 4096)})
        self.assertEqual(len(suf.fetch("https://good.com/", max_bytes=4096)), 4096)


if __name__ == "__main__":
    unittest.main(verbosity=2)
