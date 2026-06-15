# Contributing

This module guards a security boundary, so the bar is correctness, not features. Contributions are welcome if they follow the philosophy:

1. **Fail closed, always.** Anything that cannot be proven safe must raise `SafeURLError`. Unparseable IPs, unresolvable hosts, and missing hosts all block. A check you cannot prove passed has not passed.
2. **No new blocklists.** IP classification leans on `ipaddress.is_global` precisely so there is no hand-maintained list to drift. Reach for the standard library before a literal range.
3. **Tests stay network-free.** DNS is a fake resolver and HTTP is a scripted fake. A test must never make a real outbound connection, so the suite runs anywhere with no setup.
4. **No dependencies beyond `requests` at fetch time.** Validation must work with only the standard library.

## Adding a check

1. State the bypass it closes in one sentence in the PR.
2. Add the logic, keeping the fail-closed default.
3. Add tests for it: at minimum one case that should block, one that should pass, and the specific bypass case if there is one.
4. Run `python3 test_safe_url_fetch.py` and confirm green.
5. Open a PR.

Found a bypass? Open an issue describing the URL or redirect chain that slips through, ideally with a failing test.
