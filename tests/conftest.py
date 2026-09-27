"""Test-session bootstrap: give the test run a private, random session secret and
enable POIA_TEST_MODE before any `app.*` module is imported.

app/settings.py refuses to start with a known-insecure POIA_SESSION_SECRET
(e.g. the literal "dev-only-secret" it previously defaulted to) unless
POIA_TEST_MODE is set -- this file exists so that safeguard doesn't break the
test suite. Values are set with setdefault so an operator's explicit
environment (e.g. a CI secret) is never overridden.
"""

import os
import secrets

os.environ.setdefault("POIA_TEST_MODE", "true")
os.environ.setdefault("POIA_SESSION_SECRET", secrets.token_hex(32))

# app/main.py sets https_only=True on the session cookie (Secure attribute),
# matching the paper's documented deployment claim of "secure, HTTP-only,
# same-site session cookies." httpx's cookie jar correctly refuses to send a
# Secure-flagged cookie back over a plain "http://" request, which is exactly
# what every test's TestClient(app) would otherwise do by default -- silently
# breaking every session-based login in the suite, not exercising a real gap.
# Giving TestClient an "https://" base_url by default (only when a test does
# not explicitly choose its own) makes the in-process test transport keep
# treating the cookie as same-origin/secure, with no real TLS involved and no
# change to the application under test.
import starlette.testclient as _starlette_testclient

_original_testclient_init = _starlette_testclient.TestClient.__init__


def _https_default_testclient_init(self, app, base_url="https://testserver", *args, **kwargs):
    _original_testclient_init(self, app, *args, base_url=base_url, **kwargs)


_starlette_testclient.TestClient.__init__ = _https_default_testclient_init
