"""Shared pytest fixtures.

`bh_mock` returns a fresh BlasthttpMock per test. For tests that drive a CLI
script which constructs its own BlastHTTP client internally, the fixture also
patches `BlastHTTP` on each example module so the script picks up the mock
transparently — tests just register responses on `bh_mock` and call the script.
"""

from pathlib import Path
from unittest.mock import patch

import pytest
from blasthttp.mock import BlasthttpMock

import badsecrets.base
from badsecrets.base import BadsecretsBase
from badsecrets.examples import cli, symfony_knownkey, telerik_knownkey

_RESOURCE_DIR = Path(badsecrets.base.__file__).parent / "resources"
_DEFAULT_TRIM_WORDLIST = "top_250000_passwords.txt"


def pytest_configure(config):
    config.addinivalue_line(
        "markers",
        "trim_wordlist(*answers, wordlist=..., context=...): trim a shipped wordlist down to "
        "`answers` plus neighbours, so brute-force modules do not sweep all 250k candidates.",
    )


@pytest.fixture
def bh_mock():
    """A fresh BlasthttpMock per test, with all CLI script BlastHTTP imports
    patched to return this mock. Tests register responses with
    ``bh_mock.add_response(...)`` / ``bh_mock.add_callback(...)``.
    For library-level tests (active modules), pass it directly via
    ``http_client=bh_mock`` instead — the patches are harmless either way.
    """
    mock = BlasthttpMock()
    with (
        patch.object(cli, "BlastHTTP", return_value=mock),
        patch.object(symfony_knownkey, "BlastHTTP", return_value=mock),
        patch.object(telerik_knownkey, "_HTTP_CLIENT", mock),
    ):
        yield mock


@pytest.fixture
def trim_wordlist(monkeypatch):
    """Cut a shipped wordlist down to `answers` plus `context` neighbours each.

    Without this the brute-force modules sweep all 250k candidates per call.
    """
    orig = BadsecretsBase.load_resources
    trimmed = {}

    def patched(self, resource_list):
        lines = list(orig(self, [])) if self.custom_resource else []
        for name in resource_list:
            lines.extend(trimmed[name] if name in trimmed else orig(self, [name]))
        return tuple(dict.fromkeys(lines))

    def _trim(name, *answers, context=2):
        with open(_RESOURCE_DIR / name) as f:
            all_lines = f.readlines()
        keep = []
        for answer in answers:
            i = all_lines.index(f"{answer}\n")
            keep += all_lines[max(0, i - context) : i + context + 1]
        trimmed[name] = tuple(keep)
        badsecrets.base._resource_cache.clear()
        monkeypatch.setattr(BadsecretsBase, "load_resources", patched)

    yield _trim
    badsecrets.base._resource_cache.clear()


@pytest.fixture(autouse=True)
def _trim_wordlists(request):
    """Apply any `trim_wordlist` markers on the test, module or class.

    Opt a whole file in with ``pytestmark = pytest.mark.trim_wordlist``, or
    ``pytest.mark.trim_wordlist("secret")`` when a test has to actually crack a
    secret that lives deep in the list. Unmarked tests never build the fixture,
    so they keep the shared resource cache.
    """
    markers = list(request.node.iter_markers("trim_wordlist"))
    if not markers:
        return
    trim = request.getfixturevalue("trim_wordlist")
    for marker in markers:
        kwargs = dict(marker.kwargs)
        trim(kwargs.pop("wordlist", _DEFAULT_TRIM_WORDLIST), *marker.args, **kwargs)
