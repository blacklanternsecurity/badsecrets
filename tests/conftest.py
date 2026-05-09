"""Shared pytest fixtures.

`bh_mock` returns a fresh BlasthttpMock per test. For tests that drive a CLI
script which constructs its own BlastHTTP client internally, the fixture also
patches `BlastHTTP` on each example module so the script picks up the mock
transparently — tests just register responses on `bh_mock` and call the script.
"""

from unittest.mock import patch
import pytest
from blasthttp.mock import BlasthttpMock

from badsecrets.examples import cli, symfony_knownkey, telerik_knownkey


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
