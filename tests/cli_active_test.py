import os
import sys
import tempfile
import pytest
import respx
import httpx

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from badsecrets.examples import cli
from badsecrets.examples.cli import validate_active_keys

import argparse

GLOBALPROTECT_PORTAL_HTML = """
<html>
<head><title>GlobalProtect Portal</title></head>
<body>
<form action="/global-protect/login.esp" method="POST">
<input type="text" name="user" />
<input type="password" name="passwd" />
</form>
</body>
</html>
"""


def test_active_keys_inline():
    """--active-keys MODULE:key1,key2 parses inline keys."""
    result = validate_active_keys(["GlobalProtect_DefaultMasterKey:key1,key2,key3"])
    assert "GlobalProtect_DefaultMasterKey" in result
    assert result["GlobalProtect_DefaultMasterKey"] == ["key1", "key2", "key3"]


def test_active_keys_file():
    """--active-keys MODULE:/path/to/file reads keys from file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("filekey1\nfilekey2\n\n")
        f.flush()
        try:
            result = validate_active_keys([f"GlobalProtect_DefaultMasterKey:{f.name}"])
            assert "GlobalProtect_DefaultMasterKey" in result
            assert result["GlobalProtect_DefaultMasterKey"] == ["filekey1", "filekey2"]
        finally:
            os.unlink(f.name)


def test_active_keys_invalid_module():
    """Typo in module name -> error with suggestion."""
    with pytest.raises(argparse.ArgumentTypeError, match="No active module found"):
        validate_active_keys(["GlobalProtect_DefaultMasterKe:key1"])


def test_active_keys_no_colon():
    """Missing colon -> format error."""
    with pytest.raises(argparse.ArgumentTypeError, match="Expected MODULE:keys_or_file"):
        validate_active_keys(["GlobalProtect_DefaultMasterKeykey1"])


def test_active_keys_multiple():
    """Multiple --active-keys for same module extend the key list."""
    result = validate_active_keys(
        [
            "GlobalProtect_DefaultMasterKey:key1,key2",
            "GlobalProtect_DefaultMasterKey:key3",
        ]
    )
    assert result["GlobalProtect_DefaultMasterKey"] == ["key1", "key2", "key3"]


def test_active_keys_case_insensitive():
    """Module name lookup is case-insensitive."""
    result = validate_active_keys(["globalprotect_defaultmasterkey:mykey"])
    assert "GlobalProtect_DefaultMasterKey" in result


def test_active_keys_empty():
    """No --active-keys returns empty dict."""
    result = validate_active_keys(None)
    assert result == {}


@respx.mock
def test_passive_only_skips_active(monkeypatch, capsys):
    """--passive-only suppresses active probes."""
    respx.get("https://vpn.example.com").mock(return_value=httpx.Response(200, text=GLOBALPROTECT_PORTAL_HTML))

    monkeypatch.setattr(
        "sys.argv",
        ["python", "-u", "https://vpn.example.com", "--passive-only", "-nc"],
    )

    cli.main()
    captured = capsys.readouterr()
    # Should not contain "Active probes are enabled" message
    assert "Active probes are enabled" not in captured.out


@respx.mock
def test_url_mode_runs_active_by_default(monkeypatch, capsys):
    """--url without --passive-only runs active probes (shows active message)."""
    respx.get("https://vpn.example.com").mock(return_value=httpx.Response(200, text=GLOBALPROTECT_PORTAL_HTML))
    respx.post("https://vpn.example.com/sslmgr").mock(return_value=httpx.Response(200, text="Invalid Cookie"))

    monkeypatch.setattr(
        "sys.argv",
        ["python", "-u", "https://vpn.example.com", "-nc"],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Active probes are enabled" in captured.out


@respx.mock
def test_url_mode_active_finds_secret(monkeypatch, capsys):
    """Active probe finds default key and reports it."""
    respx.get("https://vpn.example.com").mock(return_value=httpx.Response(200, text=GLOBALPROTECT_PORTAL_HTML))
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    monkeypatch.setattr(
        "sys.argv",
        ["python", "-u", "https://vpn.example.com", "-nc"],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Known Secret Found!" in captured.out
    assert "p1a2l3o4a5l6t7o8" in captured.out


@respx.mock
def test_url_mode_active_json(monkeypatch, capsys):
    """Active probe result in JSON mode."""
    respx.get("https://vpn.example.com").mock(return_value=httpx.Response(200, text=GLOBALPROTECT_PORTAL_HTML))
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    monkeypatch.setattr(
        "sys.argv",
        ["python", "-u", "https://vpn.example.com", "-j"],
    )

    cli.main()
    captured = capsys.readouterr()

    # JSON output may have passive (empty) then active results
    assert "GlobalProtect_DefaultMasterKey" in captured.out
    assert "p1a2l3o4a5l6t7o8" in captured.out


def test_passive_only_and_active_keys_conflict(monkeypatch, capsys):
    """--passive-only + --active-keys -> error."""
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "-u",
            "https://vpn.example.com",
            "--passive-only",
            "--active-keys",
            "GlobalProtect_DefaultMasterKey:key1",
            "-nc",
        ],
    )

    with pytest.raises(SystemExit):
        cli.main()
