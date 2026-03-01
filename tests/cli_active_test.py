import os
import sys
import tempfile
import pytest
import respx
import httpx

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from badsecrets.examples import cli
from badsecrets.examples.cli import parse_custom_secrets

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

SHIRO_LOGIN_HTML = """
<html>
<head><title>Login</title></head>
<body>
<form action="/doLogin" method="POST">
<input type="text" name="username" />
<input type="password" name="password" />
<input type="checkbox" name="rememberMe" /> Remember me
</form>
</body>
</html>
"""


# --- parse_custom_secrets tests ---


def test_custom_secrets_global_file():
    """--custom-secrets FILE (no module prefix) returns as global file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("key1\nkey2\n")
        f.flush()
        try:
            global_files, module_keys = parse_custom_secrets([f.name])
            assert len(global_files) == 1
            assert global_files[0] == f.name
            assert module_keys == {}
        finally:
            os.unlink(f.name)


def test_custom_secrets_module_inline():
    """--custom-secrets MODULE:key1,key2 parses inline keys."""
    global_files, module_keys = parse_custom_secrets(["GlobalProtect_DefaultMasterKey:key1,key2,key3"])
    assert global_files == []
    assert "GlobalProtect_DefaultMasterKey" in module_keys
    assert module_keys["GlobalProtect_DefaultMasterKey"] == ["key1", "key2", "key3"]


def test_custom_secrets_module_file():
    """--custom-secrets MODULE:/path/to/file reads keys from file."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("filekey1\nfilekey2\n\n")
        f.flush()
        try:
            global_files, module_keys = parse_custom_secrets([f"GlobalProtect_DefaultMasterKey:{f.name}"])
            assert global_files == []
            assert "GlobalProtect_DefaultMasterKey" in module_keys
            assert module_keys["GlobalProtect_DefaultMasterKey"] == ["filekey1", "filekey2"]
        finally:
            os.unlink(f.name)


def test_custom_secrets_invalid_module():
    """Typo in module name -> error with suggestion."""
    with pytest.raises(argparse.ArgumentTypeError, match="No module found"):
        parse_custom_secrets(["GlobalProtect_DefaultMasterKe:key1"])


def test_custom_secrets_multiple():
    """Multiple --custom-secrets for same module extend the key list."""
    global_files, module_keys = parse_custom_secrets(
        [
            "GlobalProtect_DefaultMasterKey:key1,key2",
            "GlobalProtect_DefaultMasterKey:key3",
        ]
    )
    assert module_keys["GlobalProtect_DefaultMasterKey"] == ["key1", "key2", "key3"]


def test_custom_secrets_case_insensitive():
    """Module name lookup is case-insensitive."""
    global_files, module_keys = parse_custom_secrets(["globalprotect_defaultmasterkey:mykey"])
    assert "GlobalProtect_DefaultMasterKey" in module_keys


def test_custom_secrets_empty():
    """No --custom-secrets returns empty."""
    global_files, module_keys = parse_custom_secrets(None)
    assert global_files == []
    assert module_keys == {}


def test_custom_secrets_mixed():
    """Mix of global file and module-targeted keys."""
    with tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False) as f:
        f.write("globalkey\n")
        f.flush()
        try:
            global_files, module_keys = parse_custom_secrets([f.name, "GlobalProtect_DefaultMasterKey:targeted_key"])
            assert len(global_files) == 1
            assert "GlobalProtect_DefaultMasterKey" in module_keys
            assert module_keys["GlobalProtect_DefaultMasterKey"] == ["targeted_key"]
        finally:
            os.unlink(f.name)


def test_custom_secrets_shiro_module():
    """Module targeting works for active Shiro module."""
    global_files, module_keys = parse_custom_secrets(["Shiro_RememberMe_Key:myShiroKey123"])
    assert "Shiro_RememberMe_Key" in module_keys
    assert module_keys["Shiro_RememberMe_Key"] == ["myShiroKey123"]


def test_custom_secrets_passive_module():
    """Module targeting also works for passive modules."""
    global_files, module_keys = parse_custom_secrets(["Shiro_RememberMe:mykey"])
    assert "Shiro_RememberMe" in module_keys


# --- CLI integration tests ---


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


@respx.mock
def test_url_mode_custom_secrets_for_active(monkeypatch, capsys):
    """--custom-secrets MODULE:keys works in URL mode for active modules."""
    respx.get("https://vpn.example.com").mock(return_value=httpx.Response(200, text=GLOBALPROTECT_PORTAL_HTML))
    respx.post("https://vpn.example.com/sslmgr").mock(
        return_value=httpx.Response(200, text="Unable to find the configuration")
    )

    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "-u",
            "https://vpn.example.com",
            "-c",
            "GlobalProtect_DefaultMasterKey:customkey1,customkey2",
            "-nc",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Known Secret Found!" in captured.out


def test_list_modules(monkeypatch, capsys):
    """--list-modules shows module descriptions."""
    monkeypatch.setattr("sys.argv", ["python", "--list-modules", "-nc"])

    cli.main()
    captured = capsys.readouterr()
    assert "Passive modules" in captured.out
    assert "Active modules" in captured.out
    assert "GlobalProtect_DefaultMasterKey" in captured.out
    assert "Shiro_RememberMe_Key" in captured.out
    assert "Apache Shiro" in captured.out
