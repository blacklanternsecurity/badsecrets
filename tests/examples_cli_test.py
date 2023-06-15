import os
import sys
import requests_mock
from mock import patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from badsecrets.examples import cli

base_vulnerable_page = """
<html>
<head>
</head>
<body>
<p>test</p>
<p> heres a JWT for fun: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"</p>
</body>
</html>
"""

base_identifyonly_page = """
<html>
<head>
</head>
<body>
<p>test</p>
<p> heres a JWT for fun: eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_zzzzzzz"</p>
</body>
</html>
"""

base_non_vulnerable_page = "<html>Just a website</html>"


def test_examples_cli_manual(monkeypatch, capsys):
    # Check Vulnerable JWT
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "your-256-bit-secret" in captured.out


def test_examples_cli_url_invalid(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr("sys.argv", ["python", "--url", "hxxp://notaurl"])
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "URL is not formatted correctly" in captured.err


def test_examples_cli_url_both_set(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        # Both URL and secrets are supplied - rejected appropriately
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "--url",
                "http://example.com",
                "dn/WEP+ogagnOcePgsXoPRe05wss0YIyAZdzFHJuWJejTRbDNDEqes7fBwNY4IqTmT7kTB0o9f8fRSpRXaMcyg==",
            ],
        )
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "In --url mode, no positional arguments should be used" in captured.err


def test_example_cli_vulnerable_url(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        m.get(
            f"http://example.com/vulnerablejwt.html",
            status_code=200,
            text=base_vulnerable_page,
        )

        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/vulnerablejwt.html"])
        cli.main()
        captured = capsys.readouterr()
        assert "your-256-bit-secret" in captured.out


def test_example_cli_not_vulnerable_url(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        m.get(
            f"http://example.com/notvulnerable.html",
            status_code=200,
            text=base_non_vulnerable_page,
        )

        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/notvulnerable.html"])
        cli.main()
        captured = capsys.readouterr()
        assert "No secrets found :(" in captured.out


def test_example_cli_identifyonly_url(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        m.get(
            f"http://example.com/identifyonly.html",
            status_code=200,
            text=base_identifyonly_page,
        )

        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/identifyonly.html"])
        cli.main()
        captured = capsys.readouterr()
        assert "Cryptographic Product Identified (no vulnerability)" in captured.out


def test_example_cli_hashcat_result(monkeypatch, capsys):
    # Check Vulnerable JWT
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
            "--hashcat",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Potential matching hashcat commands:" in captured.out
    assert "Module: [Generic_JWT] JSON Web Token (JWT) Algorithm: HS256 Command" in captured.out

    print(captured.out)


def test_example_cli_hashcat_noresult(monkeypatch, capsys):
    # Check Vulnerable JWT
    monkeypatch.setattr(
        "sys.argv",
        ["python", "nonsense!", "--hashcat"],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "No matching hashcat commands found :/" in captured.out
    print(captured.out)


def test_example_cli_hashcat_matchnomodule(monkeypatch, capsys):
    # Check Vulnerable JWT
    monkeypatch.setattr(
        "sys.argv",
        # this example will satisfy the tests now, since it matches an identify regex but no modules with hashcat functions
        # If we make a hashcat function for express, we will probably have to make a dummy module instead
        ["python", "s%3ABh8oG0qgMyJc4qq8A47I0MTwcNiu7ue8.hXhPs8q9AN4ATeh2KrjuzvSbJA7cqbkP5cUUT34bZKB", "--hashcat"],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "No matching hashcat commands found :/" in captured.out
    print(captured.out)
