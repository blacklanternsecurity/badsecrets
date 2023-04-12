import os
import sys
import requests
import requests_mock
from mock import patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from badsecrets.examples import symfony_knownkey

from badsecrets import modules_loaded

Symfony_SignedURL = modules_loaded["symfony_signedurl"]


def test_symfony_url_not_up(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        # URL is down - handled correctly

        m.get(f"http://notreal.com/_fragment", exc=requests.exceptions.ConnectTimeout)
        monkeypatch.setattr("sys.argv", ["python", "--url", "http://notreal.com"])
        symfony_knownkey.main()
        captured = capsys.readouterr()
        assert "Error connecting to URL" in captured.out


def test_symfony_url_malformed(monkeypatch, capsys):
    # URL is not properly formatted

    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr("sys.argv", ["python", "--url", "hxxp://notreal.com"])
        symfony_knownkey.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "URL is not formatted correctly" in captured.err


def test_symfony_brute_success(monkeypatch, capsys, mocker):
    phpcredits_page = """
    <tr class="h"><th>PHP Group</th></tr>
<tr><td class="e">Thies C. Arntzen, Stig Bakken, Shane Caraveo, Andi Gutmans, Rasmus Lerdorf, Sam Ruby, Sascha Schumann, Zeev Suraski, Jim Winstead, Andrei Zmievski </td></tr>
</table>
<table>
<tr class="h"><th>Language Design &amp; Concept</th></tr>
<tr><td class="e">Andi Gutmans, Rasmus Lerdorf, Zeev Suraski, Marcus Boerger </td></tr>
</table>
<table>
<tr class="h"><th colspan="2">PHP Authors</th></tr>
<tr class="h"><th>Contribution</th><th>Authors</th></tr>
<tr><td class="e">Zend Scripting Language Engine </td><td class="v">Andi Gutmans, Zeev Suraski, Stanislav Malyshev, Marcus Boerger, Dmitry Stogov, Xinchen Hui, Nikita Popov </td></tr>
<tr><td class="e">Extension Module API </td><td class="v">Andi Gutmans, Zeev Suraski, Andrei Zmievski </td></tr>
<tr><td class="e">UNIX Build and Modularization </td><td class="v">Stig Bakken, Sascha Schumann, Jani Taskinen, Peter Kokot </td></tr>
<tr><td class="e">Windows Support </td><td class="v">Shane Caraveo, Zeev Suraski, Wez Furlong, Pierre-Alain Joye, Anatol Belski, Kalle Sommer Nielsen </td></tr>
<tr><td class="e">Server API (SAPI) Abstraction Layer </td><td class="v">Andi Gutmans, Shane Caraveo, Zeev Suraski </td></tr>
    """

    with requests_mock.Mocker() as m:
        m.get(
            f"https://localhost/AAAAAAAA",
            status_code=404,
            text="",
        )

        m.get(
            f"https://localhost/_fragment",
            status_code=403,
            text="",
        )

        m.get(
            f"https://localhost/_fragment?_path=_controller%3Dphpcredits&_hash=SrBMT/u6I0ylFIn/i6LYayCog21DnFMJ7yFBSnZpImA=",
            status_code=200,
            text=phpcredits_page,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "https://localhost/"],
        )
        symfony_knownkey.main()
        captured = capsys.readouterr()
        assert "Found Symfony Secret! [50c8215b436ebfcc1d568effb624a40e]" in captured.out
        print(captured)
