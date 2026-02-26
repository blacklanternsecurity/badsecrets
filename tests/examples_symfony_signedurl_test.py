import os
import sys
import httpx
import respx
from unittest.mock import patch

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from badsecrets.examples import symfony_knownkey

from badsecrets import modules_loaded

Symfony_SignedURL = modules_loaded["symfony_signedurl"]


def test_symfony_url_not_up(monkeypatch, capsys):
    with respx.mock:
        # URL is down - handled correctly

        respx.get("http://notreal.com/_fragment").mock(side_effect=httpx.ConnectTimeout("timeout"))
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

    with respx.mock:
        respx.get("https://localhost/AAAAAAAA").respond(
            status_code=404,
            text="",
        )

        # Use a side_effect dispatcher because respx matches URLs without considering
        # query parameters, so a route for "_fragment" would also match "_fragment?_path=..."
        def _fragment_dispatcher(request):
            if "_hash=SrBMT/u6I0ylFIn/i6LYayCog21DnFMJ7yFBSnZpImA=" in str(request.url):
                return httpx.Response(200, text=phpcredits_page)
            return httpx.Response(403, text="")

        respx.get(url__startswith="https://localhost/_fragment").mock(side_effect=_fragment_dispatcher)

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "https://localhost/"],
        )
        symfony_knownkey.main()
        captured = capsys.readouterr()
        assert "Found Symfony Secret! [50c8215b436ebfcc1d568effb624a40e]" in captured.out
        print(captured)
