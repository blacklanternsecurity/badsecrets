import os
import sys
import tempfile
import requests_mock
from mock import patch

from badsecrets.modules.generic_jwt import Generic_JWT

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


def test_examples_cli_manual_severityprinted(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Severity: HIGH" in captured.out


def test_examples_cli_manualtwovalues(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "foo=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==",
            "zOQU7v7aTe_3zu7tnVuHi1MJ2DU",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert (
        "Product: Data Cookie: [foo=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==] Signature Cookie: [zOQU7v7aTe_3zu7tnVuHi1MJ2DU]"
        in captured.out
    )


def test_examples_cli_manualtwovalues_identifyonly(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "/wEPDwUJODExMDE5NzY5ZGSglOSr1rG6xN5rzh/4C9UEuwa64w==", "EDD8C9AE"],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Viewstate: /wEPDwUJODExMDE5NzY5ZGSglOSr1rG6xN5rzh/4C9UEuwa64w== Generator: EDD8C9AE" in captured.out


def test_examples_cli_url_invalid(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr("sys.argv", ["python", "--url", "hxxp://notaurl"])
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "URL is not formatted correctly" in captured.out


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
        assert "In --url mode, no positional arguments should be used" in captured.out


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


def test_example_cli_vulnerable_headers(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        m.get(
            f"http://example.com/vulnerableexpress_cs.html",
            status_code=200,
            text="<html><body>content</body></html>",
            headers={
                "X-Powered-By": "Express",
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": "11",
                "ETag": 'W/"b-LTx1jc/VQrBurpG4w6qnFsu3lHk"',
                "Set-Cookie": "session=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==; path=/; expires=Sun, 16 Jul 2023 19:56:30 GMT; httponly, session.sig=8BrG9wzvqxuPCtKmfgdyXXGGqA8; path=/; expires=Sun, 16 Jul 2023 19:56:30 GMT; httponly",
                "Date": "Sat, 15 Jul 2023 02:47:13 GMT",
                "Connection": "close",
            },
        )

        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/vulnerableexpress_cs.html"])
        cli.main()
        captured = capsys.readouterr()
        assert (
            "Product: Data Cookie: [session=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==] Signature Cookie: [8BrG9wzvqxuPCtKmfgdyXXGGqA8]"
            in captured.out
        )


def test_example_cli_vulnerable_headersidentifyonly(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        m.get(
            f"http://example.com/vulnerableexpress_cs.html",
            status_code=200,
            text="<html><body>content</body></html>",
            headers={
                "X-Powered-By": "Express",
                "Content-Type": "text/html; charset=utf-8",
                "Content-Length": "11",
                "ETag": 'W/"b-LTx1jc/VQrBurpG4w6qnFsu3lHk"',
                "Set-Cookie": "session=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==; path=/; expires=Sun, 16 Jul 2023 19:56:30 GMT; httponly, session.sig=8BrG9wzvqxuPCtKmfgdyXXGGqA7; path=/; expires=Sun, 16 Jul 2023 19:56:30 GMT; httponly",
                "Date": "Sat, 15 Jul 2023 02:47:13 GMT",
                "Connection": "close",
            },
        )

        monkeypatch.setattr("sys.argv", ["python", "--url", "http://example.com/vulnerableexpress_cs.html"])
        cli.main()
        captured = capsys.readouterr()
        assert (
            "Data Cookie: [session=eyJ1c2VybmFtZSI6IkJib3RJc0xpZmUifQ==] Signature Cookie: [8BrG9wzvqxuPCtKmfgdyXXGGqA7]"
            in captured.out
        )
        assert "Cryptographic Product Identified (no vulnerability, or not confirmed vulnerable)" in captured.out


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
        print(captured)
        assert "Cryptographic Product Identified (no vulnerability, or not confirmed vulnerable)" in captured.out


def test_example_cli_identifyonly_hashcat(monkeypatch, capsys):
    with requests_mock.Mocker() as m:
        m.get(
            f"http://example.com/identifyonly.html",
            status_code=200,
            text=base_identifyonly_page,
        )

        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCB",
            ],
        )
        cli.main()
        captured = capsys.readouterr()
        print(captured)
        assert "No secrets found :(" in captured.out
        assert "Potential matching hashcat commands:" in captured.out
        assert "JSON Web Token (JWT) Algorithm: HS256 Command: [hashcat -m 16500" in captured.out


def test_example_cli_hashcat_omittedonmatch(monkeypatch, capsys):
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
    assert not "Potential matching hashcat commands:" in captured.out
    assert "your-256-bit-secret" in captured.out

    print(captured.out)


def test_example_cli_hashcat_noresult(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "nonsense!"],
    )

    cli.main()
    captured = capsys.readouterr()
    assert not "Potential matching hashcat commands" in captured.out
    print(captured.out)


def test_example_cli_hashcat_matchnomodule(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        # this example will satisfy the tests now, since it matches an identify regex but no modules with hashcat functions
        # If we make a hashcat function for express, we will probably have to make a dummy module instead
        ["python", "s%3ABh8oG0qgMyJc4qq8A47I0MTwcNiu7ue8.hXhPs8q9AN4ATeh2KrjuzvSbJA7cqbkP5cUUT34bZKB"],
    )

    cli.main()
    captured = capsys.readouterr()
    assert not "Potential matching hashcat commands" in captured.out
    print(captured.out)


# this is to ensure hashcat output will only show for compatable JWT algorithms
def test_example_cli_hashcat_jwtnomatchingalgo(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "eyJhbGciOiJGQUtFIiwidHlwIjoiSldUIn0.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "JSON Web Token (JWT) Algorithm: HS256 Command" not in captured.out


def test_example_cli_hashcat_peoplesoft(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABT4mYioG/i325GsBHHNyDIM+9yf1GgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert (
        "Peoplesoft PS_TOKEN Password Command: [hashcat -m 13500 -a 0 f89988a81bf8b7db91ac0471cdc8320cfbdc9fd4:750000000403020101000000bc020000000000001462006100640073006500630072006500740073000645004e0047000e50005300460054005f00480052003432003000320032002d00310030002d00310033002d00300039002e00350030002e00330039002e0039003900390035003400330000  <dictionary_file>"
        in captured.out
    )


def test_example_cli_hashcat_peoplesoft_invalid(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABT5mYioG/i325GsBHHNyDIM+9yf1GgAAAAFAFNkYXRhXHiZHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    print(captured)
    assert "[Peoplesoft_PSToken] Peoplesoft PS_TOKEN Password Command" not in captured.out


def test_example_cli_hashcat_telerikhashkey(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "y1MPLyncErmvCfYRJDU72NLpEurHW6DfWxGJlfMGTH55vxb8V9m2vrkLDCkDm8%2F1PlVto%2FNCiuCR6ioagdVglig7fQjiAmlEMc7v5RWKx74f8v%2FXxMLhwqLzLkF5YbKbAJO7Rtmhqod1vAzINW2yo16gm7yNseksxi4dSIdiGKVIBuUYiA%2BJrhAlDYfmYrdSA0laWPsYjCyTLWwVipZnPb%2FmOJk%2BMnZC3WD2JLtJyiTTanExxyVsx8SKrKqighnPQCiCLEcBik9FoPNBElJLCIZqizM%2Fy8DYmvyC0bTH7rB6plNMYthd%2F%2FIr7DdRaoJJXHThVbra3BXybA7aiW4fRmuRD0vwiZUV%2BYWaClCgPpZ90YOfwXGlGpVhYfZJPNH%2BeCG2piS6oJPs2AjSUlQuzKn4uN%2F2OZYca8IP%2FkVE0jwU5EUq3uf%2FCmXJ8zNcgmcQXhhxejsn3dEygzw4zzyqR3LAnFQkk3BWtrhEmyNVjCL2y1MgsSTjClmTQzX0UicfQOBv4Vgg9E3EA6rqIdxj%2F7pq7N47X0f4wLByBROlgKj%2BhbuWNKAaZmXhjurQ5uu7WOGwKEmOpEnkTZzyoCFui8S6f3dtbrNw2rwGgo1oz8pD7gDXIXATx66hswuK7tfxjkMab%2FdXBQ3vQTSa5HYNpCWnJu3RunO3sb5OKT%2FtUe061%2BdO%2FcFDNwNiGXQvQ9yuY99w2BtNB7ZOazMl9vGG8lcL4s9yuSMdfG3tcgD4%2BrtHDEL7v0ub14dFxB8TOqY5JMRKdyd8D%2FP46%2BC3pWT61EYaddn3U548w%2FjHz1sXXx6b2lo7%2BYnG1DrRt%2Bk6%2BZt1Wa7UkfYC2b2n4OM2ro%2FqwHBU3FL0LOvBdXDDvlqqMSF4PtYUpO09GaE4TrzKlA%2FFN%2BZ9ibPj%2BmHyanK3GpdsR9S%2BavrhfnL%2BXrI26E5C2GPYOHTlR6u5dqvKJ71%2FCCF%2F%2FdYWbdzS5FVQ25WO6XREomBdvK2gP55Mh3byVUfoli%2F9pNkXytwYVo3yIIICReAuYdbteZN6%2BDJl4rJ5AKTbThpNk6co%2BG6Gl5rYKz1KqV80fqOF4TBlv6cm4kLvS%2FFk2JWD3L5kE8llElj9j4Bq7esFt1I%2Fvvo95guNdrBiiRfh2u7qENi1jfXYNlf1Npth8Vw11vztAq8jssrpMo3cVCKU2aTDkOQWvFBO6tN%2FvpYRCzRJHoy3e0sImQa3rN7wTNedxsadcL%2BHRXuYFFvQpcg5lfngY6lyVkjYPgxc5K4mRKZHDEXGWetFRl5af22wuNiEYmIERrh%2Fq25zBBCTfe2swAKb8hZLjoEywedeaQyZVveb4E0mTuMEQ259781fg727QoKnlu2m7Zh6gJINDk1a68Ap3t%2FCU1U8%2BL1haNZ5s7ywWl6vHM7dWvGffmqofBXoOKFhPdnSTc5xn6kgryFZJmnKwRyhOlPVCthRkgnANcLXEH1mtC1WQ8soXuVuMm6uAg44nwOt8BVZSNyJYYaEZCH4HPhtTo1F93W4PtXWJKIT6Mphf%2FWsIwJOKJzxgzCkCSwBB65kTL17LIQuyBqfmprPFtqEgTIRv4IFpJ8WuyeES08ti8QYwYM%2BPN2GZ1CTQu6kvlVlSBJxdTSvdf5IS%2BVje1pQqPJdYOIwwMTTpLfOno4qkHZVcM6OQnUNpvyIvRTuYJ5twYx8Rkty36P1%2BsKeaTMFgVWfMvpK5UNThjDxKMAsy7MgcMTxfZAeNi41gaQSbOFrdgtbkYMTALGiozY1NCcnHbXwr0qnHVKjVVDBuOPZeLL0lzBcm3hGjGYhOjrJLv4ZuRSLvCAe4UfHRhQcCjJd15vNpV8nbdcvEl2e7FUdoNlrPWxaglcEK0vu9WJxBzQVmzoNINhUvqnDZIrYOAGfzrDYrDAwMheLpr9OKHMvM2WHNHUecDK0781NXS%2FdoGGeheaTOe8DieXwcL%2FJlW2bBEwSUNDMuyD8RiukZHUQ4qcgDF%2FGLqUqkDesWIdQyj99wqKFfQNuwm41kCnzAN5uSt3IUiMiA7zsuDr%2BDg0Ro00K6Ap3wFLF1M3xtQobLnsRuCHZGwXSGxye%2Bmg8%2FxD%2BlTOs55IRwb3DDwi6eKdubRJMLN2o544FHYWL1UBAc%2BZcfz7vIqFeHUBMOc5htw%2BDPlXZRRnEzn%2F4qpV4ioEdZeQEv%2BhfXyUs9hF19JP%2BLJiWDJ3Ukdh7OdW2c6GtjOIiKeOcFcJi%2BYB8CP8ItWydzlt0IUaHufQ4ooPkkmmchlX7HV6%2BboKKGxaNWcOx%2BkAWPvP0IeYahPPff9PiSErWiFzc%2BOmFinwZu%2FXJsse%2BG1ndzbUJeMV%2B8jBdZtxiAewbNJxJZl%2Bgu6avfcLJqYjBfxFJ3%2B87%2B6AtI3JI93aCTEiLPVHMiMjsI6j8N1Nxn77BhCsXF3D9uXIqbqTsxp5je4xS4LHqrTTVnsKk3zqlc1PZvgVRGYVD3MRFUmFQfT%2Bnn9HhrDkuCfVdALWHnDOC%2BOOhHglnYm38GLFWA2Mo5VW4k3wM0ftFYVzaVVYYAEFmp8Uvup1sh6COO%2FZJJCSgBK1ZwjnLeWHM1j6Fo0f03YYC5Eghbzi2dBwR0WC2e0hHgtb2TY1K6Uc%3D",
        ],
    )

    cli.main()
    captured = capsys.readouterr()

    assert "Module: [Telerik_HashKey] Telerik Hash Key Signature Command: [hashcat -m 1450 -a 0 d63e" in captured.out


def test_example_cli_hashcat_disabled(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "y1MPLyncErmvCfYRJDU72NLpEurHW6DfWxGJlfMGTH55vxb8V9m2vrkLDCkDm8%2F1PlVto%2FNCiuCR6ioagdVglig7fQjiAmlEMc7v5RWKx74f8v%2FXxMLhwqLzLkF5YbKbAJO7Rtmhqod1vAzINW2yo16gm7yNseksxi4dSIdiGKVIBuUYiA%2BJrhAlDYfmYrdSA0laWPsYjCyTLWwVipZnPb%2FmOJk%2BMnZC3WD2JLtJyiTTanExxyVsx8SKrKqighnPQCiCLEcBik9FoPNBElJLCIZqizM%2Fy8DYmvyC0bTH7rB6plNMYthd%2F%2FIr7DdRaoJJXHThVbra3BXybA7aiW4fRmuRD0vwiZUV%2BYWaClCgPpZ90YOfwXGlGpVhYfZJPNH%2BeCG2piS6oJPs2AjSUlQuzKn4uN%2F2OZYca8IP%2FkVE0jwU5EUq3uf%2FCmXJ8zNcgmcQXhhxejsn3dEygzw4zzyqR3LAnFQkk3BWtrhEmyNVjCL2y1MgsSTjClmTQzX0UicfQOBv4Vgg9E3EA6rqIdxj%2F7pq7N47X0f4wLByBROlgKj%2BhbuWNKAaZmXhjurQ5uu7WOGwKEmOpEnkTZzyoCFui8S6f3dtbrNw2rwGgo1oz8pD7gDXIXATx66hswuK7tfxjkMab%2FdXBQ3vQTSa5HYNpCWnJu3RunO3sb5OKT%2FtUe061%2BdO%2FcFDNwNiGXQvQ9yuY99w2BtNB7ZOazMl9vGG8lcL4s9yuSMdfG3tcgD4%2BrtHDEL7v0ub14dFxB8TOqY5JMRKdyd8D%2FP46%2BC3pWT61EYaddn3U548w%2FjHz1sXXx6b2lo7%2BYnG1DrRt%2Bk6%2BZt1Wa7UkfYC2b2n4OM2ro%2FqwHBU3FL0LOvBdXDDvlqqMSF4PtYUpO09GaE4TrzKlA%2FFN%2BZ9ibPj%2BmHyanK3GpdsR9S%2BavrhfnL%2BXrI26E5C2GPYOHTlR6u5dqvKJ71%2FCCF%2F%2FdYWbdzS5FVQ25WO6XREomBdvK2gP55Mh3byVUfoli%2F9pNkXytwYVo3yIIICReAuYdbteZN6%2BDJl4rJ5AKTbThpNk6co%2BG6Gl5rYKz1KqV80fqOF4TBlv6cm4kLvS%2FFk2JWD3L5kE8llElj9j4Bq7esFt1I%2Fvvo95guNdrBiiRfh2u7qENi1jfXYNlf1Npth8Vw11vztAq8jssrpMo3cVCKU2aTDkOQWvFBO6tN%2FvpYRCzRJHoy3e0sImQa3rN7wTNedxsadcL%2BHRXuYFFvQpcg5lfngY6lyVkjYPgxc5K4mRKZHDEXGWetFRl5af22wuNiEYmIERrh%2Fq25zBBCTfe2swAKb8hZLjoEywedeaQyZVveb4E0mTuMEQ259781fg727QoKnlu2m7Zh6gJINDk1a68Ap3t%2FCU1U8%2BL1haNZ5s7ywWl6vHM7dWvGffmqofBXoOKFhPdnSTc5xn6kgryFZJmnKwRyhOlPVCthRkgnANcLXEH1mtC1WQ8soXuVuMm6uAg44nwOt8BVZSNyJYYaEZCH4HPhtTo1F93W4PtXWJKIT6Mphf%2FWsIwJOKJzxgzCkCSwBB65kTL17LIQuyBqfmprPFtqEgTIRv4IFpJ8WuyeES08ti8QYwYM%2BPN2GZ1CTQu6kvlVlSBJxdTSvdf5IS%2BVje1pQqPJdYOIwwMTTpLfOno4qkHZVcM6OQnUNpvyIvRTuYJ5twYx8Rkty36P1%2BsKeaTMFgVWfMvpK5UNThjDxKMAsy7MgcMTxfZAeNi41gaQSbOFrdgtbkYMTALGiozY1NCcnHbXwr0qnHVKjVVDBuOPZeLL0lzBcm3hGjGYhOjrJLv4ZuRSLvCAe4UfHRhQcCjJd15vNpV8nbdcvEl2e7FUdoNlrPWxaglcEK0vu9WJxBzQVmzoNINhUvqnDZIrYOAGfzrDYrDAwMheLpr9OKHMvM2WHNHUecDK0781NXS%2FdoGGeheaTOe8DieXwcL%2FJlW2bBEwSUNDMuyD8RiukZHUQ4qcgDF%2FGLqUqkDesWIdQyj99wqKFfQNuwm41kCnzAN5uSt3IUiMiA7zsuDr%2BDg0Ro00K6Ap3wFLF1M3xtQobLnsRuCHZGwXSGxye%2Bmg8%2FxD%2BlTOs55IRwb3DDwi6eKdubRJMLN2o544FHYWL1UBAc%2BZcfz7vIqFeHUBMOc5htw%2BDPlXZRRnEzn%2F4qpV4ioEdZeQEv%2BhfXyUs9hF19JP%2BLJiWDJ3Ukdh7OdW2c6GtjOIiKeOcFcJi%2BYB8CP8ItWydzlt0IUaHufQ4ooPkkmmchlX7HV6%2BboKKGxaNWcOx%2BkAWPvP0IeYahPPff9PiSErWiFzc%2BOmFinwZu%2FXJsse%2BG1ndzbUJeMV%2B8jBdZtxiAewbNJxJZl%2Bgu6avfcLJqYjBfxFJ3%2B87%2B6AtI3JI93aCTEiLPVHMiMjsI6j8N1Nxn77BhCsXF3D9uXIqbqTsxp5je4xS4LHqrTTVnsKk3zqlc1PZvgVRGYVD3MRFUmFQfT%2Bnn9HhrDkuCfVdALWHnDOC%2BOOhHglnYm38GLFWA2Mo5VW4k3wM0ftFYVzaVVYYAEFmp8Uvup1sh6COO%2FZJJCSgBK1ZwjnLeWHM1j6Fo0f03YYC5Eghbzi2dBwR0WC2e0hHgtb2TY1K6Uc%3D"
            "--no-hashcat",
        ],
    )

    cli.main()
    captured = capsys.readouterr()

    assert (
        not "Module: [Telerik_HashKey] Telerik Hash Key Signature Command: [hashcat -m 1450 -a 0 d63e" in captured.out
    )


def test_example_cli_hashcat_telerikhashkey_invalid(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "y1MPLyncErmvCfYRJDU72NLpEurHW6DfW=",
        ],
    )

    cli.main()
    captured = capsys.readouterr()

    assert not "Module: [Telerik_HashKey] Telerik Hash Key Signature Command" in captured.out


def test_example_cli_hashcat_telerikhashkey_invalid2(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "y1MPLyncErmvCfYRJDU72NLpEurHW6DfWxGJlfMGTH55vxb8V9m2vrkLDCkDm8%2F1PlVto%2FNCiuCR6ioagdVglig7fQjiAmlEMc7v5RWKx74f8v%2FXxMLhwqLzLkF5YbKbAJO7Rtmhqod1vAzINW2yo16gm7yNseksxi4dSIdiGKVIBuUYiA%2BJrhAlDYfmYrdSA0laWPsYjCyTLWwVipZnPb%2FmOJk%2BMnZC3WD2JLtJyiTTanExxyVsx8SKrKqighnPQCiCLEcBik9FoPNBElJLCIZqizM%2Fy8DYmvyC0bTH7rB6plNMYthd%2F%2FIr7DdRaoJJXHThVbra3BXybA7aiW4fRmuRD0vwiZUV%2BYWaClCgPpZ90YOfwXGlGpVhYfZJPNH%2BeCG2piS6oJPs2AjSUlQuzKn4uN%2F2OZYca8IP%2FkVE0jwU5EUq3uf%2FCmXJ8zNcgmcQXhhxejsn3dEygzw4zzyqR3LAnFQkk3BWtrhEmyNVjCL2y1MgsSTjClmTQzX0UicfQOBv4Vgg9E3EA6rqIdxj%2F7pq7N47X0f4wLByBROlgKj%2BhbuWNKAaZmXhjurQ5uu7WOGwKEmOpEnkTZzyoCFui8S6f3dtbrNw2rwGgo1oz8pD7gDXIXATx66hswuK7tfxjkMab%2FdXBQ3vQTSa5HYNpCWnJu3RunO3sb5OKT%2FtUe061%2BdO%2FcFDNwNiGXQvQ9yuY99w2BtNB7ZOazMl9vGG8lcL4s9yuSMdfG3tcgD4%2BrtHDEL7v0ub14dFxB8TOqY5JMRKdyd8D%2FP46%2BC3pWT61EYaddn3U548w%2FjHz1sXXx6b2lo7%2BYnG1DrRt%2Bk6%2BZt1Wa7UkfYC2b2n4OM2ro%2FqwHBU3FL0LOvBdXDDvlqqMSF4PtYUpO09GaE4TrzKlA%2FFN%2BZ9ibPj%2BmHyanK3GpdsR9S%2BavrhfnL%2BXrI26E5C2GPYOHTlR6u5dqvKJ71%2FCCF%2F%2FdYWbdzS5FVQ25WO6XREomBdvK2gP55Mh3byVUfoli%2F9pNkXytwYVo3yIIICReAuYdbteZN6%2BDJl4rJ5AKTbThpNk6co%2BG6Gl5rYKz1KqV80fqOF4TBlv6cm4kLvS%2FFk2JWD3L5kE8llElj9j4Bq7esFt1I%2Fvvo95guNdrBiiRfh2u7qENi1jfXYNlf1Npth8Vw11vztAq8jssrpMo3cVCKU2aTDkOQWvFBO6tN%2FvpYRCzRJHoy3e0sImQa3rN7wTNedxsadcL%2BHRXuYFFvQpcg5lfngY6lyVkjYPgxc5K4mRKZHDEXGWetFRl5af22wuNiEYmIERrh%2Fq25zBBCTfe2swAKb8hZLjoEywedeaQyZVveb4E0mTuMEQ259781fg727QoKnlu2m7Zh6gJINDk1a68Ap3t%2FCU1U8%2BL1haNZ5s7ywWl6vHM7dWvGffmqofBXoOKFhPdnSTc5xn6kgryFZJmnKwRyhOlPVCthRkgnANcLXEH1mtC1WQ8soXuVuMm6uAg44nwOt8BVZSNyJYYaEZCH4HPhtTo1F93W4PtXWJKIT6Mphf%2FWsIwJOKJzxgzCkCSwBB65kTL17LIQuyBqfmprPFtqEgTIRv4IFpJ8WuyeES08ti8QYwYM%2BPN2GZ1CTQu6kvlVlSBJxdTSvdf5IS%2BVje1pQqPJdYOIwwMTTpLfOno4qkHZVcM6OQnUNpvyIvRTuYJ5twYx8Rkty36P1%2BsKeaTMFgVWfMvpK5UNThjDxKMAsy7MgcMTxfZAeNi41gaQSbOFrdgtbkYMTALGiozY1NCcnHbXwr0qnHVKjVVDBuOPZeLL0lzBcm3hGjGYhOjrJLv4ZuRSLvCAe4UfHRhQcCjJd15vNpV8nbdcvEl2e7FUdoNlrPWxaglcEK0vu9WJxBzQVmzoNINhUvqnDZIrYOAGfzrDYrDAwMheLpr9OKHMvM2WHNHUecDK0781NXS%2FdoGGeheaTOe8DieXwcL%2FJlW2bBEwSUNDMuyD8RiukZHUQ4qcgDF%2FGLqUqkDesWIdQyj99wqKFfQNuwm41kCnzAN5uSt3IUiMiA7zsuDr%2BDg0Ro00K6Ap3wFLF1M3xtQobLnsRuCHZGwXSGxye%2Bmg8%2FxD%2BlTOs55IRwb3DDwi6eKdubRJMLN2o544FHYWL1UBAc%2BZcfz7vIqFeHUBMOc5htw%2BDPlXZRRnEzn%2F4qpV4ioEdZeQEv%2BhfXyUs9hF19JP%2BLJiWDJ3Ukdh7OdW2c6GtjOIiKeOcFcJi%2BYB8CP8ItWydzlt0IUaHufQ4ooPkkmmchlX7HV6%2BboKKGxaNWcOx%2BkAWPvP0IeYahPPff9PiSErWiFzc%2BOmFinwZu%2FXJsse%2BG1ndzbUJeMV%2B8jBdZtxiAewbNJxJZl%2Bgu6avfcLJqYjBfxFJ3%2B87%2B6AtI3JI93aCTEiLPVHMiMjsI6j8N1Nxn77BhCsXF3D9uXIqbqTsxp5je4xS4LHqrTTVnsKk3zqlc1PZvgVRGYVD3MRFUmFQfT%2Bnn9HhrDkuCfVdALWHnDOC%2BOOhHglnYm38GLFWA2Mo5VW4k3wM0ftFYVzaVVYYAEFmp8Uvup1sh6COO%252FZJJCSgBK1ZwjnLeWHM1j6Fo0f03YYC5Eghbzi2dBwR0WC2e0hHgtb2TY1K6Uc%3D",
        ],
    )

    cli.main()
    captured = capsys.readouterr()

    assert not "Module: [Telerik_HashKey] Telerik Hash Key Signature Command" in captured.out


def test_example_cli_hashcat_symfony_sha1(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=x3nyAneZB74G5S9L66d5ftJVNnK=",
        ],
    )

    cli.main()
    captured = capsys.readouterr()

    assert (
        "[Symfony_SignedURL] Symfony Signed URL Algorithm: [sha1] Command: [hashcat -m 150 -a 0 c779f202779907be06e52f4beba7797ed2553672:68747470733a2f2f6c6f63616c686f73742f5f667261676d656e743f5f706174683d5f636f6e74726f6c6c657225334473797374656d253236636f6d6d616e64253344696425323672657475726e5f76616c75652533446e756c6c --hex-salt  <dictionary_file>]"
        in captured.out
    )


def test_example_cli_hashcat_symfony_sha256(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=Xnsvx/yLVQaimEd1CfepgH0rEXr422JnRSn/uaCE3gS=",
        ],
    )

    cli.main()
    captured = capsys.readouterr()

    assert (
        "[Symfony_SignedURL] Symfony Signed URL Algorithm: [sha256] Command: [hashcat -m 1450 -a 0 5e7b2fc7fc8b5506a298477509f7a9807d2b117af8db62674529ffb9a084de04:68747470733a2f2f6c6f63616c686f73742f5f667261676d656e743f5f706174683d5f636f6e74726f6c6c657225334473797374656d253236636f6d6d616e64253344696425323672657475726e5f76616c75652533446e756c6c --hex-salt  <dictionary_file>]"
        in captured.out
    )


def test_example_cli_customsecrets_valid(monkeypatch, capsys):
    with tempfile.NamedTemporaryFile("w+t", delete=False) as f:
        f.write("fake123")
        f.flush()

    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.vKxsE0u-TrpoMQ5zmBv1_I-NXSgouq6iZJWMHbHSmgY",
            "-c",
            f.name,
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert "Secret: fake123" in captured.out


def test_example_cli_customsecrets_bad(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.vKxsE0u-TrpoMQ5zmBv1_I-NXSgouq6iZJWMHbHSmgY",
                "-c",
                "notexist.txt",
            ],
        )
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "The file notexist.txt does not exist!" in captured.out


def test_example_cli_customsecrets_directory(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.vKxsE0u-TrpoMQ5zmBv1_I-NXSgouq6iZJWMHbHSmgY",
                "-c",
                "/",
            ],
        )
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "is not a valid file!" in captured.out


def test_example_cli_customsecrets_toolarge(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        with tempfile.NamedTemporaryFile("w+t", delete=False) as f:
            f.write("x" * 1024 * 101)
            f.flush()
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.vKxsE0u-TrpoMQ5zmBv1_I-NXSgouq6iZJWMHbHSmgY",
                "-c",
                f.name,
            ],
        )
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "exceeds the maximum limit of 100KB!" in captured.out


def test_example_cli_customsecrets_urlmode(monkeypatch, capsys):
    base_vulnerable_page_aspnet_custom = """  
    <form method="post" action="./form.aspx" id="ctl00">
<div class="aspNetHidden">
<input type="hidden" name="__EVENTTARGET" id="__EVENTTARGET" value="" />
<input type="hidden" name="__EVENTARGUMENT" id="__EVENTARGUMENT" value="" />
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="TKwYYxGacVENJs9TmowhpXAlUIZFv+VssG/Q4XEwiH0BMFcwk9XhuUXiks0yXI5CKhrVAyWyhKRxTFiuH0BXuMys6b+LIEaHlImgxwypQvLu6SbX" />
</div>

<script type="text/javascript">
//<![CDATA[
var theForm = document.forms['ctl00'];
if (!theForm) {
    theForm = document.ctl00;
}
function __doPostBack(eventTarget, eventArgument) {
    if (!theForm.onsubmit || (theForm.onsubmit() != false)) {
        theForm.__EVENTTARGET.value = eventTarget;
        theForm.__EVENTARGUMENT.value = eventArgument;
        theForm.submit();
    }
}
//]]>
</script>


<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="DB68D79A" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
    <input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="X7iYTRnjyg5vH2cOQyBB0vKkTxDJ1/pZeXaadptYUR+jUbHHBJmetJAFrMeOQ1KEihcEnZdVsBQ/+aBTNZCx9c4+mm+BXPDX0np2CicTTDlacfpDMObK2AeZnNkBRKZ1gZk8yfuFV2mzlBPdExFtd7UfyFE=" />
</div>
    """

    with tempfile.NamedTemporaryFile("w+t", delete=False) as f:
        f.write(
            "0007EDC7D387A1C86422F769DDF45DE4C2FEEDBE21460EACD2F64D2B749A4159A497B6EF0B08252CB24C09DA993DA6F3524CE73B945BA531EB3C7DD4FFC0DFAA,4FCA412AF185EBF793CF3E79E1AF7098E1C3CEACD6B4C43B10252B69174A32AA"
        )
        f.flush()

        with requests_mock.Mocker() as m:
            m.get(
                f"http://example.com/vulnerableaspnet.html",
                status_code=200,
                text=base_vulnerable_page_aspnet_custom,
            )

            monkeypatch.setattr(
                "sys.argv",
                [
                    "python",
                    "--url",
                    "http://example.com/vulnerableaspnet.html",
                    "-c",
                    f.name,
                ],
            )
            cli.main()
            captured = capsys.readouterr()
            assert ("Known Secret Found!") in captured.out


def test_example_cli_color(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "junk"],
    )
    cli.main()
    captured = capsys.readouterr()
    assert "\x1b[32m\n" in captured.out


def test_example_cli_help(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr(
            "sys.argv",
            ["python", "-h"],
        )
        cli.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        assert "-h, --help" in captured.out
        assert "-nc, --no-color" in captured.out
        assert "-u URL, --url URL" in captured.out
        assert "-nh, --no-hashcat" in captured.out
        assert "-c CUSTOM_SECRETS, --custom-secrets CUSTOM_SECRETS" in captured.out
        assert "-p PROXY, --proxy PROXY" in captured.out
        assert "-a USER_AGENT, --user-agent USER_AGENT" in captured.out


def test_example_cli_dotnet45_url(monkeypatch, capsys):
    base_vulnerable_page_aspnet_dotnet45 = """
         <form method="post" action="./form.aspx" id="ctl00">
<div class="aspNetHidden">
<input type="hidden" name="__EVENTTARGET" id="__EVENTTARGET" value="" />
<input type="hidden" name="__EVENTARGUMENT" id="__EVENTARGUMENT" value="" />
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="4UzPhFpZZHLdlrT7oAv6gk6lNhI/f2n/4NkAGaaPUqQKk1wgM0XQndONaHukRvNo2hon4C0JTQLnGUEE6vg8nHYJqBgXiknpIqUcaQtFLf6Z2dAaBhIhRdWPz4PIF3wQ" />
</div>

<script type="text/javascript">
//<![CDATA[
var theForm = document.forms['ctl00'];
if (!theForm) {
    theForm = document.ctl00;
}
function __doPostBack(eventTarget, eventArgument) {
    if (!theForm.onsubmit || (theForm.onsubmit() != false)) {
        theForm.__EVENTTARGET.value = eventTarget;
        theForm.__EVENTARGUMENT.value = eventArgument;
        theForm.submit();
    }
}
//]]>
</script>


<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="DB68D79A" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
    <input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="1E02dhhNh5Elng+wXjTw6opqE8R/OdZddtcAL82qdZyIIRVQ8s97YQsJqECjV/OJQAu5ZySO9StoIr1X0S6NUbt/h4tCjnSvkgol4hnPb0DshxRmrMTYr/s+zlBn09dZFQ40HKbQeaRIxkww99sDGqnXdTyIOjVxrVW2FmKJSm8=" />
</div>
    """
    with requests_mock.Mocker() as m:
        m.get(
            f"http://172.16.25.128/form.aspx",
            status_code=200,
            text=base_vulnerable_page_aspnet_dotnet45,
        )

        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "--url",
                "http://172.16.25.128/form.aspx",
            ],
        )
        cli.main()
        captured = capsys.readouterr()
        assert ("Known Secret Found!") in captured.out
        assert ("Details: Mode [DOTNET45]") in captured.out


def test_example_cli_aspnetvstate_url(monkeypatch, capsys):
    base_vulnerable_page_aspnet_vstate = """
         <!doctype html>

<!--[if IE 9]> <html class="no-js lt-ie10" lang="en" xmlns:fb="http://ogp.me/ns/fb#"> <![endif]-->
<!--[if gt IE 9]><!--> <html class="no-js" lang="en" xmlns:fb="http://ogp.me/ns/fb#"> <!--<![endif]-->
<head> 
    <meta charset="utf-8" />
    <meta name="viewport" content="width=device-width, initial-scale=1.0" />
 
    <meta http-equiv="X-UA-Compatible" content="IE=edge" /> 

</head>
<body id="_body">
  <a id="page_top" name="page_top"></a>
    <form method="post" action="./default.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VSTATE" id="__VSTATE" value="H4sIAAAAAAAEAPvPyJ/Cz8ppZGpgaWpgZmmYAgAAmCJNEQAAAA==" />
<input type="hidden" name="__VSTATELENGTH" id="__VSTATELENGTH" value="52" />
<input type="hidden" name="__VSTATEHOST" id="__VSTATEHOST" value="02" />
<input type="hidden" name="__VSTATETIMESTAMP" id="__VSTATETIMESTAMP" value="7/29/2016 11:19:46 AM" />
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="" />
</div>   
<p>content</p>
</html>
    """
    with requests_mock.Mocker() as m:
        m.get(
            f"http://172.16.25.128/form.aspx",
            status_code=200,
            text=base_vulnerable_page_aspnet_vstate,
        )

        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "--url",
                "http://172.16.25.128/form.aspx",
            ],
        )
        cli.main()
        captured = capsys.readouterr()
        assert ("Known Secret Found!") in captured.out
        assert ("Product: H4sIAAAAAAAEAPvPyJ/Cz8ppZGpgaWpgZmmYAgAAmCJNEQAAAA==") in captured.out
        assert ("ASP.NET Compressed Vstate") in captured.out


def test_example_cli_dotnet45_manual(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "4UzPhFpZZHLdlrT7oAv6gk6lNhI/f2n/4NkAGaaPUqQKk1wgM0XQndONaHukRvNo2hon4C0JTQLnGUEE6vg8nHYJqBgXiknpIqUcaQtFLf6Z2dAaBhIhRdWPz4PIF3wQ",
            "http://172.16.25.128/form.aspx",
        ],
    )

    cli.main()
    captured = capsys.readouterr()
    assert ("Known Secret Found!") in captured.out
    assert ("Details: Mode [DOTNET45]") in captured.out


def test_example_cli_longinput(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "Ly8gp+FZKt9XsaxT5gZu41DDxO74k029z88gNBOru2jXW0g1Og+RUPdf2d8hGNTiofkD1VvmQTZAfeV+5qijOoD+SPzw6K72Y1H0sxfx5mFcfFtmqX7iN6Gq0fwLM+9PKQz88f+e7KImJqG1cz5KYhcrgT87c5Ayl03wEHvWwktTq9TcBJc4f1VnNHXVZgALGqQuETU8hYwZ1VilDmQ7J4pZbv+pvPUvzk+/e2oNeybso6TXqUrbT2Mz3k7yfe92q3pRjdxRlGxmkO9bPqNOtETlLPE5dDiZY11U9gr8BBD=",
                "AAAAAAAA",
                "BBBBBBBB",
                "CCCCCC",
            ],
        )
        cli.main()
        assert not exit_mock.called


def test_example_cli_dotnetbadgenerator(monkeypatch, capsys):
    with patch("sys.exit") as exit_mock:
        monkeypatch.setattr(
            "sys.argv",
            [
                "python",
                "Ly8gp+FZKt9XsaxT5gZu41DDxO74k029z88gNBOru2jXW0g1Og+RUPdf2d8hGNTiofkD1VvmQTZAfeV+5qijOoD+SPzw6K72Y1H0sxfx5mFcfFtmqX7iN6Gq0fwLM+9PKQz88f+e7KImJqG1cz5KYhcrgT87c5Ayl03wEHvWwktTq9TcBJc4f1VnNHXVZgALGqQuETU8hYwZ1VilDmQ7J4pZbv+pvPUvzk+/e2oNeybso6TXqUrbT2Mz3k7yfe92q3pRjdxRlGxmkO9bPqNOtETlLPE5dDiZY11U9gr8BBD=",
                "!!!!!!!!",
            ],
        )
        cli.main()
        assert not exit_mock.called


def test_examples_cli_colors_medlow(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ],
    )
    monkeypatch.setattr(
        Generic_JWT, "description", {"product": "JSON Web Token (JWT)", "secret": "HMAC/RSA Key", "severity": "MEDIUM"}
    )
    cli.main()
    captured = capsys.readouterr()
    assert "your-256-bit-secret" in captured.out
    print(captured.out)


def test_examples_cli_colors_info(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
            "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c",
        ],
    )
    monkeypatch.setattr(
        Generic_JWT, "description", {"product": "JSON Web Token (JWT)", "secret": "HMAC/RSA Key", "severity": "INFO"}
    )
    cli.main()
    captured = capsys.readouterr()
    assert "your-256-bit-secret" in captured.out
    print(captured.out)
