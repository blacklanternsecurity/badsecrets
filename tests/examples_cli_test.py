import os
import sys
import tempfile
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
        assert "Cryptographic Product Identified (no vulnerability)" in captured.out


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
        print()


def test_example_cli_color(monkeypatch, capsys):
    monkeypatch.setattr(
        "sys.argv",
        ["python", "junk"],
    )
    cli.main()
    captured = capsys.readouterr()
    assert "\x1b[32m\n" in captured.out
