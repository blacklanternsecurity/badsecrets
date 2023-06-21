import pytest
import requests
import requests_mock
import badsecrets.errors

from badsecrets import modules_loaded

Django_SignedCookies = modules_loaded["django_signedcookies"]
ASPNET_Viewstate = modules_loaded["aspnet_viewstate"]
Flask_SignedCookies = modules_loaded["flask_signedcookies"]
Peoplesoft_PSToken = modules_loaded["peoplesoft_pstoken"]
Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]
Rails_SecretKeyBase = modules_loaded["rails_secretkeybase"]
Generic_JWT = modules_loaded["generic_jwt"]
Jsf_viewstate = modules_loaded["jsf_viewstate"]

aspnet_viewstate_sample = """
<!DOCTYPE html PUBLIC "-//W3C//DTD XHTML 1.0 Transitional//EN" "http://www.w3.org/TR/xhtml1/DTD/xhtml1-transitional.dtd">
<html xmlns="http://www.w3.org/1999/xhtml" >
<head><title>
    Untitled Page
</title></head>
<body>
    <form method="post" action="./query.aspx" id="form1">
<div class="aspNetHidden">
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="NezCOd0kSte/RO2Uc3awo5w6YZGASxqT0wUjljizUB1ykCF0/HtCaRs+bc9sEhzahl1U9SLqD8eO0d31aduWR+MnCHpBPbUlWZ+r9x6PC69lfgZX" />
</div>

<div class="aspNetHidden">

    <input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="EDD8C9AE" />
    <input type="hidden" name="__VIEWSTATEENCRYPTED" id="__VIEWSTATEENCRYPTED" value="" />
</div>
    <div>
        <span id="dft">test</span>
    </div>
    </form>
</body>
</html>
"""

telerik_dialogparameters_sample = """
Sys.Application.add_init(function() {
    $create(Telerik.Web.UI.RadDialogOpener, {"_dialogDefinitions":{"ImageManager":{"SerializedParameters":"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","Width":"770px","Height":"588px","Title":"Image Manager"}
"""


def test_carve_aspnet_viewstate():
    x = ASPNET_Viewstate()
    r = x.carve(aspnet_viewstate_sample)
    print(r)
    assert r
    assert (
        "0F97BAE23F6F36801ABDB5F145124E00A6F795A97093D778EE5CD24F35B78B6FC4C0D0D4420657689C4F321F8596B59E83F02E296E970C4DEAD2DFE226294979"
        in r[0]["secret"]
    )

    t = x.carve("INVALID")
    assert not t


def test_carve_telerik():
    x = Telerik_HashKey()
    r = x.carve(telerik_dialogparameters_sample)
    print(r)
    assert r
    assert r[0]["secret"] == "YOUR_ENCRYPTION_KEY_TO_GO_HERE"

    t = x.carve("INVALID")
    assert not t

    y = Telerik_EncryptionKey()
    r = y.carve(telerik_dialogparameters_sample)
    print(r)
    assert r
    assert r[0]["secret"] == "d2a312d9-7af4-43de-be5a-ae717b46cea6"


def test_carve_headers():
    with requests_mock.Mocker() as m:
        x = Generic_JWT()

        test_headers_vuln = {
            "auth_jwt": "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
        }
        m.get(
            f"http://vuln.headerscarve.badsecrets.com/",
            status_code=200,
            headers=test_headers_vuln,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://vuln.headerscarve.badsecrets.com/")
        r = x.carve(requests_response=res)

        print(r)
        assert len(r) > 0
        assert r[0]["type"] == "SecretFound"
        assert r[0]["secret"] == "1234"

        test_headers_notvuln = {
            "auth_jwt": "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCA"
        }
        m.get(
            f"http://notvuln.headerscarve.badsecrets.com/",
            status_code=200,
            headers=test_headers_notvuln,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://notvuln.headerscarve.badsecrets.com/")
        r = x.carve(requests_response=res)

        print(r)
        assert len(r) > 0
        assert r[0]["type"] == "IdentifyOnly"


def test_carve_cookies():
    with requests_mock.Mocker() as m:
        # peoplesoft_pstoken
        x = Peoplesoft_PSToken()

        cookies = {
            "random-cookie": "useless_data",
            "PS_TOKEN": "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABT5mYioG/i325GsBHHNyDIM+9yf1GgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
            "random-cookie2": "useless_data2",
        }

        m.get(
            f"http://ps_token.badsecrets.com/",
            status_code=200,
            cookies=cookies,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://ps_token.badsecrets.com/")
        r = x.carve(requests_response=res)
        print(r)
        assert len(r) > 0
        assert r[0]["secret"] == "Username: badsecrets Password: password"

        # django_signedcookies
        x = Django_SignedCookies()

        cookies = {
            "random-cookie": "useless_data",
            "django_session": ".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCIRIpvaTZRQMM3-UypscEN57ECtXis",
            "random-cookie2": "useless_data2",
        }

        m.get(
            f"http://django.badsecrets.com/",
            status_code=200,
            cookies=cookies,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://django.badsecrets.com/")
        r = x.carve(requests_response=res)
        print(r)
        assert len(r) > 0
        assert r[0]["details"]["_auth_user_hash"] == "d86e01d10e66d199e5f5cb92e0c3d9f4a03140068183b5c9387232c4d32cff4e"

        # flash_signedcookies
        x = Flask_SignedCookies()

        cookies = {
            "random-cookie": "useless_data",
            "flask_session": "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA",
            "random-cookie2": "useless_data2",
        }

        m.get(
            f"http://flask.badsecrets.com/",
            status_code=200,
            cookies=cookies,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://flask.badsecrets.com/")
        r = x.carve(requests_response=res)
        print(r)
        assert len(r) > 0
        assert r[0]["secret"] == "CHANGEME"

        # rails_secretkeybase
        x = Rails_SecretKeyBase()

        cookies = {
            "random-cookie": "useless_data",
            "rails_session": "eyJfcmFpbHMiOnsibWVzc2FnZSI6IklraGxiR3h2TENCSklHRnRJR0VnYzJsbmJtVmtJSEpoYVd4ek5pQkRiMjlyYVdVaElnPT0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5zaWduZWQifX0%3D--eb1ea3ddc55deb16ffc58ac165edfbb554067edc",
            "random-cookie2": "useless_data2",
        }

        m.get(
            f"http://rails.badsecrets.com/",
            status_code=200,
            cookies=cookies,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://rails.badsecrets.com/")
        r = x.carve(requests_response=res)
        print(r)
        assert len(r) > 0
        assert (
            r[0]["secret"]
            == "4698bc5d99f3103ca76ab57f28a6b8f75f5f0768aab4f2e3f3743383594ad91f43e78c1b86138602f5859a811927698180ebfae7c490333f37b87521ca5a5f8c"
        )

        # generic_jwt
        x = Generic_JWT()

        cookies = {
            "random-cookie": "useless_data",
            "auth": "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo",
            "random-cookie2": "useless_data2",
        }

        m.get(
            f"http://hmac.generic-jwt.badsecrets.com/",
            status_code=200,
            cookies=cookies,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://hmac.generic-jwt.badsecrets.com/")
        r = x.carve(requests_response=res)
        print(r)
        assert len(r) > 0
        assert r[0]["secret"] == "1234"

        cookies = {
            "random-cookie": "useless_data",
            "auth": "eyJhbGciOiJSUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.VY5gbfqc1nrTMz7oCFvFBZtHE_gb97dWBAsOG9NJeeXJhASEBe2srxVqbWw1HTGcyZc1oxzJU6o-fpPAEpNO4QhFEJNZbWYJBLMtggiu_MKBEHGHgrAOE9gtH2qUKZ6zMWq5hO3JA0QuIWKE3g342C-beBNoLJ8ph02yrrqYuCWg2smExg6wL_LK0gnpsNLBXRcJ2dYSlEn9tz9Aim5TioZVJZK1DVtBX8k4xA0k47i9DGNwII7R9SU2cqqDOXBd7oo8AYwGP1U4kWtzeTKBBIAEjwGh11yKIMkZrL1SkctWEY1ogFlxBG9dWn0BcrYCVJaIxTSMCGmpjRSUKPnkTg",
            "random-cookie2": "useless_data2",
        }

        m.get(
            f"http://rsa.generic-jwt.badsecrets.com/",
            status_code=200,
            cookies=cookies,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://rsa.generic-jwt.badsecrets.com/")
        r = x.carve(requests_response=res)
        print(r)
        assert len(r) > 0
        assert r[0]["secret"] == "Private key Name: 1"


def test_multiple_results():
    with requests_mock.Mocker() as m:
        # rails_secretkeybase
        x = Rails_SecretKeyBase()

        cookies = {
            "random-cookie": "useless_data",
            "rails_session": "eyJfcmFpbHMiOnsibWVzc2FnZSI6IklraGxiR3h2TENCSklHRnRJR0VnYzJsbmJtVmtJSEpoYVd4ek5pQkRiMjlyYVdVaElnPT0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5zaWduZWQifX0%3D--eb1ea3ddc55deb16ffc58ac165edfbb554067edc",
            "random-cookie2": "useless_data2",
            "rails_session_2": "fuP54C4UxMudlZRR6j25zJfkevHVZ6IJR6Hp1B3rW6sAW5Aqc1j2Ri0XgcyLRvuSNVLwzq6cqeWlVhwU13xMS8scjU%2BSGGi%2Bta4jQU7oYujKdxynHSEiYOmeNFW4onXoF3KLlmr7ODmtIaHm1zIEP11TT%2FmRqZuxxecjz0VIxUDhvHYEFQ%3D%3D--ZclUs5zZFu3JPKnx--%2Fc0Q4ufTHqqmMxoin0mRtQ%3D%3D",
        }

        m.get(
            f"http://rails.badsecrets.com/",
            status_code=200,
            cookies=cookies,
            text="<html><p>Some HTML Content</p></html>",
        )

        res = requests.get("http://rails.badsecrets.com/")
        r = x.carve(requests_response=res)
        print(r)
        assert len(r) == 2
        assert (
            r[0]["secret"]
            == "4698bc5d99f3103ca76ab57f28a6b8f75f5f0768aab4f2e3f3743383594ad91f43e78c1b86138602f5859a811927698180ebfae7c490333f37b87521ca5a5f8c"
        )
        assert (
            r[1]["secret"]
            == "4698bc5d99f3103ca76ab57f28a6b8f75f5f0768aab4f2e3f3743383594ad91f43e78c1b86138602f5859a811927698180ebfae7c490333f37b87521ca5a5f8c"
        )


def test_generic_jwt_body_carve():
    jwt_html = """
    <html>
<head>
<title>Test</title>
</head>
<body>
<p>Some text</p>
<div class="JWT_IN_PAGE">
<p>eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo</p>
</div>
</body>
</html>
"""

    with requests_mock.Mocker() as m:
        x = Generic_JWT()
        m.get(
            f"http://body.generic-jwt.badsecrets.com/",
            status_code=200,
            text=jwt_html,
        )
        res = requests.get("http://body.generic-jwt.badsecrets.com/")
        r = x.carve(requests_response=res)
        assert r
        assert r[0]["secret"] == "1234"
        assert r[0]["type"] == "SecretFound"


def test_carve_negativeidentify_body():
    x = Jsf_viewstate()
    identify_html = """
    <html>
    <head>
    </head>
    <body>
    <p><input type="hidden" name="javax.faces.ViewState" id="j_id__v_0:javax.faces.ViewState:1" value="Ly8gp+FZKt9XsaxT5gZu41DDxO74k029z88gNBOru2jXW0g1Og+RUPdf2d8hGNTiofkD1VvmQTZAfeV+5qijOoD+SPzw6K72Y1H0sxfx5mFcfFtmqX7iN6Gq0fwLM+9PKQz88f+e7KImJqG1cz5KYhcrgT87c5Ayl03wEHvWwktTq9TcBJc4f1VnNHXVZgALGqQuETU8hYwZ1VilDmQ7J4pZbv+pvPUvzk+/e2oNeybso6TXqUrbT2Mz3k7yfe92q3pRjdxRlGxmkO9bPqNOtETlLPE5dDiZYo1U9gr8BBD=" autocomplete="off" />
    </body>
    <html>
    """

    with requests_mock.Mocker() as m:
        m.get(
            f"http://negativeidentify.jsf_viewstate.badsecrets.com/",
            status_code=200,
            text=identify_html,
        )
        res = requests.get("http://negativeidentify.jsf_viewstate.badsecrets.com/")
        r = x.carve(requests_response=res)
        assert r
        assert r[0]["type"] == "IdentifyOnly"


def test_carve_negative():
    x = Generic_JWT()
    useless_html = """
    <html>
    <head>
    </head>
    <body>
    <p>This is just some text.</p>
    </body>
    <html>
    """

    with requests_mock.Mocker() as m:
        m.get(
            f"http://negative.generic-jwt.badsecrets.com/",
            status_code=200,
            text=useless_html,
        )
        res = requests.get("http://negative.generic-jwt.badsecrets.com/")
        r = x.carve(requests_response=res)
        assert not r

    x = Generic_JWT()
    useless_html = """
    <html>
    <head>
    </head>
    <body>
    <p>eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJAAAA</p>
    </body>
    <html>
    """

    with requests_mock.Mocker() as m:
        m.get(
            f"http://identifyonly.generic-jwt.badsecrets.com/",
            status_code=200,
            text=useless_html,
        )
        res = requests.get("http://identifyonly.generic-jwt.badsecrets.com/")
        r = x.carve(requests_response=res)
        assert r
        assert r[0]["type"] == "IdentifyOnly"


def test_invalid_carve_args():
    useless_html = """
    <html>
    <head>
    </head>
    <body>
    <p>This is just some text.</p>
    </body>
    <html>
    """
    cookies = {"random-cookie": "useless_data"}
    x = Generic_JWT()
    with requests_mock.Mocker() as m:
        m.get(
            f"http://invalidcarveargs.generic-jwt.badsecrets.com/", status_code=200, text=useless_html, cookies=cookies
        )
        res = requests.get("http://invalidcarveargs.generic-jwt.badsecrets.com/")

    with pytest.raises(badsecrets.errors.CarveException):
        x.carve(body=useless_html, cookies=cookies, requests_response=res)

    with pytest.raises(badsecrets.errors.CarveException):
        x.carve(body=useless_html, cookies="cookies")

    with pytest.raises(badsecrets.errors.CarveException):
        x.carve(body={"dict": "dict"})

    with pytest.raises(badsecrets.errors.CarveException):
        x.carve(requests_response=("AAAA"))

    with pytest.raises(badsecrets.errors.CarveException):
        x.carve()


def test_cookie_dict():
    useless_html = """
    <html>
    <head>
    </head>
    <body>
    <p>This is just some text.</p>
    </body>
    <html>
    """
    x = Generic_JWT()
    r = x.carve(
        body=useless_html,
        cookies={
            "arbitrary": "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo"
        },
    )
    assert r
    assert r[0]["secret"] == "1234"
    assert r[0]["type"] == "SecretFound"
