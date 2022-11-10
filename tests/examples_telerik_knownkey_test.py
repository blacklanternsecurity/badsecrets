import os
import sys
import requests
import requests_mock
from mock import patch


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from examples import telerik_knownkey

from badsecrets import modules_loaded

Telerik_HashKey = modules_loaded["telerik_hashkey"]
Telerik_EncryptionKey = modules_loaded["telerik_encryptionkey"]


partial_dialog_page = """
<input type="hidden" name="__VIEWSTATEGENERATOR" id="__VIEWSTATEGENERATOR" value="D9FD575A" />
<input type="hidden" name="__EVENTVALIDATION" id="__EVENTVALIDATION" value="/wEdAAJspJIt1GVCOCk05y5PNKqHr1eUXYH2SY42AOoXP1wAYw2bbvWgGSKjsWouPBAT+yhhHBVc" /><input type="hidden" name="dialogParametersHolder" id="dialogParametersHolder" /><div style='text-align:center;'>Loading the dialog...</div>

<script type="text/javascript">
"""


def PBKDF2_found_key_matcher(request):
    if (
        request.body
        == "dialogParametersHolder=Ct3E%2FAXZ0ct05hNqzzSbCRVxte%2F%2BQBIVbVz21p21CqLSnQsGfzTjsiq%2FxoAQaaDuaafBKu8cNXMOGT5kJcE0snNDBVbQqvbQLEYa1cWQYr%2FL2tOMq8Rnuzq6F7HKpN2%2BUJzGeJxt25pqbTTLzS1VwSSsBRgS3Y13wCJNk24A%2BmI%3D"
    ):
        return True
    return False


def PBKDF2_found_key_matcher_negative(request):
    if (
        request.body
        == "dialogParametersHolder=Ct3E%2FAXZ0ct05hNqzzSbCRVxte%2F%2BQBIVbVz21p21CqLSnQsGfzTjsiq%2FxoAQaaDuaafBKu8cNXMOGT5kJcE0snNDBVbQqvbQLEYa1cWQYr%2FL2tOMq8Rnuzq6F7HKpN2%2BUJzGeJxt25pqbTTLzS1VwSSsBRgS3Y13wCJNk24A%2BmI%3D"
    ):
        return False
    return True


def PBKDF1_MS_found_key_matcher(request):
    if (
        request.body
        == "dialogParametersHolder=RW5hYmxlQXN5bmNVcGxvYWQsRmFsc2UsMyxUcnVlO0RlbGV0ZVBhdGhzLFRydWUsMCxabWs0ZFV4M1BUMHNabWs0ZFV4M1BUMD07RW5hYmxlRW1iZWRkZWRCYXNlU3R5bGVzaGVldCxGYWxzZSwzLFRydWU7UmVuZGVyTW9kZSxGYWxzZSwyLDI7VXBsb2FkUGF0aHMsVHJ1ZSwwLFptazRkVXgzUFQwc1ptazRkVXgzUFQwPTtTZWFyY2hQYXR0ZXJucyxUcnVlLDAsUzJrMGNRPT07RW5hYmxlRW1iZWRkZWRTa2lucyxGYWxzZSwzLFRydWU7TWF4VXBsb2FkRmlsZVNpemUsRmFsc2UsMSwyMDQ4MDA7TG9jYWxpemF0aW9uUGF0aCxGYWxzZSwwLDtGaWxlQnJvd3NlckNvbnRlbnRQcm92aWRlclR5cGVOYW1lLEZhbHNlLDAsO1ZpZXdQYXRocyxUcnVlLDAsWm1rNGRVeDNQVDBzWm1rNGRVeDNQVDA9O0lzU2tpblRvdWNoLEZhbHNlLDMsRmFsc2U7U2NyaXB0TWFuYWdlclByb3BlcnRpZXMsRmFsc2UsMCxDZ29LQ2taaGJITmxDakFLQ2dvSztFeHRlcm5hbERpYWxvZ3NQYXRoLEZhbHNlLDAsO0xhbmd1YWdlLEZhbHNlLDAsWlc0dFZWTT07VGVsZXJpay5EaWFsb2dEZWZpbml0aW9uLkRpYWxvZ1R5cGVOYW1lLEZhbHNlLDAsVkdWc1pYSnBheTVYWldJdVZVa3VSV1JwZEc5eUxrUnBZV3h2WjBOdmJuUnliMnh6TGtSdlkzVnRaVzUwVFdGdVlXZGxja1JwWVd4dlp5d2dWR1ZzWlhKcGF5NVhaV0l1VlVrc0lGWmxjbk5wYjI0OU1qQXhPQzR4TGpFeE55NDBOU3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHhNakZtWVdVM09ERTJOV0poTTJRMDtBbGxvd011bHRpcGxlU2VsZWN0aW9uLEZhbHNlLDMsRmFsc2U%3DL5sb9SKliKw%2Bw6w13%2FzMlFZ52mRvsWTpQO3uN4eQQ7k%3D"
        and request.body != "dialogParametersHolder=AAAA"
    ):
        return True
    return False


def PBKDF1_MS_found_key_matcher_negative(request):
    if (
        request.body
        == "dialogParametersHolder=RW5hYmxlQXN5bmNVcGxvYWQsRmFsc2UsMyxUcnVlO0RlbGV0ZVBhdGhzLFRydWUsMCxabWs0ZFV4M1BUMHNabWs0ZFV4M1BUMD07RW5hYmxlRW1iZWRkZWRCYXNlU3R5bGVzaGVldCxGYWxzZSwzLFRydWU7UmVuZGVyTW9kZSxGYWxzZSwyLDI7VXBsb2FkUGF0aHMsVHJ1ZSwwLFptazRkVXgzUFQwc1ptazRkVXgzUFQwPTtTZWFyY2hQYXR0ZXJucyxUcnVlLDAsUzJrMGNRPT07RW5hYmxlRW1iZWRkZWRTa2lucyxGYWxzZSwzLFRydWU7TWF4VXBsb2FkRmlsZVNpemUsRmFsc2UsMSwyMDQ4MDA7TG9jYWxpemF0aW9uUGF0aCxGYWxzZSwwLDtGaWxlQnJvd3NlckNvbnRlbnRQcm92aWRlclR5cGVOYW1lLEZhbHNlLDAsO1ZpZXdQYXRocyxUcnVlLDAsWm1rNGRVeDNQVDBzWm1rNGRVeDNQVDA9O0lzU2tpblRvdWNoLEZhbHNlLDMsRmFsc2U7U2NyaXB0TWFuYWdlclByb3BlcnRpZXMsRmFsc2UsMCxDZ29LQ2taaGJITmxDakFLQ2dvSztFeHRlcm5hbERpYWxvZ3NQYXRoLEZhbHNlLDAsO0xhbmd1YWdlLEZhbHNlLDAsWlc0dFZWTT07VGVsZXJpay5EaWFsb2dEZWZpbml0aW9uLkRpYWxvZ1R5cGVOYW1lLEZhbHNlLDAsVkdWc1pYSnBheTVYWldJdVZVa3VSV1JwZEc5eUxrUnBZV3h2WjBOdmJuUnliMnh6TGtSdlkzVnRaVzUwVFdGdVlXZGxja1JwWVd4dlp5d2dWR1ZzWlhKcGF5NVhaV0l1VlVrc0lGWmxjbk5wYjI0OU1qQXhPQzR4TGpFeE55NDBOU3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHhNakZtWVdVM09ERTJOV0poTTJRMDtBbGxvd011bHRpcGxlU2VsZWN0aW9uLEZhbHNlLDMsRmFsc2U%3DL5sb9SKliKw%2Bw6w13%2FzMlFZ52mRvsWTpQO3uN4eQQ7k%3D"
        and request.body != "dialogParametersHolder=AAAA"
    ):
        return False
    return True


def PBKDF1_MS_probe_matcher(request):
    if request.body == "dialogParametersHolder=AAAA":
        return True
    return False


def PBKDF1_MS_encryption_probe_matcher(request):
    if (
        request.body
        == "dialogParametersHolder=CaCbLSlA%2F3GG4AJY2Lrkw%2FYyoo9hsLMk7MDf5Ku5qk7ALj2MhWj%2BdiVwDJIpxdOfGYYKT%2BtFcvqOSZPRZZas0cgfM1xZtoJ0rDr0vHZCeKF2MchSI7T4s1rp%2F17FOhy0VFUWETHfD47ah6CDQGtptldvlYp5Iq5FSRMgJrFZ6V8%3D"
    ):
        return True
    return False


def test_examples_telerik_knownkey_argparsing(monkeypatch, capsys):

    # URL is required
    monkeypatch.setattr(
        "sys.argv",
        [
            "python",
        ],
    )
    with patch("sys.exit") as exit_mock:
        telerik_knownkey.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        print(captured)
        assert "the following arguments are required: -u/--url" in captured.err

    # Invalid URL is rejected

    monkeypatch.setattr(
        "sys.argv",
        ["python", "--url", "NOTaURL"],
    )
    with patch("sys.exit") as exit_mock:
        telerik_knownkey.main()
        assert exit_mock.called
        captured = capsys.readouterr()
        print(captured)
        assert "URL is not formatted correctly" in captured.err


def test_non_telerik_ui(monkeypatch, capsys):
    # Non-Telerk UI is detected
    with requests_mock.Mocker() as m:

        m.get(
            f"http://nottelerik.com/Telerik.Web.UI.DialogHandler.aspx",
            status_code=200,
            text="<html><p>Just a regular website</p></html>",
        )
        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://nottelerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        print(captured)
        assert "URL does not appear to be a Telerik UI DialogHandler" in captured.out


def test_url_not_up(monkeypatch, capsys):

    with requests_mock.Mocker() as m:
        # URL is down - handled correctly

        m.get(f"http://notreal.com/", exc=requests.exceptions.ConnectTimeout)
        monkeypatch.setattr("sys.argv", ["python", "--url", "http://notreal.com"])
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "Error connecting to URL" in captured.out


def test_full_run_PBKDF2(monkeypatch, capsys, mocker):

    mocker.patch.object(
        Telerik_EncryptionKey,
        "prepare_keylist",
        return_value=iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        ),
    )
    mocker.patch.object(
        Telerik_HashKey,
        "prepare_keylist",
        return_value=iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"]),
    )

    with requests_mock.Mocker() as m:
        # Basic Probe Detects Telerik
        m.get(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx", status_code=200, text=partial_dialog_page
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_found_key_matcher,
            status_code=200,
            text="Please refresh the editor page.</div><div>Error Message:Index was outside the bounds of the array",
        )

        m.post(
            f"http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF2_found_key_matcher_negative,
            status_code=200,
            text="<div>Error Message:Exception of type 'System.Exception' was thrown.</div>",
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF2.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "Target is a newer version of Telerik UI" in captured.out
        assert "Found Encryption key!" in captured.out
        assert "Found matching hashkey!" in captured.out
        assert (
            "%2Bv%2BRs6kf9lDUYnqqYk32Vg84DkpdruQOKGZRmm6RMkaYuxNmvg5Ca5cT%2F74qkOozHIKkG1ovf6XBsjlp4kgO8BJ6KgNcT78BExQZfT1mN5rMO8kcLDRdffFhFXmvAr0o%2F4x%2B9VoRJVaOyGLXk2nhX4OMP%2BjGP2C96Fa6LyfGWHlk1CF0E5mAPeQ6CLbycR88WU5hlmUUqniXC2UdeYd6HO9RFnISEnhq72MkdiEfvNsqAhr2XaCX2%2BQxFXfCLi2%2Fc%2Bn2NmUiFRdhCLutnVxILEnYiRmU5eHJdB2IOTtoc2XZ3NUdZJwrwOswjzCkk7LOwt2bddTvOXdfWtRrbNz1GDNXlPz1cXotgAhucxLLsknNDbeeboMbL%2Bk3tIeervi7oI%2FRQn6Ml3ffUAfcqHzwcZCEIlQXh%2FBEIKHAY9fGKs5JSdtRbREDI0rh9sH%2B0TmYv444WQyqYpa8pOqtxgC1QRRcsNQcVGFzpyNL2SfKSlLTZi5Q7bo8XMTfLG6jg60csDEDiJ7MwJBGIm1iYzt%2FP9JEKkZujTMyHoBI0RESNpux7BeanEIDsfDmfwbcUo%2B2%2BkoHkCE4zXWBdW3lqssk4GwSbc0mbmf3U79rsQdNEqIOL87evE1U6tGB5PuXgwAIj9sKdyffd8%2B%2Bz1CCffFovLM72ilbCmSljAJ%2BvVBfNpTiL7RV7j3XGygljzi4NL8yXJuCLYiNxmqPMdV8DahLed0jSe2mkU1u6rx4yS3dcWEfwMWjI5tVrfnbqtdInC8TliXkTZ919CtORoydmIXGL1u3kdBIq8EZcjRMa4bN4VTvUlbqeIe8p8QYEQwAi7vXiZCKS6R6dmJfQv%2B%2FqBHXWSFuglLYde019GNtNdGQfEnY31zT0Q86ieDYn4k55LbYq5lK8PNjg50gdJxn9fNtHTQ7frKP9vRM4cImRSvDBTATVw1PDzMqn0exo3xciYd5%2BXYAxlFoqwFMDz40w2xR4OWwoPsixpVjR2DYiqYiZrYytFMjziRCLQhkVuJpED8nB9CTlo05WBKN%2Bb4UBHBg%2FkCkHXJxNakIX7UbAjDcqzrNCGhjrgehCGA81uOf0Ppfswda0ZHMi8g9W6Y7uwWmn7Ux7xBMgDCUNIi8I3UvLGXdKnuB8YHX8TLC1z2%2Fm3ip797Pix1ya2sBsbw9KgOJ7PBT0u9W0puchi7zpT%2FzFe3V2HbV0ottDethRJhzaN856VgvjyNhbbmA04gnal%2Fq01j7LNWxEwTjNPyHORI1l9jztvYqItLei7YQYg2pFhmvuv0Od8DPfH40Y1m3mL2F2d%2FAy3ImzFI%2BKQB6mnGPvRcDIS1j7zPhciKRuLfu3dCxhIH7ojo83rhQus3SyXdyZ5cjkFKcG3H7WmBBMOFs2o5xjWcdLARevRbNbqwRfATerc5GuJxy1Qb8RJvOqhDcS5YAHyxVMx2QYU3yMhg0tCpy4wW%2FHsa33feu3NeBu9lRI38ojJNM7o6xYRoSTQu4tYadB4Yh4w60e%2FsttnecOC5plZrLw6BYN2piqvUD07BnO4yTvrpdBDXR%2BMFDchnFh2YK9JtvvtAISvpoSOJojOhwRKuafCwEJn0GB1dsdmOOxxaFHkPXQ7789eCxlTL5mkVf3ktzmHQdDyBxBlDLFWSjmFIBHp%2BPobFdDOmv5p6J3%2F%2FM23PMgGDLRMrj5LVZV3trGV1ZaJHEFIGmVwW0tN4426Q4rCdcxT4ju%2B%2FNhcq90e8crWw9nrF2rPTzW1YM7VqWWwhLj8MtVtGZFa3N%2FxdjEys8FWyT8VqAbC4IltuT5lW1ou1SXsA96h%2F9y3vzJADbm4Lv624OGnh6M%2FCmR930i6YeUlWWmMw1%2FpcZ5werHPm9v0OWulNmGfbNEoKuThz2sSCZ8FLNVToygv1VXPXnur4dJnoCkwBP2%2BQQ6%2FHlyFRXnrrGsiDJE3qtRXgECIhc2zpuC5HAz9FhIfC9VZZ5nxRMbhA6W%2Fz%2BjPpKLCBpmLqHJfy8%2B%2FausiZJv7d9yQ0SvHtq0y%2FSY04hOgZTJul6IIYpObD6s%2FqrGy2nMmY3%2FtEn830%2F%2BFERnXMeBsj%2B%2F5ZSewYe4xBnub1wvSbsA3qjoU5gq7fhDJOhmMQXkbas%2FRholsU9CNKNXpSyqVarqAc8XwaG34JmdG3wjQXd6p%2Bz2jZLew5ja8nelvVdIeN%2F9ejCNOoXcPApYLHyxslcrEuJrSHlAMR4FbonfrFhYYTR%2B8pdxRGYGpVUDxlIRvay5xE4PoiuJ4tF82nhc3kr%2FsJWj86DXt9uK%2FPIDMokhA3fOe%2BrL4lXuzGGv7ZJBaIgkKFliYYdW1axURY4MjnW8jyI5YRuG%2FTCW1ZjBBqDaym%2BmmAjjd2gWID9klXsEA5%2BY%2FjHaDfQJVwm5Bukzr7eZx1zc13OWRVKnbThUNdzOZAEP%2FPnFsxPqZkDZp53nSPzQTJeOldSMnV4YUInoXN%2BTOIcoHAssVkv4iplzNOy1HZT63jfJ1fr6uvhIRZvQ3OolQWlbsk0RoNnFOqXX7lGKYzq8EGCjuwApDN3zvcV16VeRE98GpQUx0qMXOGgo3RdaVqWEOCI4vqhcx3LtEoA8ZDkLqiHKzjqU0UTh92laKWefnBI2XeeKpwZ%2BJireCrS8yWZ%2BLQ2kRDnO2ezbcREVERW7Vvg100MxDKpDVha3oRWNcKtXxu8exJ3ndLi1dY9BNywI3TTnzoW8x0VzAMuyjIfHpvpk0jcqyI3%2BL3cMEU%3D"
            in captured.out
        )
        print(captured)


def test_full_run_PBKDF1_MS(monkeypatch, capsys, mocker):

    mocker.patch.object(
        Telerik_EncryptionKey,
        "prepare_keylist",
        return_value=iter(
            ["Not_The_Real_Encryption_Key", "d2a312d9-7af4-43de-be5a-ae717b46cea6", "another_fake_encryption_key"]
        ),
    )
    mocker.patch.object(
        Telerik_HashKey,
        "prepare_keylist",
        return_value=iter(["Not_The_Real_HaSh_Key", "YOUR_ENCRYPTION_KEY_TO_GO_HERE", "Y3t_anoth3r_f@k3_key"]),
    )

    with requests_mock.Mocker() as m:
        # Basic Probe Detects Telerik
        m.get(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            status_code=200,
            text=partial_dialog_page,
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_found_key_matcher,
            status_code=200,
            text="<div>Error Message:The input data is not a complete block.</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_found_key_matcher_negative,
            status_code=200,
            text="<div>Error Message:The hash is not valid!</div>",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_probe_matcher,
            status_code=200,
            text="Error Message:Length cannot be less than zero",
        )

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_encryption_probe_matcher,
            status_code=200,
            text="<div>Error Message:Index was outside the bounds of the array.</div>",
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "Target is a valid DialogHandler endpoint. Brute forcing Telerik Hash Key" in captured.out
        # assert "Found Encryption key!" in captured.out
        assert "Found matching hashkey! [YOUR_ENCRYPTION_KEY_TO_GO_HERE]" in captured.out
        assert "Found Encryption key! [d2a312d9-7af4-43de-be5a-ae717b46cea6]" in captured.out
        assert "Found Telerik Version! [2022.3.1109]" in captured.out
        assert (
            "0f%2FJzyPXo8HtM74q6lrNugswrOnUPgC%2BwcnF858TFdl3eT0OcFlzrksR5TwRwHCbxxauOfDqmzyzctchZ7wJLwT0Yxy%2BS7bBC1rySed%2Fu1Y%2FM5dsUKoFvCXkaWvez7%2Bx84KbnDrYEIcR6rQRGHZJIarLLJAlL6fllQaKtKURQtpsNhavafrLkZ4IXJqbT8KfPrVAwUIQDBLJZDQ%2B8XsuE1HKH%2FcekD3ulavKM%2Bi6Zq41KlyR5HdiReoAVvZPsC1HvmlK3BkQVxtpn4SGyCmaIQ8fmrg%2BPnLooENkptYV24H6jOaAbQa0snhaIIBx4KZHhy7YCbQgDN1djmTBr1%2FEc5HweAPqzrLlCL5MfPVlt7QV%2BMEUJuFwbk1wQ8m%2BB15cgICmpiSRSpTyNIYoLYifh6biaUcEMIAFCm60kSizGK2axnmIbvR8k7f1AZCPUFrPRQ05cSBKKbqhjhZ2GOGqeNv7VGzzVeLn0EtsIMd5tb9qWIPZB7vfa7m4R1otJW4BSZIPVfaa75PWjuQptnXyu9ETixRCN%2FDTw9vudVjm3ElfMwSR5SgRUXB5GBFsONXZiITYXs2mI9oRYGlRhPuCFqgJ%2B%2FXdhjeC4c%2Bpi7HaYuaCge3HRmjjWs7FHJCQssGFiGVokKrDZV64iUif1nujBceHxxy7tIQlCA3YCEaEEm%2F3f9cCSxpZ2G5FDLqSEL33ix11RrUxu%2FyrSqNqRMK8G%2BIoHNpWO4jp591fAdk8xqtqU6zrKg7oIpP87fDp3rywR0opcK57G3KBS%2BA0pEQFf4FPaamYtGZrZaiH1lsheZjfRAB9of6H4kkE2W5KbhK%2FuxZPJih9IFrgq3OPqrucrS1c4AUuFL1wAPZhAY7544IrU0YLBzhkBufNL%2FAi8RbDLl6%2BCxLBI372fh%2FglWPDdoh%2FJ1ST55YxMAUu0gB6OqKJxp%2FVo%2BVu5y8i6CfWZJC1MlDWuqMboglJAcPxGKCdx81TF1PK%2FcNMEUUY%2FFf09FbI9k1fnk7VrwwZu2xHVEdKMtS%2FS373xqpPi%2B5oi%2FLOmbR4JUf3FGjb3Ywuub54rTEmihoc3%2FvpAlStKG1dmTfebCnAg1shCUx0q8l%2FsGdf%2F6mIovoI3dZVA4vE%2FHFpMi5%2BqWSyFDywug6mI6fPZbmO%2BAS3szlYDGEzsDrGz8e6pbPVU6IK38yuDEXrPngvugtAtEySnLveLgq%2Bn6Ym5k7wpLX%2B87Qv2PRN9ZgXuOyyIaF95KNw5X8krVQccw1fpTD1GQg7SlHGfiirL7aW4UVmpDwPmJI1bY7FHDVXqZyiOA7ZzKnr4tlrX%2F%2B8FC8VWI8eRr20a%2FD3ScY05O%2FN4Mh0fp9rRlpEt9DE%2BfCBo2hQB1V%2B2ihorP8Si%2BDvUPIzm6L%2FheLaLxBIjFR9ebRQ%2FJje%2FlqRY2FAozKb4WpUNi2%2B8ytAr0r0Vum%2F%2BWlpM8XqsofekEZy0Tbc9U7aKkSC%2BrF7RwvBZQi8LCTNmFqSOIQjLAGgMdpuPy0N160opGwmDfHNnvdWI4CC8Ug60F2mEPVRjUoWsiAIoxMP0Fi2yBLFAqYwoDg%2FHlmNIx3mizWrlocJN5P6fioFv%2F80aUDlIGayHB0CYorNmeHBGyOzMp%2Fd00sYJQH3OR8oh2%2FbzlOLn04IKIbQtAZDqJw8DweqnR5ACuKzef4SPdEzMuneqcLi5bjN1444XyC2kYDhjjAYbMQ0xaafbK6Snv%2BrbaFvbosyy5okj3nwq%2FW8ze5aSqCl06nKOOzK%2BR4SrswS4XKW9y%2F2Inucc%2FOcLMC15DmpPR%2BzwN4kGWgFgeOYO6PZjEY1PFcLOJX7AbHPMRywHrsuMa5i%2F%2FGi7xu2RlcdVB%2Ftl272yp7wizxgpaiHe%2B483eF4Yb2z1GnuJBG6o%2FFBKFKp9FFPxK%2F4v3zvhJlIRBGXGjnWIRMALfNpJ6DMw%2FLHRtL3oEccFbSkeL3XrIoHdN6psyOnv6lBhDAAmfGK5bppY8F%2BKpZhl9SmhuPg8SsogyNnYPARkfV%2B7L%2Bdc2y6pi6cvY%2BNyGt42ibutFsB%2BpQdzghPnoc5mACGyUpZEra6T7HsZ3ZXvfGgRlU71WKCMOHXtDIDxXfftH%2F6554c6NH%2FWX8fwGrFTDC%2FIF70lK88lIEYJHhB3hGSTYK75FypgFAi756nTfAvQrL4gZG%2FAJXP6NY%2BpjMTDdhEoBywzCbSFi7G3wXgs7rbuAg9pKYGR3ueiRC81VlHhbpFL4F52SOPs2s4CByHIshaY6lan5Ps09ejKRpXulEzwDhGgpxRYlfm8gZrrEO5Ymq%2B83S%2BNcYTncsxPNri28CTKsQSdlat79jezczFv%2BfL%2FjZ%2FPtwvN2rAEC5yPaa%2F%2FfeO%2FQuMsvE0FjZv%2B0I568hJmGqzvJSL%2BL4y1Ywdh2s4B5he41GphKbREVY4RZwp56spSN9GNnNc1YjadwfFLWTxie1XdzpRiECROPRrAzXeHP%2FM1JLVVBaASvHcHt9Aqjnfw9TDl9viqHsgJixmi1aAMw33JCKqZDhZhl%2BOA%2FwRen540wPrvkOw%2BX1Jy13VApwMayJXNZpfCaYp2QVrEJjF%2BxQ7sKDe8FsbaSe5tXIl%2Fhnr2saqyigSHmotAuZoqcpCm1fJi%2FhD1ydOGVCTMhICz9HAbhyqbwCAGbIcDEdgsg8niZ1WAnGB2tlvj6VaPdeejwPadtzn5EahLvAKefthb9UapfMt39iJakLLhhD7IDQaXm%2FtwoQhlSU%3D"
            in captured.out
        )
        print(captured)


# PBKDF2 is correctly identified
#

# Successfully identify PBKDF1_MS known hash_key


# Successfully identify PBKDF2 known encryption and hash_key
