import requests
import requests_mock

from badsecrets.base import check_all_modules, carve_all_modules

tests = [
    "yJrdyJV6tkmHLII2uDq1Sl509UeDg9xGI4u3tb6dm9BQS4wD08KTkyXKST4PeQs00giqSA==",
    "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA",
    "vpwClvnLODIx9te2vO%2F4e06KzbKkjtwmNnMx09D1Dmau0dPliYzgpqB9MnEqhPNe3fWemQyH25eLULJi8KiYHXeHvjfS1TZAL2o5Gku1gJbLuqusRXZQYTNlU2Aq4twXO0o0CgVUTfknU89iw0ceyaKjSteOhxGvaE3VEDfiKDd8%2B9j9vD3qso0mLMqn%2Btxirc%2FkIq5oBbzOCgMrJjkaPMa2SJpc5QI2amffBJ%2BsAN25VH%2BwabEJXrjRy%2B8NlYCoUQQKrI%2BEzRSdBsiMOxQTD4vz2TCjSKrK5JEeFMTyE7J39MhXFG38Bq%2FZMDO%2FETHHdsBtTTkqzJ2odVArcOzrce3Kt2%2FqgTUPW%2BCjFtkSNmh%2FzlB9BhbxB1kJt1NkNsjywvP9j7PvNoOBJsa8OwpEyrPTT3Gm%2BfhDwtjvwpvN7l7oIfbcERGExAFrAMENOOt4WGlYhF%2F8c9NcDv0Bv3YJrJoGq0rRurXSh9kcwum9nB%2FGWcjPikqTDm6p3Z48hEnQCVuJNkwJwIKEsYxJqCL95IEdX3PzR81zf36uXPlEa3YdeAgM1RD8YGlwlIXnrLhvMbRvQW0W9eoPzE%2FjP68JGUIZc1TwTQusIWjnuVubFTEUMDLfDNk12tMwM9mfnwT8lWFTMjv9pF70W5OtO7gVN%2BOmCxqAuQmScRVExNds%2FF%2FPli4oxRKfgI7FhAaC%2Fu1DopZ6vvBdUq1pBQE66fQ9SnxRTmIClCpULUhNO90ULTpUi9ga2UtBCTzI8z6Sb6qyQ52NopNZMFdrn9orzdP8oqFeyYpF%2BQEtbp%2F5AMENkFkWUxHZn8NoSlO8P6G6ubSyDdY4QJPaFS4FxNhhm85WlZC9xfEZ1AGSSBOu9JJVYiKxXnL1yYLqrlWp5mfBHZeUBwEa%2FMjGxZEVYDhXo4PiU0jxN7fYmjaobp3DSgA5H3BcFuNG5d8CUnOlQcEie5b%2BUHOpI9zAk7qcuEUXbaZ5Mvh0t2jXCRALRKYDyBdbHlWAFo10dTIM6L3aSTM5uEz9%2FalXLXoWlMo7dTDpuO5bBfTq7YkoPExL3g3JJX47UhuLq85i3%2Bzxfvd7r%2Fmid69kbD3PnX%2Bj0QxaiShhyOZg6jl1HMeRRXvZap3FPCIfxbCf7j2TRqB5gYefBIIdGYjrdiL6HS8SbjXcROMwh2Fxnt505X4jmkmDcGmneU3z%2B84TSSFewcSpxGEGvHVkkU4OaT6vyFwsxCmdrR187tQZ7gn3ZkAiTps%2FfOPcL5QWXja06Z%2FHT3zboq6Hj9v9NBHzpC1eAK0YN8r4V2UMI3P0%2FsIPQYXhovoeLjJwq6snKZTX37ulE1mbS1uOY%2BZrvFYbLN5DdNL%2B%2Bl%2F%2BcWIpc0RSYBLo19xHpKeoeLjU2sxaYzK%2B92D4zKANdPPvsHPqJD1Y%2FBwCL%2FfZKaJfRK9Bj09ez1Z1ixTEKjIRCwuxijnJGq33faZchbwpMPpTfv43jEriGwXwoqOo9Mbj9ggPAil7O81XZxNT4vv4RoxXTN93V100rt3ClXauL%2BlNID%2BseN2CEZZqnygpTDf2an%2FVsmJGJJcc0goW3l43mhx2U79zeuT94cFPGpvITEbMtjmuNsUbOBuw6nqm5rAs%2FxjIsDRqfQxGQWfS0kuwuU6RRmiME2Ps0NrBENIbZzcbgw6%2BRIwClWkvEG%2BK%2FPdcAdfmRkAPWUNadxnhjeU2jNnzI1yYNIOhziUBPxgFEcAT45E7rWvf8ghT08HZvphzytPmD%2FxuvJaDdRgb6a30TjSpa7i%2BEHkIMxM5eH1kiwhN6xkTcBsJ87epGdFRWKhTGKYwCbaYid1nRs7%2BvQEU7MRYghok8KMTueELipohm3otuKo8V4a7w4TgTSBvPE%2BLPLJRwhM8KcjGlcpzF1NowRo6zeJJhbdPpouUH2NJzDcp7P4uUuUB9Cxt9B986My6zDnz1eyBvRMzj7TABfmfPFPoY3RfzBUzDm%2FA9lOGsM6d9WZj2CH0WxqiLDGmP1Ts9DWX%2FsYyqEGK5R1Xpnp7kRIarPtYliecp50ZIH6nqSkoCBllMCCE6JN%2BdoXobTpulALdmQV0%2Bppv%2FAjzIJrTHgX7jwRGEAeRgAxTomtemmIaH5NtV7xt8XS%2BqwghdJl1D06%2FWhpMtJ1%2FoQGoJ0%2F7ChYyefyAfsiQNWsO66UNVyl71RVPwATnbRO5K5mtxn0M2wuXXpAARNh6pQTcVX%2FTJ4jmosyKwhI6I870NEOsSaWlKVyOdb97C3Bt0pvzq8BagV5FMsNtJKmqIIM0HRkMkalIyfow9iS%2B5xGN5eKM8NE4E6hO4CvmpG%2BH2xFHTSNzloV0FjLdDmj5UfMjhUuEb3rkKK1bGAVaaherp6Ai6N4YJQzh%2FDdpo6al95EZN2OYolzxitgDgsWVGhMvddyQTwnRqRY04hdVJTwdhi4TiCPbLJ1Wcty2ozy6VDs4w77EOAQ5JnxUmDVPA3vXmADJZR0hIJEsuxXfYg%2BRIdV4fzGunV4%2B9jpiyM9G11iiesURK82o%2BdcG7FaCkkun2K2bvD6qGcL61uhoxNeLVpAxjrRjaEBrXsexZ9rExpMlFD8e3NM%2B0K0LQJvdEvpWYS5UTG9cAbNAzBs%3DpDsPXFGf2lEMcyGaK1ouARHUfqU0fzkeVwjXU9ORI%2Fs%3D",
    "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABRhZGwcBykRPNQv++kTK0KePPqVVGgAAAAFAFNkYXRhXHicHYc7DkBQAATnIUqVa3jxLRzApxJBrxA18bmdw1l2k9nZG/Bcxxjt4/An3NnYOVlZOMRL7ld0NAQ9IzUTMy0DeUpMqkYkso+ZGFNiKbRW//Pyb0Guzwtozw4Q",
    ".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCIRIpvaTZRQMM3-UypscEN57ECtXis",
    "dUEvRldLekFNcklGZ3ZSbU1XaHJ0ZGxsLzhYTHlNTW43T3BVN05kZXE3WUhQOVVKbVA3Rm5WaSs5eG5QQ1VIRVBzeDFNTnNpZ0xCM1FKbzFZTEJISzhaNzFmVGYzME0waDFURVpCYm5TQlJFRmRFclYzNUZhR3VuN29PMmlkVHBrRi8wb3AwZWgvWmxObkFOYnpkeHR1YWpWZ3lnN0Y4ZW9xSk9LNVlQd0U4MmFsbWtLZUI5VzkzRkM4YXBFWXBWLS15L00xME1nVFp2ZTlmUWcxZVlpelpnPT0=--7efe7919a5210cfd1ac4c6228e3ff82c0600d841",
    "eyJhbGciOiJIUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.ovqRikAo_0kKJ0GVrAwQlezymxrLGjcEiW_s3UJMMCo",
    "owOnMokk%2F4N7IMo6gznRP56OYIT34dZ1Bh0KBbXlFgztgiNNEBYrgWRYDBkDlX8BIFYBcBztC3NMwoT%2FtNF%2Ff2nCsA37ORIgfBem1foENqumZvmcTpQuoiXXbMWW8oDjs270y6LDAmHhCRsl4Itox4NSBwDgMIOsoMhNrMigV7o7jlgU16L3ezISSmVqFektKmu9qATIXme63u4IKk9UL%2BGP%2Fk3NPv9MsTEVH1wMEf4MApH5KfWBX96TRIc9nlp3IE5BEWNMvI1Gd%2BWXbY5cSY%2Buey2mXQ%2BAFuXAernruJDm%2BxK8ZZ09TNsn5UREutvNtFRrePA8tz3r7p14yG756E0vrU7uBz5TQlTPNUeN3shdxlMK5Qzw1EqxRZmjhaRpMN0YZgmjIpzFgrTnT0%2Bo0f6keaL8Z9TY8vJN8%2BEUPoq%2F7AJiHKm1C8GNc3woVzs5mJKZxMUP398HwGTDv9KSwwkSpHeXFsZofbaWyG0WuNldHNzM%2FgyWMsnGxY6S086%2F477xEQkWdWG5UE%2FowesockebyTTEn3%2B%2FqiVy%2FIOxXvMpvrLel5nVY%2FSouHp5n2URRyRsfo%2B%2BOXJZo7yxKQoYBSSkmxdehJqKJmbgxNp5Ew8m89xAS5g99Hzzg382%2BxFp8yoDVZMOiTEuw0J%2B4G6KizqRW9cis%2FELd0aDE1V7TUuJnFrX%2BlCLOiv100tKpeJ0ePMOYrmvSn0wx7JhswNuj%2BgdKqvCnMSLakGWiOHxu5m9Qqdm3s5sk7nsaxMkh8IqV%2BSzB9A2K1kYEUlY40II1Wun67OSdLlYfdCFQk4ED0N%2BV4kES%2F1xpGiaPhxjboFiiV%2BkvCyJfkuotYuN%2B42CqFyAyepXPA%2BR5jVSThT6OIN2n1UahUnrD%2BwKKGMA9QpVPTSiGLen2KSnJtXISbrl2%2BA2AnQNH%2BMEwYVNjseM0%2BAosbgVfNde2ukMyugo%2FRfrRM27cbdVlE0ms0uXhlgKAYJ2ZN54w1tPWhpGxvZtB0keWpZan0YPh8CBgzsAIMa04HMYLCtgUTqxKqANoKXSy7VIJUzg3fl%2F2WUELjpXK9gRcgexNWDNB1E0rHd9PUo0PvpB4fxSrRpb1LRryipqsuoJ8mrpOVrVMvjracBvtoykK3GrN%2FDUlXkSG%2FAeBQN7HwDJ9QPi3AtEOohp78Op3nmbItXo7IJUSjzBNzUYR8YPj6Ud7Fje9LZSwMBngvgx%2BOKy6HsV4ofOAU2%2FK1%2BfxI0KkCeoSso9NJHWgBD7ijfXUa1Hrc%2FuNU3mTlSSVp3VStQrJbQCkr4paaHYWeeO4pRZCDSBNUzs9qq3TDePwpEQc4QROrw5htdniRk26lFIFm%2Fzk2nC77Pg%2BrkRC1W%2BlRv0lyXsmXVBCe8F1szpWXHCxHNAJwKH%2FBb%2BV1k6AXFXVWPW5vADbXUvRu0s6KLaqu6a0KCB7dt3K2Ni%2FI6O%2FmISYXzknbMrwwakNfajbRF2ibodgR9R9xvoCoCXa3ka7%2Fejr%2BmsZ2HvPKUAffd2fNIWCQrejfpuIoOWiYx6ufN8E41HetCbYfvsI6JQfPOEdOYWI2px%2BLdfO3Nybq99%2BRSQOhjNZakBP54ozlCUfwgpLOmTBwsswZexv1RK5MIi8%2FWtjlJ%2FKjkYxdkFUlwggGS2xDwzcyl2%2FakNCQ5YmxjU8cRY7jZQRMo%2F8uTw5qa2MNZPaQGI18uRgr0i%2FTX3t57fJYCpMLXSaUKIdO7O%2FCQhIyGTS6KrPN%2B3%2FgUb%2BPQ1viGhpnWfGEYF9vhIlK57z8G8G82UQ3DpttD7M8mQ0KsmCOq75ECx9CWrWGk51vADlm%2BLEZ5oWjVMs%2FThki40B7tL7gzFrBuQksWXYeubMzZfFo4ZQ49di4wupHG5kRsyL2fJUzgpaLDP%2BSe6%2FjCnc52C7lZ3Ls0cHJVf9HRwDNXWM%2B4h8donNy5637QWK%2BV7mlH%2FL4xBZCfU9l6sIz%2FWHMtRaQprEem6a%2FRwPRDBiP65I2EwZLKGY8I%2F1uXJncwC8egLu82JY9maweI0VmJSmRcTf0evxqqe7vc9MqpsUlpSVNh4bFnxVIo5E4PGX70kVaTFe0vu1YdGKmFX5PLvkmWIf%2FnwfgPMqYsa0%2F09trboJ5LGDEQRXSBb7ldG%2FwLdOiqocYKAb91SMpn1fXVPBgkPM27QZxHnSAmWVbJR2%2FIhO%2BIVNzkgFAJlptiEPPPTxuBh%2BTT7CaIQE3oZbbJeQKvRkrt4bawTCOzciU%2F1zFGxubTJTSyInjQ8%2F1tVo7KjnxPKqGSfwZQN%2FeWL6R%2FpvCb%2BE6D4pdyczoJRUWsSNXNnA7QrdjgGNWhyOMiKvkDf3RD4mrXbul18WYVTsLyp0hvQsbdwBWOh7VlwfrWdy%2BklsttFi%2B%2BadKR7DbwjLTcxvdNpTx1WJhXROR8jwW26VEYSXPVqWnYvfyZo4DojKHMSDMbAakbuSJdkGP1d5w0AYbKlAcVQOqp9hbAvfwwLy4ErdIsOg0YEeCcnQVRAXwaCI9JvWWmM%2FzYJzE3X45A6lU9Pe7TAbft810MYh7lmV6Keb5HI6qXFiD%2B8khBZqi%2FsK6485k0a86aWLxOb4Eqnoc41x%2BYPv5CWfvP6cebsENo%3D%2BIUg0f64C4y77N4FZ6C82m5wMpvDQIHqx0ZFIHLhwMg%3D",
    "8H61sylBH/Ad3thZCGDVLyaso2g499GnjAuqpNapesoJgoo5Zk3nxDqXoWfRDwzmKk6eDLTyWViTRTdnr8Su7+XzW6MMAcZo+Fa7UwdfE4pKJ2+z6OYK58l+/93LHZmgVUF5dqI3G8mLr3uI",
    "H4sIAAAAAAAAAAG4BEf7SqmRq5Y9DfCIR9QLZ9wfMXuwWMtbz4CYqd0%2FCCMNXbRgEOJmkCbpKBJXQ%2BAz78OO%2FufCpa1k1nqcEgNxRzRnKKNVBBPMov%2FE%2BXFqh%2Bb5KZLhJvXicwGSIuVshN1XYpSRzKrosUB0ykN8j9hA90IA5AulHsXIofHj07FlFC%2BTbQqVZ7jKeHDurUkVhf8WQ1up%2BVO9KZwQU6WZzsF5y6AkidThF411avCLTxGAtIC7uZBnzMLL4duUf7YtdIDHt4UWGsXCI7ItciWv4Dzk9w5bKeWRRLp1W1pbniEQY01lTulTZBYPuLtna6pB0I3EJ5bV4c3Gktdd1YAVQcBQ2Yy5TW92YEclM99vW9mwu6xD8ZRYJNIb622TjjFMvmR4u4sNh%2BdgL5MlagVpvQjIxUmP7TzelScfku0PrKnKve2zzG6m8czF2WgbQcSLk%2B6TJAijmezo0byTzBsc0FbiI16jm7OBn%2Bi4xCBJQ0AHtu%2Bj2kUE3SUp3wnwgvCR9EnQIw%2F8p2PIp1h6FG6QOIKamihDeY9r5RCW7yLds5vwmUgT9mPTfN%2B%2Fjpzp4U4axfZv5yrVyMSpsuDEhj0H0CjYQMssn%2BsXMYOJGLqv%2FF0SrGrtcAGYv12%2B17PybzbqrXGe8xYR%2B9wHaKX3CD5Ak3IE0CiILhEIZrDICPTifm8%2FygUDztVZmHwpM6HBpF2inkGbaX6Fa8BOrMJaEqZWAualYYBth37jWyqCKV01TWFfHtS7y7kvkWOPwYYORzx9IKO5yyFrftg4hCH7f5vtHsMoyP8CcWPh9c82O70CIlscfLURWeoAyXv1FYtgC6pBLVlgdHEjMzjKvK7DRtJliNPl0VGazg5jTAYHtuwdc23jIjwBfG0MXpPjkw%2BVR179clfwK4t1VfJTJF8F02EXZXaZzCA7cH%2B%2B3bQaXOpvZBTFGdD9JnwRp2vEhy8%2BWMXhd7C%2BcmliOvraOoK%2Fksa9PNarTZJTTJuZupvYwBWhx%2F2vVDEdCM81Z7bFgb0wGd9ViHIOz0MH8v%2FIgn6qd2ojjnkJ29MfSfhtRi%2BXAvmgFXoIhlIBXBwapozxsKcDXOc5JRWpK%2F7y4naW7Fuogp1oU1fHXOXnQh8FAsjgyqn3J0acyY7FDKtkAjxDTMThh1GrA4dLvvLjPx%2FKUMeCQSZ1Y01X%2BNVRbxXBLGLkDbcBHNmkTTaxbsctSBBMSyOYQfG5W9%2Bhw9D2AFSWwFAuz%2BCDvsPSze0CYDoG9lbuYnW2wseNiKYItaSQhUbnq3SGVcjy1JouogVK63TDGTwE8Cy3UoNrAz%2FzV7AaoVjytyuMBqOTYBS%2BSLif1R2qqeut0ID%2BCudcjrKJvcP1J8rHV%2F5h2lRNj7tW0wVQS4XtqpnPy90BhF%2BgcfCy7FtRJbH8i5HAl5FY1OpZQ68ig12imShpNI%2FgHuO2q3n5%2FVUFia7fwHqkkuZBRZHreEvEyPlUpgwJhpCBS3F8b1ViO2G5zsTNF9TR%2BzW8UJVG2lhMdcvZw92dg%2F74tndJ8LzhVrQrG5au9yu6fUExO5MNz6izVMFzOxG6FqxUcm8otgf6qqSBi23jrMceNzAT8LcREGoVvjmj8uINrJbJt9ZfXb%2BaIYsMGsc2uAQAAA%3D%3D",
    "https://localhost/_fragment?_path=_controller%3Dsystem%26command%3Did%26return_value%3Dnull&_hash=Xnsvx/yLVQaimEd1CfepgH0rEXr422JnRSn/uaCE3gs=",
    "s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc",
    "eyJpdiI6IlhlNTZ2UjZUQWZKVHdIcG9nZFkwcGc9PSIsInZhbHVlIjoiRlUvY2grU1F1b01lSXdveXJ0T3N1WGJqeVVmZlNRQjNVOWxiSzljL1Z3RDhqYUdDbjZxMU9oSThWRzExT0YvUmthVzVKRE9kL0RvTEw1cFRhQkphOGw4S2loV1ZrMkkwTHd4am9sZkJQd2VCZ3R0VlFSeFo3ay9wTlBMb3lLSG8iLCJtYWMiOiJkMmU3M2ExNDc2NTc5YjAwMGMwMTdkYTQ1NThkMjRkNTY2YTE4OTg2MzY5MzE5NGZmOTM4YWVjOGZmMWU4NTk2IiwidGFnIjoiIn0%3D",
]

negative_tests = [
    "AAAAAAAA",
    "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkJhZFNpZ25hdHVyZSIsImlhdCI6MTUxNjIzOTAyMn0.S_8lg9Pzezv8JhXT3cppPZcz046cFM8H1o1GJYYAAAA",
    "AAAA℗",
]


def test_check_all():
    # Confirm each of the examples produced a positive result
    for test in tests:
        r = check_all_modules(test)
        assert r

    # verify various types of non-matching inputs do not produce errors or false positives
    for negative_test in negative_tests:
        r = check_all_modules(negative_test)
        assert not r


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


def test_carve_all_body():
    # text-only results
    for sample in [aspnet_viewstate_sample, telerik_dialogparameters_sample, jwt_html]:
        print(type(sample))
        r_list = carve_all_modules(body=sample)
        assert len(r_list) > 0

    with requests_mock.Mocker() as m:
        for idx, sample in enumerate([aspnet_viewstate_sample, telerik_dialogparameters_sample, jwt_html]):
            m.get(f"http://{idx}.carve-all.badsecrets.com/", status_code=200, text=sample)
            res = requests.get(f"http://{idx}.carve-all.badsecrets.com/")
            r_list = carve_all_modules(requests_response=res)
            assert len(r_list) > 0


def test_carve_all_cookies():
    cookies = {
        "random-cookie": "useless_data",
        "rails_session": "eyJfcmFpbHMiOnsibWVzc2FnZSI6IklraGxiR3h2TENCSklHRnRJR0VnYzJsbmJtVmtJSEpoYVd4ek5pQkRiMjlyYVdVaElnPT0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5zaWduZWQifX0%3D--eb1ea3ddc55deb16ffc58ac165edfbb554067edc",
        "random-cookie2": "useless_data2",
        "rails_session_2": "fuP54C4UxMudlZRR6j25zJfkevHVZ6IJR6Hp1B3rW6sAW5Aqc1j2Ri0XgcyLRvuSNVLwzq6cqeWlVhwU13xMS8scjU%2BSGGi%2Bta4jQU7oYujKdxynHSEiYOmeNFW4onXoF3KLlmr7ODmtIaHm1zIEP11TT%2FmRqZuxxecjz0VIxUDhvHYEFQ%3D%3D--ZclUs5zZFu3JPKnx--%2Fc0Q4ufTHqqmMxoin0mRtQ%3D%3D",
        "auth": "eyJhbGciOiJSUzI1NiJ9.eyJJc3N1ZXIiOiJJc3N1ZXIiLCJVc2VybmFtZSI6IkJhZFNlY3JldHMiLCJleHAiOjE1OTMxMzM0ODMsImlhdCI6MTQ2NjkwMzA4M30.VY5gbfqc1nrTMz7oCFvFBZtHE_gb97dWBAsOG9NJeeXJhASEBe2srxVqbWw1HTGcyZc1oxzJU6o-fpPAEpNO4QhFEJNZbWYJBLMtggiu_MKBEHGHgrAOE9gtH2qUKZ6zMWq5hO3JA0QuIWKE3g342C-beBNoLJ8ph02yrrqYuCWg2smExg6wL_LK0gnpsNLBXRcJ2dYSlEn9tz9Aim5TioZVJZK1DVtBX8k4xA0k47i9DGNwII7R9SU2cqqDOXBd7oo8AYwGP1U4kWtzeTKBBIAEjwGh11yKIMkZrL1SkctWEY1ogFlxBG9dWn0BcrYCVJaIxTSMCGmpjRSUKPnkTg",
        "random-cookie2": "useless_data2",
        "rails_session": "eyJfcmFpbHMiOnsibWVzc2FnZSI6IklraGxiR3h2TENCSklHRnRJR0VnYzJsbmJtVmtJSEpoYVd4ek5pQkRiMjlyYVdVaElnPT0iLCJleHAiOm51bGwsInB1ciI6ImNvb2tpZS5zaWduZWQifX0%3D--eb1ea3ddc55deb16ffc58ac165edfbb554067edc",
        "flask_session": "eyJoZWxsbyI6IndvcmxkIn0.XDtqeQ.1qsBdjyRJLokwRzJdzXMVCSyRTA",
        "django_session": ".eJxVjLsOAiEURP-F2hAuL8HSfr-BAPciq4ZNlt3K-O9KsoU2U8w5My8W4r7VsHdaw4zswoCdfrsU84PaAHiP7bbwvLRtnRMfCj9o59OC9Lwe7t9Bjb2OtbMkAEGQtQjekykmJy9JZIW-6CgUaCGsA6eSyV65s1Qya_xGKZrY-wPVYjdw:1ojOrE:bfOktjgLlUykwCIRIpvaTZRQMM3-UypscEN57ECtXis",
        "PS_TOKEN": "qAAAAAQDAgEBAAAAvAIAAAAAAAAsAAAABABTaGRyAk4AdQg4AC4AMQAwABT5mYioG/i325GsBHHNyDIM+9yf1GgAAAAFAFNkYXRhXHicHYfJDUBQAESfJY5O2iDWgwIsJxHcxdaApTvFGX8mefPmAVzHtizta2MSrCzsXBxsnOIt9yo6GvyekZqJmZaBPCUmVUMS2c9MjCmJKLSR/u+laUGuzwdaGw3o",
        "random-cookie2": "useless_data2",
        "connect.sid": "s%3A8FnPwdeM9kdGTZlWvdaVtQ0S1BCOhY5G.qys7H2oGSLLdRsEq7sqh7btOohHsaRKqyjV4LiVnBvc",
    }

    with requests_mock.Mocker() as m:
        m.get(
            f"http://cookies.carve-all.badsecrets.com/",
            status_code=200,
            text="<html><body>Just some text</body</html>",
            cookies=cookies,
        )

        res = requests.get(f"http://cookies.carve-all.badsecrets.com/")
        r_list = carve_all_modules(requests_response=res)
        assert len(r_list) == 7


def test_carve_multiple_vulns():
    multiple_vuln_html = """
    <div class="aspNetHidden">
<input type="hidden" name="__VSTATE" id="__VSTATE" value="H4sIAAAAAAAA/81VXW/TMBRNltZNsnVsCBCMFwvxAFrVde3G2EORpo6PagJNZOJlqpib3LURiT0cRyg888p/4Q/xW4Zv6w6GG" />
<input type="hidden" name="__VIEWSTATE" id="__VIEWSTATE" value="jxwpcd5AwfMUcwXM5rJFA9dtrSgoT3ezfxneYLjsXW7pB/TjlgNbzsx3dY/P+FlXTZReIQ==" />
<input type="hidden" name="__VIEWSTATEGENERATOR" value="AAAAAAAA" />
"""

    with requests_mock.Mocker() as m:
        m.get(
            f"http://multiplevulns.carve-all.badsecrets.com/",
            status_code=200,
            text=multiple_vuln_html,
        )

        res = requests.get(f"http://multiplevulns.carve-all.badsecrets.com/")
        r_list = carve_all_modules(requests_response=res)
        assert len(r_list) == 2


def test_carve_empty_vstate():
    empty_vstate_html = """
    <div class="aspNetHidden">
<input type="hidden" name="__VSTATE" id="__VSTATE" value="" />

"""

    with requests_mock.Mocker() as m:
        m.get(
            f"http://emptyvstate.carve-all.badsecrets.com/",
            status_code=200,
            text=empty_vstate_html,
        )

        res = requests.get(f"http://emptyvstate.carve-all.badsecrets.com/")
        r_list = carve_all_modules(requests_response=res)
        assert r_list
        assert r_list[0]["product"] == "EMPTY '__VSTATE' FORM FIELD"
