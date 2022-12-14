from badsecrets import modules_loaded

Jsf_viewstate = modules_loaded["jsf_viewstate"]

# Mojarra 2.0.3 (password = "PASSWORD")

# Unprotected / Uncompressed
def test_unprotected():

    s = "rO0ABXBzcgARamF2YS51dGlsLkhhc2hNYXAFB9rBwxZg0QMAAkYACmxvYWRGYWN0b3JJAAl0aHJlc2hvbGR4cD9AAAAAAAAMdwgAAAAQAAAABHQABmpfaWR0NHVyABNbTGphdmEubGFuZy5PYmplY3Q7kM5YnxBzKWwCAAB4cAAAAAJ1cQB+AAMAAAAFcHBwcHVxAH4AAwAAAAV+cgAuamF2YXguZmFjZXMuY29tcG9uZW50LlVJQ29tcG9uZW50JFByb3BlcnR5S2V5cwAAAAAAAAAAEgAAeHIADmphdmEubGFuZy5FbnVtAAAAAAAAAAASAAB4cHQACmF0dHJpYnV0ZXNzcgATamF2YS51dGlsLkFycmF5TGlzdHiB0h2Zx2GdAwABSQAEc2l6ZXhwAAAAA3cEAAAAA3NyACZqYXZheC5mYWNlcy5jb21wb25lbnQuU3RhdGVIb2xkZXJTYXZlclnKsz2TnM1NAgACTAAJY2xhc3NOYW1ldAASTGphdmEvbGFuZy9TdHJpbmc7TAAKc2F2ZWRTdGF0ZXQAFkxqYXZhL2lvL1NlcmlhbGl6YWJsZTt4cHB2cQB+AABzcQB+AA1wdAAeY29tLnN1bi5mYWNlcy5mYWNlbGV0cy5BUFBMSUVEc3EAfgANcHNyADVjb20uc3VuLmZhY2VzLmZhY2VsZXRzLmltcGwuRGVmYXVsdEZhY2VsZXQkQXBwbHlUb2tlbvWoLFmcQGpADAAAeHB3FgAML2luZGV4LnhodG1sAAABhKAqW4d4eH5yADVqYXZheC5mYWNlcy5jb21wb25lbnQuVUlDb21wb25lbnQkUHJvcGVydHlLZXlzUHJpdmF0ZQAAAAAAAAAAEgAAeHEAfgAIdAAUYXR0cmlidXRlc1RoYXRBcmVTZXRzcQB+AAsAAAACdwQAAAACc3EAfgANcHZxAH4AC3NxAH4ADXBxAH4AE3hwcHQABmpfaWR0NnVxAH4AAwAAAAJ1cQB+AAMAAAAFcHBwcHVxAH4AAwAAAAVxAH4ACXNxAH4ACwAAAAN3BAAAAANzcQB+AA1wcQB+ABFzcQB+AA1wcQB+ABNzcQB+AA1wcQB+ABZ4cQB+ABhzcQB+AAsAAAACdwQAAAACc3EAfgANcHEAfgAcc3EAfgANcHEAfgATeHBwdAANal9pZHQ4OmpfaWR0OXVxAH4AAwAAAARwcHBwdAAFal9pZDF1cQB+AAMAAAACcHB4"
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "UNPROTECTED"
    assert r["details"]["compression"] == False
    assert "Unprotected" in r["details"]["info"]


# Unprotected / Compressed
def test_unprotected_compressed():

    s = "H4sIAAAAAAAAAJWST2sTQRTAXzeJNmkqbSPBg3oqgiATBCtqEBPahgZTDaSCxYNOstNm4uzuOPM22fRQEPwAgiehokcP3voJxIMgKOjR7+DRuzPbJBvQHHywb9/8eW9+78+HX5CRWsFyj/YpCZELskV1d5vKzOmfHz8Vn3xPgVODnAioW6MdDFQdsthVTHcD4UbyTgWs5AfzRi+ZL41wqveYu3gtVFB41IjjCurvk/vtHutg+eW3h2+X9GXhAETSODjhMziElLEy0kiyOlRArHdE9miHadIJPBn4zEfyoL4+tlebKpBM4fAuG2oYyYoJreBM8vSmH3rThxIhRxEVb4fItEm/kKRfVYoOG1xj9PzHhdef6ZsUzNUhrfkBi3lTg7TVxunSv+laSJFtmeow1aJ9pna/HN9+dfR12wGnAdmOoFrfox5DWImLU7KEpZaB8ffLDchp4+PGMRCKJzd4UGoxxangB7QtWDmSsm/LBNrqRZPNRfM80aE/grFaMNSk2mw26psbo3uGeW3GRe5JQTbYHg0F1k42V6tSiuFO8JT5v99f2T2q9Cp5W7tBEfIl7rssIlEXPQEw9+Jdaf04ikzH1v6vY03F+ybT6d5Y1HmEs0l/droUq4q1DKc9XLBDEzfBGeUVF2NhtLC6YCo0nsPrk4maOWnWyE5ijxuchFueDj1lF2PYczOorD7/F9RiDHXjVvy7OWFIWyKEjN2+mhBLGf0BupeT66IDAAA="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "UNPROTECTED"
    assert r["details"]["compression"] == True
    assert "Unprotected" in r["details"]["info"]


# 3DES Encrypted Compressed
def test_des_compressed():

    s = "H4sIAAAAAAAAAAG4BEf7SqmRq5Y9DfCIR9QLZ9wfMXuwWMtbz4CYqd0%2FCCMNXbRgEOJmkCbpKBJXQ%2BAz78OO%2FufCpa1k1nqcEgNxRzRnKKNVBBPMov%2FE%2BXFqh%2Bb5KZLhJvXicwGSIuVshN1XYpSRzKrosUB0ykN8j9hA90IA5AulHsXIofHj07FlFC%2BTbQqVZ7jKeHDurUkVhf8WQ1up%2BVO9KZwQU6WZzsF5y6AkidThF411avCLTxGAtIC7uZBnzMLL4duUf7YtdIDHt4UWGsXCI7ItciWv4Dzk9w5bKeWRRLp1W1pbniEQY01lTulTZBYPuLtna6pB0I3EJ5bV4c3Gktdd1YAVQcBQ2Yy5TW92YEclM99vW9mwu6xD8ZRYJNIb622TjjFMvmR4u4sNh%2BdgL5MlagVpvQjIxUmP7TzelScfku0PrKnKve2zzG6m8czF2WgbQcSLk%2B6TJAijmezo0byTzBsc0FbiI16jm7OBn%2Bi4xCBJQ0AHtu%2Bj2kUE3SUp3wnwgvCR9EnQIw%2F8p2PIp1h6FG6QOIKamihDeY9r5RCW7yLds5vwmUgT9mPTfN%2B%2Fjpzp4U4axfZv5yrVyMSpsuDEhj0H0CjYQMssn%2BsXMYOJGLqv%2FF0SrGrtcAGYv12%2B17PybzbqrXGe8xYR%2B9wHaKX3CD5Ak3IE0CiILhEIZrDICPTifm8%2FygUDztVZmHwpM6HBpF2inkGbaX6Fa8BOrMJaEqZWAualYYBth37jWyqCKV01TWFfHtS7y7kvkWOPwYYORzx9IKO5yyFrftg4hCH7f5vtHsMoyP8CcWPh9c82O70CIlscfLURWeoAyXv1FYtgC6pBLVlgdHEjMzjKvK7DRtJliNPl0VGazg5jTAYHtuwdc23jIjwBfG0MXpPjkw%2BVR179clfwK4t1VfJTJF8F02EXZXaZzCA7cH%2B%2B3bQaXOpvZBTFGdD9JnwRp2vEhy8%2BWMXhd7C%2BcmliOvraOoK%2Fksa9PNarTZJTTJuZupvYwBWhx%2F2vVDEdCM81Z7bFgb0wGd9ViHIOz0MH8v%2FIgn6qd2ojjnkJ29MfSfhtRi%2BXAvmgFXoIhlIBXBwapozxsKcDXOc5JRWpK%2F7y4naW7Fuogp1oU1fHXOXnQh8FAsjgyqn3J0acyY7FDKtkAjxDTMThh1GrA4dLvvLjPx%2FKUMeCQSZ1Y01X%2BNVRbxXBLGLkDbcBHNmkTTaxbsctSBBMSyOYQfG5W9%2Bhw9D2AFSWwFAuz%2BCDvsPSze0CYDoG9lbuYnW2wseNiKYItaSQhUbnq3SGVcjy1JouogVK63TDGTwE8Cy3UoNrAz%2FzV7AaoVjytyuMBqOTYBS%2BSLif1R2qqeut0ID%2BCudcjrKJvcP1J8rHV%2F5h2lRNj7tW0wVQS4XtqpnPy90BhF%2BgcfCy7FtRJbH8i5HAl5FY1OpZQ68ig12imShpNI%2FgHuO2q3n5%2FVUFia7fwHqkkuZBRZHreEvEyPlUpgwJhpCBS3F8b1ViO2G5zsTNF9TR%2BzW8UJVG2lhMdcvZw92dg%2F74tndJ8LzhVrQrG5au9yu6fUExO5MNz6izVMFzOxG6FqxUcm8otgf6qqSBi23jrMceNzAT8LcREGoVvjmj8uINrJbJt9ZfXb%2BaIYsMGsc2uAQAAA%3D%3D"
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "PASSWORD"
    assert r["details"]["compression"] == True
    assert "3DES Encrypted" in r["details"]["info"]


# 3DES Encrypted Uncompressed
def test_des():

    s = "a/3+VnZrv9jjbmI9Wdk6EOKZUIlZdGAChPjKxw80vMfcJDjAi4Q5p4bedz/vbEtvX5qT2X/8PkCJ7va35OONm9ngpzSJzPWcrSe/CIeqcoEiRbYOzhOENgqvLbi9BZAJb4avuhNrjAsYWTPRl1l4sRN/qfNpcnCZvlIBveC7N5vV1hf+svQ61aNb66xIIkg+oU210qHGY3PEGUVJgo0/09C2LpB1HFjxpg3h1e/rfl/KF7W87Sn9qcJrvW61Lgl8OfUbfMiRdJoaTCCPUTQK4ZLJww4AyrblqEy21Ui4GLNTUSCIi/VjNJPws0/dn6TOoOzKrlhOMh0SLTmPyOYzxrdqOSNieknvP/eR5/h+uVX/0oVvann7qLpzPQ4jVKUWCWXaqD3YlLRzCBngQG53ayMEeMfWJmjf7uM4zvCtAaHLiF9L+ZbaI++0JHMEitJXU2/dDoXpO+Uol1xcGdD3KExHl44Udi+nq1SWudIV/3dNRMEIv0nSbTLoWnZpUfZR6zANlcAGKRYxI5jEQAvlMUtkUJoI605rhnFK3ONgOfZik4Fu0JQ3ozjuklphg0PcIpgDAbdsKyx19iPXCkUgNTeycUkrI8mBzYXgbRlGRxmKC59G6jzPBuK1KBpe5AQPo3zxsb1f6Zng0Xb7Qo+C6qr+sm5gkYXycxFUtjypUjflFe6PJm+uNTzZ641fW7DDSXMC1jSnTA0M7RT2W3U82kifDgCoFhz8WtLKR4PGbkGToySWvuMnMrsGMr8CKQ+7RVb39+upMmmAHfL15mRS2uugz92e9eS+2gc29ut/iTsvfRab3h3QB+cx6jBEczL+3cOoSi20c3mYkjw4KH07yMfyLcIZFVgkJGmRImdCQIGmZFCCFgKD1TfWCmS8fJqEmOaID0Iq2KEnZuAbCo21qYPWfT5Bjf3Fthaln6ekfh8u2c4WyERzOBYr3/l5P4N4V7v1b99RL26oKBKPoIOhqih8KMecEa21hBJijVogSECUQl1SMNg0dve5GIMKL1JocQzCvLeH/ByGbEWzYln8+Z97d3nF/qxZc/2c7g4/y68j2/P1c5pB66eCBWgKX7XrBJXUs2pu/Jajpj1/d5m8K4t1Ta+nShJn3RFq6XKBkCYCZ5d+jp0Zs4dZxa11Pmpz5uAQGyw//me4rjhs6LsbOuIk5x2RjCHi1baedWfuKjQobEYJjXRFCqEazIaPpNIg6Fseug86zGtYVptE0xPUE9+yyQbjXcV/"
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "PASSWORD"
    assert r["details"]["compression"] == False
    assert "3DES Encrypted" in r["details"]["info"]


# AES Encrypted Compressed
def test_aes_compressed():

    s = "wZC+syugf1QV9sEcnIGY+sBWqC1MPsYh7cJb5ZB1uVucJ5DuWFpZkAnP/KZrPSxWrLWjfv41aWQyfTh3DMYL8+p2Zc8S8EVhvonNtvzvN5xORNN8LI939XI6DqfAdsC7g+1EMQ5fV7oFcs9pq3kqdShVoN/u2Rem3qISST6O3R/L4hNVQrISANO942HhznEmyTpLRWjeZthSVjBr74QRTNbzyf6goTcFuz288/c+MAIQQwRoggvaWg5Ou4VXEobKz6s1NLb80YNb9lkgtXIX3zeEAvBjgjkv/A5CHnKKb68="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "UEFTU1dPUkRQQVNTV09SRA=="
    assert r["details"]["compression"] == True
    assert "AES Encrypted" in r["details"]["info"]


# AES Encrypted Uncompressed
def test_aes():

    s = "Ly8gp+FZKt9XsaxT5gZu41DDxO74k029z88gNBOru2jXW0g1Og+RUPdf2d8hGNTiofkD1VvmQTZAfeV+5qijOoD+SPzw6K72Y1H0sxfx5mFcfFtmqX7iN6Gq0fwLM+9PKQz88f+e7KImJqG1cz5KYhcrgT87c5Ayl03wEHvWwktTq9TcBJc4f1VnNHXVZgALGqQuETU8hYwZ1VilDmQ7J4pZbv+pvPUvzk+/e2oNeybso6TXqUrbT2Mz3k7yfe92q3pRjdxRlGxmkO9bPqNOtETlLPE5dDiZYo1U9gr8BBQ="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"] == "UEFTU1dPUkRQQVNTV09SRA=="
    assert r["details"]["compression"] == False
    assert "AES Encrypted" in r["details"]["info"]


# Myfaces JSF

# DES/ECB/SHA1/NoCompression
def test_myfaces_des_ecb_sha1():

    s = "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RSCWwjtJcZNbWPcvPqL5zzfl03DoeMZfGGX7a9PSv+fUi1LWO6vtZ+EWjhGezWmugJxQ2Eo="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Algo"] == "DES"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# DES/CBC/SHA1/NoCompression
def test_myfaces_des_cbc_sha1():

    s = "Zw1z6gRrHxlOFRhb4WnoOrS9m7bQivOWVyOLggR74US+3hLpcd0gXh9Dv+4WjbsAF2SuwHqnWa3qTjvogQHQMe1sDwbEp8PILVrrsFnl0D0GRjEABRyc0C4zZkg="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Algo"] == "DES"
    assert r["secret"]["Decryption Mode"] == "CBC"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# DES/ No Signature


# AES/CBC/SHA1/NoCompression
def test_myfaces_aes_cbc_sha1():

    s = "jYL4rrAMxAUGTAoHk8nlTnT7dej5+8dWVbTv0liQn/XEm2J6UGxOFyRifCBkmHGrdyRK/2sEXdpu/nl8c0QJkWBNLOI2MDc58fFzo4Gf2UWw4BYzfXSAvq5/2YEICT2hG6Y9WQ=="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "UEFTU1dPUkRQQVNTV09SRA=="
    assert r["secret"]["Decryption Key"] == "UEFTU1dPUkRQQVNTV09SRA=="
    assert r["secret"]["Decryption Algo"] == "AES"
    assert r["secret"]["Decryption Mode"] == "CBC"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["secret"]["Decryption IV"] == "UEFTU1dPUkRQQVNTV09SRA=="
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# AES/ECB/SHA1/NoCompression
def test_myfaces_aes_ecb_sha1():

    s = "pBZgkQwn04iTzlwq/D0QMkpyddzl3ZykcI0Z60tu51sS1PGvDaWuG8nIqcH6m+xIupBoUYKfQ29HU4Aj2oQVTsakM34wklFTxBDGibP5G0gGHsYPfBcj66uGNnHY+5pgR9IuSA=="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "UEFTU1dPUkRQQVNTV09SRA=="
    assert r["secret"]["Decryption Key"] == "UEFTU1dPUkRQQVNTV09SRA=="
    assert r["secret"]["Decryption Algo"] == "AES"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# 3DES/CBC/SHA1/NoCompression
def test_myfaces_3des_cbc_sha1():

    s = "ryvk9O4nTbphFjFZNbgb9HZy0f+YFDJZdngV8i+fwGof0LYom4hQfw7kV1kyYI8FMlC/vU0d0oYptIFJKmQ/0A+dGyGMAgCHpsqXdbu8dHZLzVvvTYVyCwSQeZ8="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "M0RFUzNERVMxMjM0MTIzNDU2Nzg1Njc4"
    assert r["secret"]["Decryption Key"] == "M0RFUzNERVMxMjM0MTIzNDU2Nzg1Njc4"
    assert r["secret"]["Decryption Algo"] == "DES3"
    assert r["secret"]["Decryption Mode"] == "CBC"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["secret"]["Decryption IV"] == "M0RFUzNERVM="
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# 3DES/ECB/SHA1
def test_myfaces_3des_ecb_sha1():

    s = "YfpcoNIuQKFpaBCzskZ2moZjOVfAXr2duxADqVgkgWOlTqR8sB7xApnKu/O1vJG1qbiy3N6wAfi/2FD5xbi/bp81+ZmL72GV6k3OYCuB3J69jq+b0jOgyJ7uGp8="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "M0RFUzNERVMxMjM0MTIzNDU2Nzg1Njc4"
    assert r["secret"]["Decryption Key"] == "M0RFUzNERVMxMjM0MTIzNDU2Nzg1Njc4"
    assert r["secret"]["Decryption Algo"] == "DES3"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# DES/ECB/MD5/NoCompression
def test_myfaces_des_ecb_md5():

    s = "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RSCWwjtJcZNbWPcvPqL5zzfl03DoeMZfGGX7a9PSv+fUYxZ5XEIOtghaDC4uVpnB4Q=="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Algo"] == "DES"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "MD5"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# DES/ECB/SHA256/NoCompression
def test_myfaces_des_ecb_sha256():

    s = "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RSCWwjtJcZNbWPcvPqL5zzfl03DoeMZfGGX7a9PSv+fUKmvYzFYEqvO3FKF1HYNsHLQt/uV13NWzmalZxg+UL+4="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Algo"] == "DES"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "SHA256"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# DES/ECB/SHA384/NoCompression
def test_myfaces_des_ecb_sha384():

    s = "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RSCWwjtJcZNbWPcvPqL5zzfl03DoeMZfGGX7a9PSv+fUBrsnBq1D+nb2VllJZZckRZXkfioc95rZ1wlWlvuZwf8VhG5m3lVvhT5h/mAvj/sU"
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Algo"] == "DES"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "SHA384"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# DES/ECB/SHA512/NoCompression
def test_myfaces_des_ecb_sha512():

    s = "wHo0wmLu5ceItIi+I7XkEi1GAb4h12WZ894pA+Z4OH7bco2jXEy1RSCWwjtJcZNbWPcvPqL5zzfl03DoeMZfGGX7a9PSv+fUT8MAeKNouAGj1dZuO8srXt8xZIGg+wPCWWCzcX6IhWOtgWUwiXeSojCDTKXklsYt+kzlVbk5wOsXvb2lTJoO0Q=="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Algo"] == "DES"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "SHA512"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# DES/ECB/SHA1/Compression
def test_myfaces_des_ecb_sha1_compressed():

    s = "8H61sylBH/Ad3thZCGDVLyaso2g499GnjAuqpNapesoJgoo5Zk3nxDqXoWfRDwzmKk6eDLTyWViTRTdnr8Su7+XzW6MMAcZo+Fa7UwdfE4pKJ2+z6OYK58l+/93LHZmgVUF5dqI3G8mLr3uI"
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Key"] == "SnNGOTg3Ni0="
    assert r["secret"]["Decryption Algo"] == "DES"
    assert r["secret"]["Decryption Mode"] == "ECB"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["details"]["compression"] == True
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


# 3DES/CBC/SHA1/NoCompression/UnknownIV
def test_myfaces_3des_cbc_sha1_invalidIV():

    s = "jBWXxyZZx1y12WYHCkj34qUMR+hVvTZOsK6VlaifRn8sXZJKOoW/v3WMZFpCP6+6VVbyv3MpBc2x57Dei+t7zZ6HiltEQqaMv1XnmgRtAWsKb9uiVMlfkcDWwl8="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert r
    assert r["secret"]["Hash Key"] == "M0RFUzNERVMxMjM0MTIzNDU2Nzg1Njc4"
    assert r["secret"]["Decryption Key"] == "M0RFUzNERVMxMjM0MTIzNDU2Nzg1Njc4"
    assert r["secret"]["Decryption Algo"] == "DES3"
    assert r["secret"]["Decryption Mode"] == "CBC"
    assert r["secret"]["Hash Algo"] == "SHA1"
    assert r["secret"]["Decryption IV"] == "INVALID"
    assert r["details"]["compression"] == False
    assert "JSF Viewstate (Myfaces)" in r["details"]["info"]


def test_negative():

    s = "QUFBQUFBQUFBQUFBQUFBQUFBQUE="
    x = Jsf_viewstate()
    r = x.check_secret(s)
    assert not r
