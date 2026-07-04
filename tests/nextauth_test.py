import json
import base64

from badsecrets import modules_loaded
from badsecrets.helpers import b64url_decode, hkdf_sha256, parse_jwe_compact, jwe_decrypt

NextAuth = modules_loaded["nextauth"]

# Authoritative vectors generated with Node.js stdlib crypto (crypto.hkdfSync + createCipheriv) —
# an implementation entirely independent of this library's pycryptodome/hmac code. A successful
# crack is therefore a cross-implementation check, not a round-trip against our own encoder.
#
# V4: NextAuth v4 (A256GCM, empty-salt HKDF); secret "your-secret-here" lives in nextauth_secrets.txt.
V4_TOKEN = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..eV7_ge7JJ9vqaYxW.97XOYXr0ANwWherKQ3wIwyLNBN7-A8O40pNSwihk4BPIDWUn3KoXzX5I9fV9rhmlkaILza1p3jVKhzcGISkE3nmx_gaxnXv6UlNfg2vMeA8A_jeQb9x9MgK1yBuIG_V-cw.5b2T1NpI1p4rku2w9mXZ-Q"
# V5: Auth.js v5 (A256CBC-HS512, cookie-name-salt HKDF); secret "secret" lives in the shared top_100000 list.
V5_TOKEN = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2Q0JDLUhTNTEyIn0..S2AiBDv1_dMgGggynajqYg.sCaHFuGzsLCmkv-ZTp9O4cd5RRXRC_CIGzzTabIOiVQ2rc0XuxcXtBUz3sHcE0ZE4gxsyP5FeVZBtHcFaHOOEjd8XBN2KG0tK2lBYo_paRVf65VNeJu5xwWVy-2CBgxS0ZFQ18astxH_dVsiBlX5rQ.va5FTqejKaqgUUOBz-fM1RKnRx5LGNLM6_Se-e1sAr4"
# Identifies as a NextAuth JWE but was sealed with a strong random secret (in no wordlist).
UNCRACKABLE_TOKEN = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..R8KMZAmcMsSl9nzt.Pc4uyDiqQvcL5JI.XDos2qvZvv3nI2Q4WtYx5A"
# Cracks under "nextauth" but the decrypted plaintext is not JSON (exercises the fallback).
NONJSON_TOKEN = (
    "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0..SCmq5b3bfrXCjlzt.zizEcgPEd9PTvQ2b_C1nTA.pLEK8OD5OqK4t0gQCW2nVg"
)


def _b64u(data):
    raw = data if isinstance(data, bytes) else data.encode()
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def _make_token(header_bytes, iv="AAAA", ct="AAAA", tag="AAAA"):
    return f"{_b64u(header_bytes)}..{iv}.{ct}.{tag}"


def test_nextauth_v4_gcm():
    x = NextAuth()
    found = x.check_secret(V4_TOKEN)
    assert found
    assert found["secret"] == "your-secret-here"
    assert found["details"]["enc"] == "A256GCM"
    assert found["details"]["session"]["email"] == "alice@example.com"


def test_nextauth_v5_cbc_hs512():
    x = NextAuth()
    found = x.check_secret(V5_TOKEN)
    assert found
    assert found["secret"] == "secret"
    assert found["details"]["enc"] == "A256CBC-HS512"
    assert found["details"]["session"]["name"] == "alice"


def test_nextauth_nonjson_payload():
    x = NextAuth()
    found = x.check_secret(NONJSON_TOKEN)
    assert found
    assert found["secret"] == "nextauth"
    assert found["details"]["session"] == "this is not json"


def test_nextauth_uncrackable():
    x = NextAuth()
    assert x.check_secret(UNCRACKABLE_TOKEN) is None


def test_nextauth_skips_blank_wordlist_lines(monkeypatch):
    # A stray blank line in a (community-editable) wordlist must be skipped, not tried as a secret.
    x = NextAuth()
    monkeypatch.setattr(x, "load_resources", lambda names: iter(["\n", "your-secret-here\n"]))
    found = x.check_secret(V4_TOKEN)
    assert found and found["secret"] == "your-secret-here"


def test_nextauth_negative_not_identified():
    x = NextAuth()
    # 3-segment signed JWT, not a dir JWE
    assert x.check_secret("eyJhbGciOiJIUzI1NiJ9.eyJhIjoxfQ.c2ln") is None
    # not token-shaped at all
    assert x.check_secret("hello.world") is None
    # empty-key JWE shape but non-base64 junk header start
    assert x.check_secret("notjwt..a.b.c") is None


def test_nextauth_bad_header():
    x = NextAuth()
    # passes identify (starts eyJ, 5 segs, empty key) but the header is not valid JSON
    assert x.check_secret(_make_token(b'{"alg":"dir"')) is None


def test_nextauth_alg_not_dir():
    x = NextAuth()
    assert x.check_secret(_make_token(b'{"alg":"A256KW","enc":"A256GCM"}')) is None


def test_nextauth_unsupported_enc():
    x = NextAuth()
    assert x.check_secret(_make_token(b'{"alg":"dir","enc":"A128GCM"}')) is None


def test_nextauth_parse_bad_segment_count():
    # _parse_token is defensive even though check_secret gates on identify (which requires 5 segments)
    x = NextAuth()
    assert x._parse_token("only.three.parts") is None


def test_nextauth_carve_and_chunk_reassembly():
    x = NextAuth()
    # NextAuth splits large tokens into .0/.1 chunks; carve() must reassemble them.
    head, tail = V4_TOKEN[:80], V4_TOKEN[80:]
    cookies = {
        "next-auth.session-token.0": head,
        "next-auth.session-token.1": tail,
        "unrelated": "value",
    }
    results = x.carve(cookies=cookies)
    assert any(r["type"] == "SecretFound" and r["product"] == V4_TOKEN for r in results)
    # single (unchunked) cookie still works
    single = x.carve(cookies={"authjs.session-token": V4_TOKEN})
    assert any(r["type"] == "SecretFound" for r in single)


# --- helper unit tests ---


def test_hkdf_rfc5869_test_case_1():
    # RFC 5869 Appendix A.1 known-answer test anchors our HKDF independently of NextAuth.
    ikm = bytes.fromhex("0b" * 22)
    salt = bytes.fromhex("000102030405060708090a0b0c")
    info = bytes.fromhex("f0f1f2f3f4f5f6f7f8f9")
    expected = bytes.fromhex("3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865")
    assert hkdf_sha256(ikm, salt, info, 42) == expected
    # accepts str inputs too
    assert hkdf_sha256("secret", "", "info", 32) == hkdf_sha256(b"secret", b"", b"info", 32)


def test_b64url_decode():
    assert b64url_decode("YWJj") == b"abc"
    assert b64url_decode(b"YWJj") == b"abc"
    assert b64url_decode("YQ") == b"a"  # tolerates missing padding


def test_parse_jwe_compact():
    assert parse_jwe_compact("a.b.c.d.e") == ("a", "b", "c", "d", "e")
    assert parse_jwe_compact("a.b.c") is None


def test_jwe_decrypt_failure_branches():
    protected = _b64u(json.dumps({"alg": "dir", "enc": "A256CBC-HS512"}))
    # wrong CEK length for CBC-HS512
    assert jwe_decrypt(protected, "A256CBC-HS512", b"tooshort", b"\x00" * 16, b"\x00" * 16, b"\x00" * 32) is None
    # CBC-HS512 authentication tag mismatch
    assert jwe_decrypt(protected, "A256CBC-HS512", b"\x00" * 64, b"\x00" * 16, b"\x00" * 16, b"\x00" * 32) is None
    # unsupported enc
    assert jwe_decrypt(protected, "A128GCM", b"\x00" * 32, b"\x00" * 12, b"", b"") is None
    # GCM tag failure
    assert jwe_decrypt(protected, "A256GCM", b"\x00" * 32, b"\x00" * 12, b"\x00" * 16, b"\x00" * 16) is None
