import pytest
from badsecrets.helpers import write_vlq_string


def test_vlq_encoding_multi_bytes():
    string_128_chars = "a" * 128  # utf-8 encoding is 1 byte per character
    string_16384_chars = "b" * 16384  # utf-8 encoding is 1 byte per character
    assert write_vlq_string(string_128_chars)[0] == 0x80  # the first byte should be 0x80
    assert write_vlq_string(string_16384_chars)[0:2] == bytearray(
        [0x80, 0x80]
    )  # the first two bytes should both be 0x80
