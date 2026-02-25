import json
import re
import sys
import hmac
import struct
import hashlib
import binascii
from enum import Enum
from urllib.parse import urlparse
from colorama import Fore, Style, init
from badsecrets.errors import BadsecretsException

init(autoreset=True)  # Automatically reset the color to default after each print statement


def print_status(msg, passthru=False, color="white", colorenabled=True):
    color_dict = {"white": Fore.WHITE, "red": Fore.RED, "yellow": Fore.YELLOW, "blue": Fore.BLUE, "green": Fore.GREEN}

    colorama_color = color_dict.get(color.lower(), Fore.WHITE)

    if msg:
        if colorenabled:
            msg = f"{colorama_color}{msg}{Style.RESET_ALL}"
        if passthru:
            return msg
        else:
            print(msg)


def _writeuint(v):
    return struct.pack(">I", v)


def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]


def sp800_108_derivekey(key, label, context, keyLengthInBits):
    lblcnt = 0 if label is None else len(label)
    ctxcnt = 0 if context is None else len(context)
    buffer = b"\x00" * (4 + lblcnt + 1 + ctxcnt + 4)
    if lblcnt != 0:
        buffer = buffer[:4] + label + buffer[4 + lblcnt :]
    if ctxcnt != 0:
        buffer = buffer[: 5 + lblcnt] + context + buffer[5 + lblcnt + ctxcnt :]
    buffer = buffer[: 5 + lblcnt + ctxcnt] + _writeuint(keyLengthInBits) + buffer[5 + lblcnt + ctxcnt + 4 :]
    v = int(keyLengthInBits / 8)
    res = b"\x00" * v
    num = 1
    while v > 0:
        buffer = _writeuint(num) + buffer[4:]
        h = hmac.new(key, buffer, hashlib.sha512)
        hash = h.digest()
        cnt = min(v, len(hash))
        res = hash[:cnt] + res[cnt:]
        v -= cnt
        num += 1
    return res


def write_vlq_string(string):
    encoded_string = string.encode("utf-8")
    length = len(encoded_string)
    length_vlq = bytearray()
    while length >= 0x80:
        length_vlq.append((length | 0x80) & 0xFF)
        length >>= 7
    length_vlq.append(length)
    return bytes(length_vlq) + encoded_string


def sp800_108_get_key_derivation_parameters(primary_purpose, specific_purposes):
    derived_key_label = primary_purpose.encode("utf-8")
    derived_key_context = b"".join([write_vlq_string(purpose) for purpose in specific_purposes])
    return derived_key_label, derived_key_context


class Csharp_pbkdf1_exception(BadsecretsException):
    pass


class Csharp_pbkdf1:
    def __init__(self, passwordBytes, saltBytes, iterations):
        self.passwordBytes = passwordBytes
        self.saltBytes = saltBytes
        self.iterations = iterations
        self.extra = bytes([])
        self.extra_count = 0
        self.magic_number = 0
        if not iterations > 0:
            raise Csharp_pbkdf1_exception("Iterations must be greater than 0")

        try:
            self.lasthash = hashlib.sha1(passwordBytes + saltBytes).digest()
        except TypeError:
            raise Csharp_pbkdf1_exception("Password and Salt must be of type bytes")

        self.iterations -= 1

        for i in range(self.iterations - 1):
            self.lasthash = hashlib.sha1(self.lasthash).digest()

        self.derivedBytes = hashlib.sha1(self.lasthash).digest()
        self.ctrl = 1

    def GetBytes(self, keylen):
        if not isinstance(keylen, int):
            raise Csharp_pbkdf1_exception("GetBytes() must be called with an int")

        result = bytearray()

        if len(self.extra) > 0:
            self.magic_number = len(self.extra) - self.extra_count
            if self.magic_number >= keylen:
                result.extend(self.extra[self.extra_count : self.extra_count + keylen])
                if self.magic_number > keylen:
                    self.extra_count += keylen
                else:
                    self.extra = bytes([])
                self.derivedBytes = bytes([])
                return result

            result.extend(self.extra[self.magic_number : self.magic_number + self.magic_number])
            self.extra = bytes([])

        while len(self.derivedBytes) < keylen:
            self.derivedBytes += hashlib.sha1(bytes([ord(str(self.ctrl))]) + self.lasthash).digest()
            self.ctrl += 1

        result.extend(self.derivedBytes[: keylen - self.magic_number])

        if (len(self.derivedBytes) + self.magic_number) > keylen:
            self.extra = self.derivedBytes
            self.extra_count = keylen - self.magic_number

        self.derivedBytes = bytes([])
        return result


def twos_compliment(unsigned):
    bs = bin(unsigned).replace("0b", "")
    val = int(bs, 2)
    b = val.to_bytes(1, byteorder=sys.byteorder, signed=False)
    return int.from_bytes(b, byteorder=sys.byteorder, signed=True)


class Java_sha1prng:
    def __init__(self, key):
        keyBytes = key
        if not isinstance(key, bytes):
            keyBytes = key.encode()

        self.seed = hashlib.sha1(keyBytes).digest()
        self.state = None
        self.outBytes = b""

        # Simulate setseed()
        self.state = hashlib.sha1(self.seed).digest()
        self.outBytes = hashlib.sha1(self.state).digest()
        self.updateState(self.outBytes)

    def updateState(self, output):
        last = 1
        outputBytesArray = bytearray(output)
        newState = bytearray()

        for c, n in zip(self.state, outputBytesArray):
            v = twos_compliment(c) + twos_compliment(n) + last
            finalv = v & 255
            newState.append(finalv)
            last = v >> 8
        self.state = newState

    def get_sha1prng_key(self, outLen):
        while len(self.outBytes) < outLen:
            output = hashlib.sha1(self.state).digest()
            self.outBytes += output
            self.updateState(output)
        return self.outBytes[:outLen]


class Purpose(Enum):
    """ASP.NET SP800-108 key derivation purpose strings."""

    AssemblyResourceLoader_WebResourceUrl = "AssemblyResourceLoader.WebResourceUrl"
    ScriptResourceHandler_ScriptResourceUrl = "ScriptResourceHandler.ScriptResourceUrl"
    WebForms_HiddenFieldPageStatePersister_ClientState = "WebForms.HiddenFieldPageStatePersister.ClientState"


def aspnet_resource_b64_to_standard_b64(urlsafe_str):
    """Convert ASP.NET custom URL-safe base64 to standard base64.

    The input token uses '-' for '+', '_' for '/', and the last character
    is a digit indicating the number of '=' padding chars that were removed.
    """
    pad_count = int(urlsafe_str[-1])
    standard_str = urlsafe_str[:-1].replace("-", "+").replace("_", "/")
    standard_str += "=" * pad_count
    return standard_str


def isolate_app_process(vkey_hex, apppath_hashcode):
    """Modify first 4 bytes of key based on app path hash (IsolateApps support)."""
    key = bytearray(binascii.unhexlify(vkey_hex))
    if len(key) < 4:
        return None
    key[0] = apppath_hashcode & 0xFF
    key[1] = (apppath_hashcode & 0xFF00) >> 8
    key[2] = (apppath_hashcode & 0xFF0000) >> 16
    key[3] = (apppath_hashcode & 0xFF000000) >> 24
    return binascii.hexlify(key)


# .NET Unicode sort key mapping for CompareInfo.GetSortKey(s, CompareOptions.IgnoreCase)
# .NET CompareInfo.GetSortKey() mapping database.
# Ported from crapsecrets (credit @irsdl) - maps Unicode code points U+0001-U+00FF to sort key byte arrays.
# fmt: off
_DOTNET_SORT_KEY_DB_JSON = r'''
{"\u0001":[1,1,1,1,255,255,3,18,0],"\u0002":[1,1,1,1,255,255,4,18,0],"\u0003":[1,1,1,1,255,255,5,18,0],"\u0004":[1,1,1,1,255,255,6,18,0],"\u0005":[1,1,1,1,255,255,7,18,0],"\u0006":[1,1,1,1,255,255,8,18,0],"\u0007":[1,1,1,1,255,255,9,18,0],"\b":[1,1,1,1,255,255,10,18,0],"\t":[7,5,1,1,1,1,0],"\n":[7,6,1,1,1,1,0],"\u000b":[7,7,1,1,1,1,0],"\f":[7,8,1,1,1,1,0],"\r":[7,9,1,1,1,1,0],"\u000e":[1,1,1,1,255,255,11,18,0],"\u000f":[1,1,1,1,255,255,12,18,0],"\u0010":[1,1,1,1,255,255,13,18,0],"\u0011":[1,1,1,1,255,255,14,18,0],"\u0012":[1,1,1,1,255,255,15,18,0],"\u0013":[1,1,1,1,255,255,16,18,0],"\u0014":[1,1,1,1,255,255,17,18,0],"\u0015":[1,1,1,1,255,255,18,18,0],"\u0016":[1,1,1,1,255,255,19,18,0],"\u0017":[1,1,1,1,255,255,20,18,0],"\u0018":[1,1,1,1,255,255,21,18,0],"\u0019":[1,1,1,1,255,255,22,18,0],"\u001a":[1,1,1,1,255,255,23,18,0],"\u001b":[1,1,1,1,255,255,24,18,0],"\u001c":[1,1,1,1,255,255,25,18,0],"\u001d":[1,1,1,1,255,255,26,18,0],"\u001e":[1,1,1,1,255,255,27,18,0],"\u001f":[1,1,1,1,255,255,28,18,0]," ":[7,2,1,1,1,1,0],"!":[7,28,1,1,1,1,0],"\"":[7,29,1,1,1,1,0],"#":[7,31,1,1,1,1,0],"$":[7,33,1,1,1,1,0],"%":[7,35,1,1,1,1,0],"&":[7,37,1,1,1,1,0],"'" :[1,1,1,1,255,255,128,18,0],"(":[7,39,1,1,1,1,0],")":[7,42,1,1,1,1,0],"*":[7,45,1,1,1,1,0],"+":[8,3,1,1,1,1,0],",":[7,47,1,1,1,1,0],"-":[1,1,1,1,255,255,130,18,0],".":[7,51,1,1,1,1,0],"/":[7,53,1,1,1,1,0],"0":[13,3,1,1,1,1,0],"1":[13,26,1,1,1,1,0],"2":[13,28,1,1,1,1,0],"3":[13,30,1,1,1,1,0],"4":[13,32,1,1,1,1,0],"5":[13,34,1,1,1,1,0],"6":[13,36,1,1,1,1,0],"7":[13,38,1,1,1,1,0],"8":[13,40,1,1,1,1,0],"9":[13,42,1,1,1,1,0],":":[7,55,1,1,1,1,0],";":[7,58,1,1,1,1,0],"<":[8,14,1,1,1,1,0],"=":[8,18,1,1,1,1,0],">":[8,20,1,1,1,1,0],"?":[7,60,1,1,1,1,0],"@":[7,62,1,1,1,1,0],"A":[14,2,1,1,1,1,0],"B":[14,9,1,1,1,1,0],"C":[14,10,1,1,1,1,0],"D":[14,26,1,1,1,1,0],"E":[14,33,1,1,1,1,0],"F":[14,35,1,1,1,1,0],"G":[14,37,1,1,1,1,0],"H":[14,44,1,1,1,1,0],"I":[14,50,1,1,1,1,0],"J":[14,53,1,1,1,1,0],"K":[14,54,1,1,1,1,0],"L":[14,72,1,1,1,1,0],"M":[14,81,1,1,1,1,0],"N":[14,112,1,1,1,1,0],"O":[14,124,1,1,1,1,0],"P":[14,126,1,1,1,1,0],"Q":[14,137,1,1,1,1,0],"R":[14,138,1,1,1,1,0],"S":[14,145,1,1,1,1,0],"T":[14,153,1,1,1,1,0],"U":[14,159,1,1,1,1,0],"V":[14,162,1,1,1,1,0],"W":[14,164,1,1,1,1,0],"X":[14,166,1,1,1,1,0],"Y":[14,167,1,1,1,1,0],"Z":[14,169,1,1,1,1,0],"[":[7,63,1,1,1,1,0],"\\":[7,65,1,1,1,1,0],"]":[7,66,1,1,1,1,0],"^":[7,67,1,1,1,1,0],"_":[7,68,1,1,1,1,0],"`":[7,72,1,1,1,1,0],"a":[14,2,1,1,1,1,0],"b":[14,9,1,1,1,1,0],"c":[14,10,1,1,1,1,0],"d":[14,26,1,1,1,1,0],"e":[14,33,1,1,1,1,0],"f":[14,35,1,1,1,1,0],"g":[14,37,1,1,1,1,0],"h":[14,44,1,1,1,1,0],"i":[14,50,1,1,1,1,0],"j":[14,53,1,1,1,1,0],"k":[14,54,1,1,1,1,0],"l":[14,72,1,1,1,1,0],"m":[14,81,1,1,1,1,0],"n":[14,112,1,1,1,1,0],"o":[14,124,1,1,1,1,0],"p":[14,126,1,1,1,1,0],"q":[14,137,1,1,1,1,0],"r":[14,138,1,1,1,1,0],"s":[14,145,1,1,1,1,0],"t":[14,153,1,1,1,1,0],"u":[14,159,1,1,1,1,0],"v":[14,162,1,1,1,1,0],"w":[14,164,1,1,1,1,0],"x":[14,166,1,1,1,1,0],"y":[14,167,1,1,1,1,0],"z":[14,169,1,1,1,1,0],"{":[7,74,1,1,1,1,0],"|":[7,76,1,1,1,1,0],"}":[7,78,1,1,1,1,0],"~":[7,80,1,1,1,1,0],"\u007f":[1,1,1,1,255,255,29,18,0],"\u0080":[12,250,1,29,1,1,1,0],"\u0081":[12,250,1,30,1,1,1,0],"\u0082":[12,250,1,31,1,1,1,0],"\u0083":[12,250,1,32,1,1,1,0],"\u0084":[12,250,1,33,1,1,1,0],"\u0085":[12,250,1,34,1,1,1,0],"\u0086":[12,250,1,35,1,1,1,0],"\u0087":[12,250,1,36,1,1,1,0],"\u0088":[12,250,1,37,1,1,1,0],"\u0089":[12,250,1,38,1,1,1,0],"\u008a":[12,250,1,39,1,1,1,0],"\u008b":[12,250,1,40,1,1,1,0],"\u008c":[12,250,1,41,1,1,1,0],"\u008d":[12,250,1,42,1,1,1,0],"\u008e":[12,250,1,43,1,1,1,0],"\u008f":[12,250,1,44,1,1,1,0],"\u0090":[12,250,1,45,1,1,1,0],"\u0091":[12,250,1,46,1,1,1,0],"\u0092":[12,250,1,47,1,1,1,0],"\u0093":[12,250,1,48,1,1,1,0],"\u0094":[12,250,1,49,1,1,1,0],"\u0095":[12,250,1,50,1,1,1,0],"\u0096":[12,250,1,51,1,1,1,0],"\u0097":[12,250,1,52,1,1,1,0],"\u0098":[12,250,1,53,1,1,1,0],"\u0099":[12,250,1,54,1,1,1,0],"\u009a":[12,250,1,55,1,1,1,0],"\u009b":[12,250,1,56,1,1,1,0],"\u009c":[12,250,1,57,1,1,1,0],"\u009d":[12,250,1,58,1,1,1,0],"\u009e":[12,250,1,59,1,1,1,0],"\u009f":[12,250,1,60,1,1,1,0],"\u00a0":[7,4,1,1,1,1,0],"\u00a1":[7,81,1,1,1,1,0],"\u00a2":[7,151,1,1,1,1,0],"\u00a3":[7,152,1,1,1,1,0],"\u00a4":[7,153,1,1,1,1,0],"\u00a5":[7,154,1,1,1,1,0],"\u00a6":[7,82,1,1,1,1,0],"\u00a7":[10,6,1,1,1,1,0],"\u00a8":[7,83,1,1,1,1,0],"\u00a9":[10,7,1,1,1,1,0],"\u00aa":[14,2,1,3,1,6,1,1,0],"\u00ab":[8,24,1,1,1,1,0],"\u00ac":[10,8,1,1,1,1,0],"\u00ad":[1,1,1,1,0],"\u00ae":[10,9,1,1,1,1,0],"\u00af":[7,84,1,1,1,1,0],"\u00b0":[10,10,1,1,1,1,0],"\u00b1":[8,23,1,1,1,1,0],"\u00b2":[13,28,1,1,6,1,1,0],"\u00b3":[13,30,1,1,6,1,1,0],"\u00b4":[7,85,1,1,1,1,0],"\u00b5":[10,11,1,1,1,1,0],"\u00b6":[10,12,1,1,1,1,0],"\u00b7":[10,13,1,1,1,1,0],"\u00b8":[7,86,1,1,1,1,0],"\u00b9":[13,26,1,1,6,1,1,0],"\u00ba":[14,124,1,3,1,6,1,1,0],"\u00bb":[8,26,1,1,1,1,0],"\u00bc":[13,13,1,1,1,1,0],"\u00bd":[13,17,1,1,1,1,0],"\u00be":[13,21,1,1,1,1,0],"\u00bf":[7,87,1,1,1,1,0],"\u00c0":[14,2,1,15,1,1,1,0],"\u00c1":[14,2,1,14,1,1,1,0],"\u00c2":[14,2,1,18,1,1,1,0],"\u00c3":[14,2,1,25,1,1,1,0],"\u00c4":[14,2,1,19,1,1,1,0],"\u00c5":[14,2,1,26,1,1,1,0],"\u00c6":[14,2,14,33,1,1,1,1,0],"\u00c7":[14,10,1,28,1,1,1,0],"\u00c8":[14,33,1,15,1,1,1,0],"\u00c9":[14,33,1,14,1,1,1,0],"\u00ca":[14,33,1,18,1,1,1,0],"\u00cb":[14,33,1,19,1,1,1,0],"\u00cc":[14,50,1,15,1,1,1,0],"\u00cd":[14,50,1,14,1,1,1,0],"\u00ce":[14,50,1,18,1,1,1,0],"\u00cf":[14,50,1,19,1,1,1,0],"\u00d0":[14,26,1,104,1,1,1,0],"\u00d1":[14,112,1,25,1,1,1,0],"\u00d2":[14,124,1,15,1,1,1,0],"\u00d3":[14,124,1,14,1,1,1,0],"\u00d4":[14,124,1,18,1,1,1,0],"\u00d5":[14,124,1,25,1,1,1,0],"\u00d6":[14,124,1,19,1,1,1,0],"\u00d7":[8,28,1,1,1,1,0],"\u00d8":[14,124,1,33,1,1,1,0],"\u00d9":[14,159,1,15,1,1,1,0],"\u00da":[14,159,1,14,1,1,1,0],"\u00db":[14,159,1,18,1,1,1,0],"\u00dc":[14,159,1,19,1,1,1,0],"\u00dd":[14,167,1,14,1,1,1,0],"\u00de":[14,153,14,44,1,1,1,1,0],"\u00df":[14,145,14,145,1,1,1,1,0],"\u00e0":[14,2,1,15,1,1,1,0],"\u00e1":[14,2,1,14,1,1,1,0],"\u00e2":[14,2,1,18,1,1,1,0],"\u00e3":[14,2,1,25,1,1,1,0],"\u00e4":[14,2,1,19,1,1,1,0],"\u00e5":[14,2,1,26,1,1,1,0],"\u00e6":[14,2,14,33,1,1,1,1,0],"\u00e7":[14,10,1,28,1,1,1,0],"\u00e8":[14,33,1,15,1,1,1,0],"\u00e9":[14,33,1,14,1,1,1,0],"\u00ea":[14,33,1,18,1,1,1,0],"\u00eb":[14,33,1,19,1,1,1,0],"\u00ec":[14,50,1,15,1,1,1,0],"\u00ed":[14,50,1,14,1,1,1,0],"\u00ee":[14,50,1,18,1,1,1,0],"\u00ef":[14,50,1,19,1,1,1,0],"\u00f0":[14,26,1,104,1,1,1,0],"\u00f1":[14,112,1,25,1,1,1,0],"\u00f2":[14,124,1,15,1,1,1,0],"\u00f3":[14,124,1,14,1,1,1,0],"\u00f4":[14,124,1,18,1,1,1,0],"\u00f5":[14,124,1,25,1,1,1,0],"\u00f6":[14,124,1,19,1,1,1,0],"\u00f7":[8,29,1,1,1,1,0],"\u00f8":[14,124,1,33,1,1,1,0],"\u00f9":[14,159,1,15,1,1,1,0],"\u00fa":[14,159,1,14,1,1,1,0],"\u00fb":[14,159,1,18,1,1,1,0],"\u00fc":[14,159,1,19,1,1,1,0],"\u00fd":[14,167,1,14,1,1,1,0],"\u00fe":[14,153,14,44,1,1,1,1,0],"\u00ff":[14,167,1,19,1,1,1,0]}
'''.strip()
# fmt: on

DOTNET_SORT_KEY_DB = json.loads(_DOTNET_SORT_KEY_DB_JSON)


def dotnet_get_sort_key(s, db=None):
    """Convert a string to its .NET sort key byte array (CompareOptions.IgnoreCase).

    Reimplements CompareInfo.GetSortKey() for the en-US invariant culture.
    Ported from crapsecrets (credit @irsdl).
    """
    if db is None:
        db = DOTNET_SORT_KEY_DB

    # Normalize: use lowercase for alphabetic chars via the DB
    proc = []
    for ch in s:
        if ch.isalpha():
            low = ch.lower()
            proc.append(low if low in db else ch.upper())
        else:
            proc.append(ch)
    proc = "".join(proc)

    # First pass: build main_result from primary weights
    main_result = []
    for i, ch in enumerate(proc):
        if ch not in db:
            raise ValueError(f"Character {repr(ch)} not found in sort key mapping.")
        mapping = db[ch]
        main_result.extend(mapping[0:2])
        if i < len(proc) - 1:
            for byte in mapping[2:]:
                if byte == 1:
                    break
                main_result.append(byte)
        else:
            for byte in mapping[2:]:
                main_result.append(byte)
                if byte == 1:
                    break
    if not main_result or main_result[-1] != 1:
        main_result.append(1)

    # Second pass: build temp array from secondary weights
    temp = []
    for ch in proc:
        mapping = db[ch]
        for idx, byte in enumerate(mapping[2:]):
            if byte == 1:
                rem = mapping[2:]
                if idx + 1 < len(rem):
                    next_byte = rem[idx + 1]
                    temp.append(2 if next_byte == 1 else next_byte)
                break

    # Filter temp: remove trailing 2s after last value > 2
    last_gt_index = None
    for i, val in enumerate(temp):
        if val > 2:
            last_gt_index = i
    if last_gt_index is not None:
        filtered_temp = temp[: last_gt_index + 1] + [val for val in temp[last_gt_index + 1 :] if val != 2]
    else:
        filtered_temp = []

    if filtered_temp:
        main_result.extend(filtered_temp)
    main_result.extend([1, 1, 1, 0])
    return main_result


def dotnet_legacy_hash(sort_key):
    """Compute .NET GetNonRandomizedStringComparerHashCode from a sort key.

    Dual-accumulator algorithm: init both to 0x1505, process pairs,
    combine with 0x5d588b65. Returns 32-bit unsigned int.
    Ported from crapsecrets (credit @irsdl).
    """
    acc1 = 0x1505
    acc2 = 0x1505
    i = 0
    n = len(sort_key)

    while i < n and sort_key[i] != 0:
        acc1 = (acc1 * 33) ^ sort_key[i]
        if i + 1 >= n or sort_key[i + 1] == 0:
            break
        acc2 = (acc2 * 33) ^ sort_key[i + 1]
        i += 2

    return ((acc2 * 0x5D588B65) + acc1) & 0xFFFFFFFF


def dotnet_string_hashcode(s, db=None):
    """Compute the .NET non-randomized string comparer hashcode for a string."""
    return dotnet_legacy_hash(dotnet_get_sort_key(s, db))


class Viewstate_Helpers:
    """Computes __VIEWSTATEGENERATOR values and KDF purpose strings from URLs.

    Given a URL (and optionally a known generator), this class can:
    - Calculate all possible generator values for a URL
    - Brute-force the path/apppath combination from a known generator
    - Generate all possible SP800-108 KDF specific purpose strings
    - Compute IsolateApps hashcodes for app paths
    """

    DEFAULT_PAGES = [
        "default.aspx",
        "index.aspx",
        "home.aspx",
        "default2.aspx",
        "default3.aspx",
        "start.aspx",
        "welcome.aspx",
        "main.aspx",
        "landing.aspx",
        "mainpage.aspx",
        "error.aspx",
        "CustomError.aspx",
    ]

    DEFAULT_PAGES_LARGE = [
        "default.aspx",
        "index.aspx",
        "home.aspx",
        "default2.aspx",
        "default3.aspx",
        "start.aspx",
        "welcome.aspx",
        "main.aspx",
        "landing.aspx",
        "mainpage.aspx",
        "portal.aspx",
        "startpage.aspx",
        "dashboard.aspx",
        "overview.aspx",
        "entry.aspx",
        "defaultview.aspx",
        "defaultpage.aspx",
        "defaulthome.aspx",
        "defaultindex.aspx",
        "intro.aspx",
        "index2.aspx",
        "welcomepage.aspx",
    ]

    COMMON_PAGES = [
        "default.aspx",
        "index.aspx",
        "error.aspx",
        "errors.aspx",
        "errorpage.aspx",
        "404.aspx",
        "500.aspx",
        "CustomError.aspx",
        "NotFound.aspx",
        "generic.aspx",
        "genericerror.aspx",
        "accessdenied.aspx",
        "denied.aspx",
        "nopermission.aspx",
        "notallowed.aspx",
        "restricted.aspx",
        "unauthorized.aspx",
        "unauthorised.aspx",
        "unavailable.aspx",
        "forbidden.aspx",
        "error404.aspx",
        "error500.aspx",
        "logon.aspx",
        "login.aspx",
        "signin.aspx",
        "signon.aspx",
        "sso.aspx",
        "ssoerror.aspx",
        "samlerror.aspx",
        "report.aspx",
        "reports.aspx",
        "article.aspx",
        "articles.aspx",
        "cms.aspx",
        "admin.aspx",
        "administrator.aspx",
        "header.aspx",
        "footer.aspx",
        "ApplicationErrorsViewer.aspx",
        "ErrorsViewer.aspx",
        "ApplicationErrors.aspx",
        "Application.aspx",
        "App.aspx",
        "mobile.aspx",
        "privacy.aspx",
    ]

    COMMON_DIRECTORIES = [
        "",
        "page",
        "pages",
        "error",
        "errors",
        "content",
        "contents",
        "errorpage",
        "errorpages",
        "404",
        "500",
        "customerror",
        "notfound",
        "report",
        "reports",
        "article",
        "articles",
        "cms",
        "portal",
        "admin",
        "administrator",
        "login",
        "signin",
        "signon",
        "blog",
        "www",
        "wwwroot",
        "web",
        "website",
        "site",
        "sites",
        "view",
        "views",
        "ui",
        "ux",
        "user",
        "title",
        "titles",
        "dashboard",
        "welcome",
        "webui",
        "application",
        "app",
        "applications",
        "apps",
        "secure",
        "protected",
    ]

    def __init__(self, url, generator="00000000"):
        self.url = self._normalize_url(url)
        self.db = DOTNET_SORT_KEY_DB
        self.verified_path = None
        self.verified_apppath = None

        if generator != "00000000":
            self.verified_path, self.verified_apppath = self.find_valid_path_params_by_generator(generator)

    @staticmethod
    def _normalize_url(url):
        """Normalize URL: backslash->slash, collapse double slashes, strip cookieless tokens, truncate after .aspx."""
        # Remove cookieless session tokens like /(S(xyz))/
        url = re.sub(r"/\([A-Z]\([A-Za-z0-9_]+\)\)/", "/", url)
        parsed = urlparse(url)
        path = parsed.path.replace("\\", "/")
        path = re.sub(r"/+", "/", path)
        url = parsed._replace(path=path).geturl()
        # Truncate after .aspx
        aspx_pos = url.lower().find(".aspx")
        if aspx_pos != -1:
            slash_pos = url.find("/", aspx_pos)
            if slash_pos != -1:
                url = url[: aspx_pos + 5]
        return url

    def _extract_path_and_apppaths(self, url):
        """Parse URL, extract path and list of possible IIS app paths (/ plus each directory level)."""
        parsed = urlparse(url)
        str_path = parsed.path
        str_path = str_path if str_path.startswith("/") else "/" + str_path

        iis_apps = ["/"]
        if str_path != "/":
            # Strip trailing slash, split into parts
            parts = str_path.rstrip("/").split("/")[1:]
            # If last part looks like a file, exclude it from directory levels
            if parts and "." in parts[-1]:
                dir_parts = parts[:-1]
            else:
                dir_parts = parts
            current = ""
            for part in dir_parts:
                current += "/" + part
                iis_apps.append(current)

        str_path = re.sub(r"/+", "/", str_path)
        iis_apps = list(dict.fromkeys(re.sub(r"/+", "/", p) for p in iis_apps))
        return str_path, iis_apps

    @staticmethod
    def _simulate_template_source_directory(path):
        """Get the directory portion of a path (strip filename if it has an extension)."""
        parts = path.split("/")
        path = "/".join(parts[:-1]) if "." in parts[-1] else path
        path = path.rstrip("/") if path else "/"
        return path if path else "/"

    def _simulate_get_type_name(self, str_path, iis_app_in_path, add_default_page=True):
        """Compute the .NET type name from path and apppath."""
        iis_app_in_path = "/" + iis_app_in_path.lower().lstrip("/")
        if add_default_page:
            str_path = str_path + "/default.aspx" if not str_path.lower().endswith(".aspx") else str_path
        iis_app_in_path = iis_app_in_path + "/" if not iis_app_in_path.endswith("/") else iis_app_in_path
        if iis_app_in_path in str_path.lower():
            str_path = str_path.lower().split(iis_app_in_path, 1)[1]
        str_path = str_path.lstrip("/")
        str_path = str_path.replace(".", "_").replace("/", "_")
        return str_path.rstrip("/")

    def calculate_generator_value(self, path, apppath):
        """Compute the __VIEWSTATEGENERATOR hex value for a path/apppath combination."""
        stsd = self._simulate_template_source_directory(path)
        sgtn = self._simulate_get_type_name(path, apppath, add_default_page=False)
        h1 = dotnet_string_hashcode(stsd, self.db)
        h2 = dotnet_string_hashcode(sgtn, self.db)
        return format((h1 + h2) & 0xFFFFFFFF, "08X")

    def find_valid_path_params_by_generator(self, generator):
        """Brute-force the path/apppath combination that produces the given generator value.

        3-phase progressive search:
        1. URL-derived paths x apppaths
        2. Apppath subdirectories x common pages (limited set)
        3. Common directories x common pages (broader set)
        """
        generator = generator.upper()
        str_path, potential_apppaths = self._extract_path_and_apppaths(self.url)
        seen = set()

        # Phase 1: URL-derived paths
        temp_paths = []
        if ".aspx" not in str_path.lower():
            if not str_path.endswith("/"):
                temp_paths.append(str_path)
                temp_paths.append(str_path + ".aspx")
            else:
                temp_paths.append(str_path.rstrip("/"))
        else:
            temp_paths.append(str_path)

        # Also consider subdirectory paths as possible pages
        for apppath in potential_apppaths:
            if apppath != "/":
                temp_paths.append(apppath)
                temp_paths.append(apppath + ".aspx")
        temp_paths = list(dict.fromkeys(temp_paths))

        for path in temp_paths:
            for apppath in potential_apppaths:
                combo = (path, apppath)
                seen.add(combo)
                if generator == self.calculate_generator_value(path, apppath):
                    return path, apppath

        # Phase 2: Apppath subdirectories x common pages
        for apppath in potential_apppaths:
            for common_dir in self.COMMON_DIRECTORIES:
                for default_page in self.DEFAULT_PAGES_LARGE:
                    default_path = f"/{apppath}/{common_dir}/{default_page}".replace("//", "/")
                    default_path = re.sub(r"/+", "/", default_path)
                    dp_path, dp_apppaths = self._extract_path_and_apppaths(f"http://x{default_path}")
                    for dp_apppath in dp_apppaths:
                        combo = (dp_path, dp_apppath)
                        if combo in seen:
                            continue
                        seen.add(combo)
                        if generator == self.calculate_generator_value(dp_path, dp_apppath):
                            return dp_path, dp_apppath

        # Phase 3: Common directories x common pages
        combined_pages = list(dict.fromkeys(self.COMMON_PAGES + self.DEFAULT_PAGES_LARGE))
        for common_dir in self.COMMON_DIRECTORIES:
            for common_page in combined_pages:
                common_path = f"/{common_dir}/{common_page}".replace("//", "/")
                common_path = re.sub(r"/+", "/", common_path)
                cp_path, cp_apppaths = self._extract_path_and_apppaths(f"http://x{common_path}")
                for apppath in cp_apppaths:
                    combo = (cp_path, apppath)
                    if combo in seen:
                        continue
                    seen.add(combo)
                    if generator == self.calculate_generator_value(cp_path, apppath):
                        return cp_path, apppath

        return None, None

    def get_all_specific_purposes(self):
        """Return list of [TemplateSourceDirectory, Type] purpose string pairs for all candidate combos."""
        if self.verified_path and self.verified_apppath:
            str_path = self.verified_path
            potential_apppaths = [self.verified_apppath]
        else:
            str_path, potential_apppaths = self._extract_path_and_apppaths(self.url)

        template_source = self._simulate_template_source_directory(str_path)

        # Generate all unique type names
        seen_types = set()
        all_purposes = []

        temp_paths = [str_path]
        if ".aspx" not in str_path.lower():
            if not str_path.endswith("/"):
                temp_paths.append(str_path + ".aspx")
            for dp in ["default.aspx"]:
                if str_path.endswith("/"):
                    temp_paths.append(str_path + dp)
                else:
                    temp_paths.append(str_path + "/" + dp)

        for apppath in potential_apppaths:
            apppath_norm = "/" + apppath.lower().lstrip("/")
            apppath_norm = apppath_norm + "/" if not apppath_norm.endswith("/") else apppath_norm
            for temp_path in temp_paths:
                type_name = temp_path.lower()
                if apppath_norm in type_name:
                    type_name = type_name.split(apppath_norm, 1)[1]
                type_name = type_name.lstrip("/")
                type_name = type_name.replace(".", "_").replace("/", "_")
                type_name = type_name.rstrip("/")
                if type_name not in seen_types:
                    seen_types.add(type_name)
                    all_purposes.append(
                        [
                            f"TemplateSourceDirectory: {template_source.upper()}",
                            f"Type: {type_name.upper()}",
                        ]
                    )

        return all_purposes

    def get_apppaths_hashcodes(self):
        """Return list of .NET string hashcodes for candidate app paths (for IsolateApps)."""
        if self.verified_apppath:
            apppaths = [self.verified_apppath]
        else:
            _, apppaths = self._extract_path_and_apppaths(self.url)
        return [dotnet_string_hashcode(apppath, self.db) for apppath in apppaths]
