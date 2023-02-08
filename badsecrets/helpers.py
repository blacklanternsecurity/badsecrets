import sys
import hashlib
from badsecrets.errors import BadsecretsException


def unpad(s):
    return s[: -ord(s[len(s) - 1 :])]


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
