import struct
import secrets
from collections import namedtuple
from array import array
from hashlib import sha256

Metadata = namedtuple("Metadata", ("tag", "nonce"))
metadata_format = "<16s12s"


class InvalidTagException(Exception):
    pass


def encrypt(data, key):
    """
    Encrypts the given data with the given key.
    Key can either be a string or a bytes-like object, in which case it must be 32 bytes long.
    Data can be a string or a bytes-like object.

    Returns an encrypted bytes object.
    """
    if isinstance(key, bytes) and len(key) != 32:
        raise ValueError("Key size must be 32 bytes")
    elif not isinstance(key, str):
        raise TypeError("Key must be of type 'bytes' or 'str'")

    if isinstance(data, str):
        data = data.encode()
    elif not isinstance(data, bytes):
        raise TypeError("Data must be of type 'bytes'")

    nonce = secrets.token_bytes(12)

    if isinstance(key, str):
        key = sha256(key.encode() + nonce).digest()

    aead = AeadChaCha20Poly1305(key, nonce)

    result = aead.encrypt(data)
    tag = aead.finish()

    return struct.pack(metadata_format, tag, aead.nonce) + result


def decrypt(data, key):
    """
    Decrypts the given data with the given key.
    Key can either be a string or a bytes-like object, in which case it must be 32-bytes long.
    Data can be a string or a bytes-like object.
    Raises InvalidTagException if the key is invalid or the data is corrupted.

    Returns a decrypted bytes object.
    """
    if isinstance(key, bytes):
        if len(key) != 32:
            raise ValueError("Key size must be 32 bytes")
    elif not isinstance(key, str):
        raise TypeError("Key must be of type 'bytes'")

    if isinstance(data, str):
        data = data.encode()
    elif not isinstance(data, bytes):
        raise TypeError("Data must be of type 'bytes' or 'str'")

    metadata = Metadata(*struct.unpack(metadata_format,
                                       data[:struct.calcsize(metadata_format)]))

    if isinstance(key, str):
        key = sha256(key.encode() + metadata.nonce).digest()

    aead = AeadChaCha20Poly1305(key, metadata.nonce)

    result = aead.decrypt(data[struct.calcsize(metadata_format):])
    tag = aead.finish()

    if metadata.tag != tag:
        raise InvalidTagException(
            "Invalid tag, either key is invalid or the data is corrupted")

    return result


def rotate_left(value, count):
    return ((value << count) & 0xffffffff) | value >> (32 - count)


def chunks(iter, n):
    for i in range(0, len(iter), n):
        yield iter[i:i + n]


def pad(n, p):
    if n % p == 0:
        return bytes()
    else:
        return bytes((0,) * (p - (n % p)))


class ChaCha20:
    @staticmethod
    def quarter_round(state, a, b, c, d):
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = rotate_left(state[d] ^ state[a], 16)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = rotate_left(state[b] ^ state[c], 12)
        state[a] = (state[a] + state[b]) & 0xffffffff
        state[d] = rotate_left(state[d] ^ state[a], 8)
        state[c] = (state[c] + state[d]) & 0xffffffff
        state[b] = rotate_left(state[b] ^ state[c], 7)

    @staticmethod
    def double_round(state):
        ChaCha20.quarter_round(state, 0, 4,  8, 12)
        ChaCha20.quarter_round(state, 1, 5,  9, 13)
        ChaCha20.quarter_round(state, 2, 6, 10, 14)
        ChaCha20.quarter_round(state, 3, 7, 11, 15)
        ChaCha20.quarter_round(state, 0, 5, 10, 15)
        ChaCha20.quarter_round(state, 1, 6, 11, 12)
        ChaCha20.quarter_round(state, 2, 7,  8, 13)
        ChaCha20.quarter_round(state, 3, 4,  9, 14)

    @staticmethod
    def get_state(key, nonce, count):
        state = array("L")

        state.extend((1634760805, 857760878, 2036477234, 1797285236))
        state.extend(struct.unpack("<8L", key))
        state.extend((count,))
        state.extend(struct.unpack("<3L", nonce))

        return state

    @staticmethod
    def block(data, key, nonce, count):
        state = ChaCha20.get_state(key, nonce, count)
        working_state = array("L", state)

        for _ in range(10):
            ChaCha20.double_round(working_state)

        key_stream = struct.pack(
            "<16L", *((state[i] + working_state[i]) & 0xffffffff for i in range(16)))
        return bytes(x ^ y for x, y in zip(data, key_stream))

    def __init__(self, key, nonce=None, count=0):
        if not isinstance(key, bytes):
            raise TypeError("Key must be of type 'bytes'")

        if len(key) != 32:
            raise ValueError("Key must be 32 bytes long")

        if not isinstance(nonce, bytes):
            raise TypeError("Nonce must be of type 'bytes' or None")

        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long")

        if not isinstance(count, int):
            raise TypeError("Count must be of type 'int'")

        if count < 0:
            raise ValueError("Count must be 0 or greater")

        self.key = key
        self.nonce = nonce
        self.count = count

    def encrypt(self, data):
        if not isinstance(data, bytes):
            raise TypeError("Data must be of type 'bytes'")

        for chunk in chunks(data, 64):
            yield ChaCha20.block(chunk, self.key, self.nonce, self.count)
            self.count += 1

    def decrypt(self, data):
        return self.encrypt(data)


class Poly1305:
    p = 0x3fffffffffffffffffffffffffffffffb

    def __init__(self, key):
        if not isinstance(key, bytes):
            raise TypeError("Key must be of type 'bytes'")

        if len(key) != 32:
            raise ValueError("Key must be 32 bytes long")

        self.accumulator = 0
        self.r = int.from_bytes(key[0:16], byteorder="little")
        self.r &= 0x0ffffffc0ffffffc0ffffffc0fffffff
        self.s = int.from_bytes(key[16:32], byteorder="little")

    def update(self, data):
        for chunk in chunks(data, 16):
            self.accumulator += int.from_bytes(chunk +
                                               b"\x01", byteorder="little")
            self.accumulator = (self.r * self.accumulator) % self.p

    def finish(self):
        self.accumulator += self.s
        return (self.accumulator & 0xffffffffffffffffffffffffffffffff).to_bytes(16, byteorder="little")

    def create_tag(self, data):
        self.update(data)
        return self.finish()


class AeadChaCha20Poly1305:
    @staticmethod
    def generate_poly1305_key(key, nonce):
        return ChaCha20.block(b"\0" * 64, key, nonce, 0)[:32]

    def __init__(self, key, nonce=None, additional_data=b"ChaCha20Poly1305"):
        if not isinstance(key, bytes):
            raise TypeError("Key must be of type 'bytes'")

        if len(key) != 32:
            raise ValueError("Key must be 32 bytes long")

        if not isinstance(nonce, bytes):
            raise TypeError("Nonce must be of type 'bytes' or None")

        if len(nonce) != 12:
            raise ValueError("Nonce must be 12 bytes long")

        if additional_data is None:
            additional_data = bytes()

        if not isinstance(additional_data, bytes):
            raise TypeError("Additional_data must be of type 'bytes'")

        self.key = key
        self.nonce = nonce
        self.data_length = 0
        self.additional_data = additional_data

        self.chacha = ChaCha20(self.key, self.nonce, 1)
        self.poly = Poly1305(self.generate_poly1305_key(self.key, self.nonce))

        self.poly.update(self.additional_data +
                         pad(len(self.additional_data), 16))

    def decrypt(self, data):
        result = bytes()

        self.poly.update(data + pad(len(data), 16))
        self.data_length += len(data)

        for chunk in self.chacha.decrypt(data):
            result += chunk

        return result

    def encrypt(self, data):
        result = bytes()

        for chunk in self.chacha.encrypt(data):
            self.poly.update(chunk + pad(len(chunk), 16))
            self.data_length += len(chunk)
            result += chunk

        return result

    def finish(self):
        self.poly.update(struct.pack(
            "<Q", len(self.additional_data)) + struct.pack("<Q", self.data_length))
        return self.poly.finish()
