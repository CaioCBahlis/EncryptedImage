#!/usr/bin/env python3

KEY_LENGTH = 24


def supa_encryption(block: bytes, key: bytes) -> bytes:
    # The cipher is a byte-for-byte XOR with the same repeating 24-byte key.
    return bytes(block_byte ^ key_byte for block_byte, key_byte in zip(block, key))


def add_pad(message: bytes) -> bytes:
    # L is always 1..24 and is also the value written into every padding byte.
    padding_length = KEY_LENGTH - len(message) % KEY_LENGTH
    return message + bytes([padding_length]) * padding_length


# Read and write binary data as bytes so Python 3 does not try to write a str
# to a file opened in "wb" mode.
with open('fullhd.png', 'rb') as f:
    data = f.read()

data = add_pad(data)

with open('key.txt', 'rb') as f:
    key = f.read()

if len(key) != KEY_LENGTH:
    raise ValueError(f"key.txt must contain exactly {KEY_LENGTH} bytes")

enc_data = bytearray()
for start in range(0, len(data), KEY_LENGTH):
    block = data[start:start + KEY_LENGTH]
    enc_data.extend(supa_encryption(block, key))

with open('BITSCTFfullhd.png', 'wb') as f:
    f.write(enc_data)
