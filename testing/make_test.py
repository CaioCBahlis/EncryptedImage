#!/usr/bin/env python3
"""
Creates a small valid test PNG (test.png) if one doesn't exist,
then encrypts it into BITSCTFfullhd.png using the exact algorithm
from enc27-1-1.py with a known 24-byte key.
"""
import os
import struct
import zlib

KEY = b"ABCDEFGHIJKLMNOPQRSTUVWX"  # 24-byte test key (ASCII 65..88)


def create_sample_png(path: str, width: int = 160, height: int = 80) -> None:
    """Create a simple valid RGB PNG with a gradient/stripes pattern."""
    raw_rows = []
    for y in range(height):
        row = bytearray([0])  # filter type 0 (None)
        for x in range(width):
            r = int(255 * x / max(width - 1, 1))
            g = int(255 * y / max(height - 1, 1))
            b = 180 if ((x // 16 + y // 16) % 2 == 0) else 60
            row.extend((r, g, b))
        raw_rows.append(bytes(row))

    def make_chunk(chunk_type: bytes, data: bytes) -> bytes:
        crc = zlib.crc32(chunk_type + data) & 0xFFFFFFFF
        return struct.pack(">I", len(data)) + chunk_type + data + struct.pack(">I", crc)

    ihdr = struct.pack(">IIBBBBB", width, height, 8, 2, 0, 0, 0)
    idat = zlib.compress(b"".join(raw_rows), level=9)
    png_bytes = (
        b"\x89PNG\r\n\x1a\n"
        + make_chunk(b"IHDR", ihdr)
        + make_chunk(b"IDAT", idat)
        + make_chunk(b"IEND", b"")
    )
    with open(path, "wb") as f:
        f.write(png_bytes)


def encrypt_like_enc27(data: bytes, key: bytes) -> tuple[bytes, int]:
    assert len(key) == 24
    pad_len = 24 - (len(data) % 24)
    padded = data + bytes([pad_len]) * pad_len
    enc = bytes(padded[i] ^ key[i % 24] for i in range(len(padded)))
    return enc, pad_len


def main() -> None:
    if not os.path.exists("test.png"):
        create_sample_png("test.png")
        print("Generated sample test.png (160x80 RGB PNG)")

    with open("test.png", "rb") as f:
        data = f.read()

    enc, pad_len = encrypt_like_enc27(data, KEY)
    with open("BITSCTFfullhd.png", "wb") as f:
        f.write(enc)

    print(f"Original test.png size:        {len(data)} bytes")
    print(f"Encrypted BITSCTFfullhd.png:   {len(enc)} bytes")
    print(f"Expected padding length:       {pad_len} bytes")
    print(f"Expected key (ASCII):          {KEY.decode()}")
    print(f"Expected key (decimal):        {list(KEY)}")


if __name__ == "__main__":
    main()
