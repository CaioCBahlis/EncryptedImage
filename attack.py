#!/usr/bin/env python3

import argparse
from pathlib import Path

KEY_LENGTH = 24
# Known plaintext from the first 16 bytes of every PNG file.
PNG_HEADER = bytes.fromhex("89504e470d0a1a0a0000000d49484452")
# The final PNG chunk is fixed when there is no trailing data before padding.
PNG_END = bytes.fromhex("0000000049454e44ae426082")
DEFAULT_CIPHERTEXT = Path("BITSCTFfullhd.png")


def _validate_ciphertext(ciphertext: bytes) -> None:
    # Encryption always pads to a whole number of 24-byte blocks.
    if len(ciphertext) < KEY_LENGTH or len(ciphertext) % KEY_LENGTH != 0:
        raise ValueError(f"ciphertext length must be a positive multiple of {KEY_LENGTH}")


def _xor_bytes(left: bytes, right: bytes) -> bytes:
    if len(left) != len(right):
        raise ValueError("byte sequences must have equal length")
    # K = C XOR P follows from C = P XOR K because XOR is self-inverse.
    return bytes(first ^ second for first, second in zip(left, right))


def _add_constraint(constraints: dict[int, int], index: int, value: int) -> bool:
    # The key repeats every 24 bytes, so every position maps into one key byte.
    index %= KEY_LENGTH
    if index in constraints:
        # Different evidence for the same key byte means a candidate is invalid.
        return constraints[index] == value
    constraints[index] = value
    return True


def recover_header_key(ciphertext: bytes) -> bytes:
    # Compare ciphertext with the known PNG header to recover K[0:16].
    _validate_ciphertext(ciphertext)
    return _xor_bytes(ciphertext[: len(PNG_HEADER)], PNG_HEADER)


def recover_full_key(ciphertext: bytes) -> tuple[bytes, int]:
    _validate_ciphertext(ciphertext)
    header_key = recover_header_key(ciphertext)
    candidates: list[tuple[bytes, int]] = []

    # The padding length is unknown, so test every valid value from 1 to 24.
    for padding_length in range(1, KEY_LENGTH + 1):
        # M is the original PNG length before padding was appended.
        original_length = len(ciphertext) - padding_length
        if original_length < len(PNG_HEADER) + len(PNG_END):
            continue

        # Seed each candidate with the 16 bytes already known from the header.
        constraints = {index: value for index, value in enumerate(header_key)}
        consistent = True

        # IEND is the final 12 bytes of the PNG and sits immediately before padding.
        for offset, expected in enumerate(PNG_END):
            position = original_length - len(PNG_END) + offset
            value = ciphertext[position] ^ expected
            if not _add_constraint(constraints, position, value):
                consistent = False
                break

        if not consistent:
            continue

        # add_pad writes L bytes whose value is also L.
        for offset in range(padding_length):
            position = original_length + offset
            value = ciphertext[position] ^ padding_length
            if not _add_constraint(constraints, position, value):
                consistent = False
                break

        # Keep only candidates that fill all 24 key bytes without conflicts.
        if consistent and len(constraints) == KEY_LENGTH:
            key = bytes(constraints[index] for index in range(KEY_LENGTH))
            candidates.append((key, padding_length))

    if not candidates:
        raise ValueError("no padding length produced a consistent 24-byte key")

    # Do not guess if the ciphertext supports more than one consistent key.
    if len(candidates) > 1:
        details = ", ".join(
            f"L={padding_length}:{key.hex()}" for key, padding_length in candidates
        )
        raise ValueError(f"multiple consistent keys found: {details}")

    return candidates[0]


# The remaining functions are teammate handoff points for the second half of the attack.
def decrypt_image(ciphertext: bytes, key: bytes) -> bytes:
    raise NotImplementedError("teammate task: decrypt ciphertext with the repeating key")


def validate_png(data: bytes) -> None:
    raise NotImplementedError("teammate task: validate PNG structure and chunk CRCs")


def extract_flag(data: bytes) -> str:
    raise NotImplementedError("teammate task: extract the BITSCTF flag")


def _format_key(key: bytes) -> str:
    return " ".join(f"{byte:02x}" for byte in key)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recover the repeating XOR key from the encrypted PNG."
    )
    parser.add_argument(
        "ciphertext",
        nargs="?",
        type=Path,
        default=DEFAULT_CIPHERTEXT,
        help=f"encrypted PNG path (default: {DEFAULT_CIPHERTEXT})",
    )
    args = parser.parse_args(argv)

    # Read binary data directly; the CLI never converts ciphertext to text.
    try:
        ciphertext = args.ciphertext.read_bytes()
    except OSError as error:
        parser.error(f"could not read {args.ciphertext}: {error}")

    try:
        header_key = recover_header_key(ciphertext)
        key, padding_length = recover_full_key(ciphertext)
    except ValueError as error:
        parser.error(str(error))

    print(f"PNG header key bytes: {_format_key(header_key)}")
    print(f"Recovered 24-byte key: {_format_key(key)}")
    print(f"Recovered padding length: {padding_length}")
    print("Next teammate tasks: decrypt image, validate PNG, extract BITSCTF flag")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
