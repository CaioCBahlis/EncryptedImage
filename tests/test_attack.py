import unittest

from attack import KEY_LENGTH, PNG_END, PNG_HEADER, recover_full_key, recover_header_key

KNOWN_KEY = bytes((index * 37 + 11) & 0xFF for index in range(KEY_LENGTH))


def make_ciphertext(padding_length: int) -> bytes:
    minimum_original_length = len(PNG_HEADER) + len(PNG_END)
    original_length = (KEY_LENGTH - padding_length) % KEY_LENGTH
    while original_length < minimum_original_length:
        original_length += KEY_LENGTH

    filler_length = original_length - minimum_original_length
    plaintext = PNG_HEADER + bytes(filler_length) + PNG_END
    padded = plaintext + bytes([padding_length]) * padding_length
    return bytes(byte ^ KNOWN_KEY[index % KEY_LENGTH] for index, byte in enumerate(padded))


class RecoveryTests(unittest.TestCase):
    def test_recover_header_key(self) -> None:
        ciphertext = make_ciphertext(8)
        self.assertEqual(recover_header_key(ciphertext), KNOWN_KEY[: len(PNG_HEADER)])

    def test_recover_full_key_for_every_padding_length(self) -> None:
        for padding_length in range(1, KEY_LENGTH + 1):
            with self.subTest(padding_length=padding_length):
                key, recovered_padding = recover_full_key(make_ciphertext(padding_length))
                self.assertEqual(key, KNOWN_KEY)
                self.assertEqual(recovered_padding, padding_length)

    def test_rejects_ciphertext_shorter_than_one_block(self) -> None:
        with self.assertRaises(ValueError):
            recover_full_key(b"\x00" * (KEY_LENGTH - 1))

    def test_rejects_ciphertext_that_is_not_block_aligned(self) -> None:
        with self.assertRaises(ValueError):
            recover_full_key(b"\x00" * (KEY_LENGTH + 1))


if __name__ == "__main__":
    unittest.main()
