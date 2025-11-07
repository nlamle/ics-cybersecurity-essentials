"""Utility helpers for symmetric encryption lab."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Optional, Tuple

from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes
from Crypto.Util import Counter
from Crypto.Util.Padding import pad, unpad


@dataclass
class CipherParams:
    algorithm: str
    mode: str
    key: bytes
    iv: Optional[bytes]


BLOCK_SIZES = {"aes": 16, "des": 8}
ALGORITHMS = {"aes": AES, "des": DES}
MODES_REQUIRING_IV = {"cbc", "ctr", "cfb", "ofb"}


class InvalidParameterError(Exception):
    """Raised when the user supplies unsupported keys, IVs, or modes."""


def _ensure_key_size(algorithm: str, key_bytes: bytes) -> bytes:
    if algorithm == "aes" and len(key_bytes) not in {16, 24, 32}:
        raise InvalidParameterError("AES key must be 16, 24, or 32 bytes long")
    if algorithm == "des" and len(key_bytes) != 8:
        raise InvalidParameterError("DES key must be exactly 8 bytes long")
    return key_bytes


def generate_key_and_iv(
    algorithm: str,
    mode: str,
    key_hex: str = "",
    iv_hex: Optional[str] = None,
) -> Tuple[bytes, Optional[bytes]]:
    """Return key/IV bytes, generating them when not supplied."""
    block_size = BLOCK_SIZES[algorithm]

    key_bytes = bytes.fromhex(key_hex) if key_hex else get_random_bytes(block_size)
    key_bytes = _ensure_key_size(algorithm, key_bytes)

    needs_iv = mode in MODES_REQUIRING_IV
    iv_bytes: Optional[bytes] = None
    if needs_iv:
        if iv_hex:
            iv_bytes = bytes.fromhex(iv_hex)
        else:
            iv_bytes = get_random_bytes(block_size)
        if len(iv_bytes) != block_size:
            raise InvalidParameterError("IV must match block size")

    return key_bytes, iv_bytes


def _build_cipher(params: CipherParams):
    cipher_cls = ALGORITHMS[params.algorithm]
    mode = params.mode

    if mode == "ecb":
        return cipher_cls.new(params.key, cipher_cls.MODE_ECB)

    if mode == "cbc":
        if params.iv is None:
            raise InvalidParameterError("CBC mode requires an IV")
        return cipher_cls.new(params.key, cipher_cls.MODE_CBC, iv=params.iv)

    if mode == "ctr":
        if params.iv is None:
            raise InvalidParameterError("CTR mode requires a nonce/IV value")
        initial_value = int.from_bytes(params.iv, byteorder="big")
        counter = Counter.new(cipher_cls.block_size * 8, initial_value=initial_value)
        return cipher_cls.new(params.key, cipher_cls.MODE_CTR, counter=counter)

    raise InvalidParameterError(f"Unsupported mode: {mode}")


def encrypt_file(
    input_path: Path,
    output_path: Path,
    algorithm: str,
    mode: str,
    key: bytes,
    iv: Optional[bytes],
) -> None:
    """Encrypt a file and write ciphertext."""
    params = CipherParams(algorithm, mode, key, iv)
    cipher = _build_cipher(params)

    data = input_path.read_bytes()
    if mode in {"ecb", "cbc"}:  # block modes need padding
        data = pad(data, cipher.block_size)

    ciphertext = cipher.encrypt(data)
    output_path.write_bytes(ciphertext)
    print(f"Ciphertext written to {output_path}")


def decrypt_file(
    input_path: Path,
    output_path: Path,
    algorithm: str,
    mode: str,
    key: bytes,
    iv: Optional[bytes],
) -> None:
    """Decrypt a file and write plaintext."""
    params = CipherParams(algorithm, mode, key, iv)
    cipher = _build_cipher(params)

    data = input_path.read_bytes()
    plaintext = cipher.decrypt(data)

    if mode in {"ecb", "cbc"}:
        plaintext = unpad(plaintext, cipher.block_size)

    output_path.write_bytes(plaintext)
    print(f"Plaintext written to {output_path}")


def encrypt_bytes(
    data: bytes,
    algorithm: str,
    mode: str,
    key: bytes,
    iv: Optional[bytes],
) -> bytes:
    """Encrypt an in-memory payload and return ciphertext."""
    params = CipherParams(algorithm, mode, key, iv)
    cipher = _build_cipher(params)
    payload = pad(data, cipher.block_size) if mode in {"ecb", "cbc"} else data
    return cipher.encrypt(payload)


def decrypt_bytes(
    data: bytes,
    algorithm: str,
    mode: str,
    key: bytes,
    iv: Optional[bytes],
) -> bytes:
    """Decrypt an in-memory payload and return plaintext."""
    params = CipherParams(algorithm, mode, key, iv)
    cipher = _build_cipher(params)
    plaintext = cipher.decrypt(data)
    if mode in {"ecb", "cbc"}:
        plaintext = unpad(plaintext, cipher.block_size)
    return plaintext
