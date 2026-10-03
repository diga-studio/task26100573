"""Chunked AEAD and key-wrapping primitives.

On-disk ciphertext layout (message files and per-recipient copies alike):
a concatenation of per-chunk AES-256-GCM ciphertexts. Chunk ``i`` uses the
12-byte nonce ``nonce_prefix (8 bytes) || i (4 bytes, big-endian)`` and its
ciphertext is ``len(plaintext_chunk) + 16`` bytes (GCM tag appended).
Plaintext chunks are CHUNK_SIZE bytes except the final one.
"""

from __future__ import annotations

import hashlib
import os

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 1 << 20  # 1 MiB plaintext per AEAD chunk
NONCE_PREFIX_LEN = 8
TAG_LEN = 16
DATA_KEY_LEN = 32  # AES-256


def new_nonce_prefix() -> bytes:
    return os.urandom(NONCE_PREFIX_LEN)


def new_data_key() -> bytes:
    return os.urandom(DATA_KEY_LEN)


def _chunk_nonce(nonce_prefix: bytes, index: int) -> bytes:
    return nonce_prefix + index.to_bytes(4, "big")


def encrypt_chunks(key: bytes, nonce_prefix: bytes, reader, writer) -> tuple[int, bytes]:
    """Encrypt plaintext read from `reader` into `writer`.

    Returns (total_plaintext_size, sha256_of_plaintext).
    """
    aead = AESGCM(key)
    hasher = hashlib.sha256()
    total = 0
    index = 0
    while True:
        chunk = reader.read(CHUNK_SIZE)
        if not chunk:
            break
        hasher.update(chunk)
        total += len(chunk)
        writer.write(aead.encrypt(_chunk_nonce(nonce_prefix, index), chunk, None))
        index += 1
    return total, hasher.digest()


def decrypt_chunks(key: bytes, nonce_prefix: bytes, reader, writer) -> int:
    """Decrypt chunked ciphertext from `reader` into `writer`. Returns plaintext size."""
    aead = AESGCM(key)
    total = 0
    index = 0
    while True:
        chunk = reader.read(CHUNK_SIZE + TAG_LEN)
        if not chunk:
            break
        plain = aead.decrypt(_chunk_nonce(nonce_prefix, index), chunk, None)
        total += len(plain)
        writer.write(plain)
        index += 1
    return total


def reencrypt_chunks(
    src_key: bytes,
    src_nonce_prefix: bytes,
    dst_key: bytes,
    dst_nonce_prefix: bytes,
    reader,
):
    """Yield ciphertext chunks re-encrypted from `reader` without exposing
    more than one plaintext chunk in memory at a time."""
    src = AESGCM(src_key)
    dst = AESGCM(dst_key)
    index = 0
    while True:
        chunk = reader.read(CHUNK_SIZE + TAG_LEN)
        if not chunk:
            break
        plain = src.decrypt(_chunk_nonce(src_nonce_prefix, index), chunk, None)
        yield dst.encrypt(_chunk_nonce(dst_nonce_prefix, index), plain, None)
        index += 1


def wrap_key(master_key: bytes, key: bytes) -> bytes:
    """Encrypt a symmetric key under the local master key. Returns nonce||ct."""
    nonce = os.urandom(12)
    return nonce + AESGCM(master_key).encrypt(nonce, key, None)


def unwrap_key(master_key: bytes, blob: bytes) -> bytes:
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(master_key).decrypt(nonce, ct, None)


def _oaep() -> padding.OAEP:
    return padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None,
    )


def rsa_wrap(public_key_pem: bytes, data_key: bytes) -> bytes:
    """RSA-OAEP-SHA256 wrap of a data key for one recipient."""
    pub = serialization.load_pem_public_key(public_key_pem)
    return pub.encrypt(data_key, _oaep())


def rsa_unwrap(private_key_pem: bytes, blob: bytes) -> bytes:
    priv = serialization.load_pem_private_key(private_key_pem, password=None)
    return priv.decrypt(blob, _oaep())
