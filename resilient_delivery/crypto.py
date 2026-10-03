"""Streaming encryption primitives.

Message bytes are encrypted in fixed-size chunks with AES-256-GCM so that
peak memory stays bounded regardless of the 64 MiB maximum message size.

Stream file format::

    "RD01"                      4-byte magic
    uint32 BE chunk_size        plaintext bytes per chunk
    repeated chunks:
        uint32 BE ct_len        ciphertext + 16-byte GCM tag length
        ct_len bytes

Each chunk's 12-byte nonce is ``nonce_prefix(4) || chunk_index(8 BE)``.
Every stream uses a fresh random key, so nonce reuse across streams is
impossible; the random prefix is defense in depth.
"""
from __future__ import annotations

import hashlib
import os
import struct
from typing import BinaryIO, Callable, Optional

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

CHUNK_SIZE = 1 << 20  # 1 MiB plaintext per chunk
NONCE_PREFIX_SIZE = 4
TAG_SIZE = 16
HEADER_MAGIC = b"RD01"
_HEADER = struct.Struct(">4sI")
_CHUNK_LEN = struct.Struct(">I")


def generate_key() -> bytes:
    """Return a fresh random 256-bit key."""
    return os.urandom(32)


def _nonce(prefix: bytes, index: int) -> bytes:
    return prefix + index.to_bytes(8, "big")


def _write_header(dst: BinaryIO, chunk_size: int) -> None:
    dst.write(_HEADER.pack(HEADER_MAGIC, chunk_size))


def _read_header(src: BinaryIO) -> int:
    raw = src.read(_HEADER.size)
    if len(raw) != _HEADER.size:
        raise ValueError("truncated stream header")
    magic, chunk_size = _HEADER.unpack(raw)
    if magic != HEADER_MAGIC:
        raise ValueError("bad stream magic")
    if not 0 < chunk_size <= CHUNK_SIZE:
        raise ValueError("bad chunk size")
    return chunk_size


def encrypt_stream(key: bytes, src: BinaryIO, dst: BinaryIO,
                   chunk_size: int = CHUNK_SIZE,
                   chunk_hook: Optional[Callable[[bytes], None]] = None) -> bytes:
    """Encrypt all bytes from ``src`` into ``dst`` chunk by chunk.

    ``chunk_hook`` (if given) receives each plaintext chunk, e.g. to update a
    hash. Returns the 4-byte nonce prefix, which must be stored alongside
    the ciphertext.
    """
    if len(key) != 32:
        raise ValueError("key must be 32 bytes")
    aead = AESGCM(key)
    prefix = os.urandom(NONCE_PREFIX_SIZE)
    _write_header(dst, chunk_size)
    index = 0
    while True:
        chunk = src.read(chunk_size)
        if not chunk:
            break
        if chunk_hook is not None:
            chunk_hook(chunk)
        ct = aead.encrypt(_nonce(prefix, index), chunk, None)
        dst.write(_CHUNK_LEN.pack(len(ct)))
        dst.write(ct)
        index += 1
    return prefix


def _chunks(src: BinaryIO, chunk_size: int):
    index = 0
    while True:
        raw = src.read(_CHUNK_LEN.size)
        if not raw:
            return
        if len(raw) != _CHUNK_LEN.size:
            raise ValueError("truncated chunk header")
        (ct_len,) = _CHUNK_LEN.unpack(raw)
        if ct_len < TAG_SIZE or ct_len > chunk_size + TAG_SIZE:
            raise ValueError("bad chunk length")
        ct = src.read(ct_len)
        if len(ct) != ct_len:
            raise ValueError("truncated chunk")
        yield index, ct
        index += 1


def decrypt_stream(key: bytes, nonce_prefix: bytes, src: BinaryIO,
                   dst: BinaryIO) -> None:
    """Decrypt a stream produced by :func:`encrypt_stream`."""
    aead = AESGCM(key)
    chunk_size = _read_header(src)
    for index, ct in _chunks(src, chunk_size):
        dst.write(aead.decrypt(_nonce(nonce_prefix, index), ct, None))


def reencrypt_stream(src_key: bytes, src_nonce_prefix: bytes, src: BinaryIO,
                     dst_key: bytes, dst: BinaryIO) -> bytes:
    """Decrypt chunks from ``src`` and re-encrypt them into ``dst``.

    Returns the destination nonce prefix. Plaintext exists only one chunk at
    a time in memory.
    """
    src_aead = AESGCM(src_key)
    dst_aead = AESGCM(dst_key)
    chunk_size = _read_header(src)
    dst_prefix = os.urandom(NONCE_PREFIX_SIZE)
    _write_header(dst, chunk_size)
    for index, ct in _chunks(src, chunk_size):
        plain = src_aead.decrypt(_nonce(src_nonce_prefix, index), ct, None)
        out = dst_aead.encrypt(_nonce(dst_prefix, index), plain, None)
        dst.write(_CHUNK_LEN.pack(len(out)))
        dst.write(out)
    return dst_prefix


def wrap_key_aesgcm(master_key: bytes, key: bytes) -> bytes:
    """Wrap a symmetric key with the local 32-byte master key (AES-256-GCM)."""
    if len(master_key) != 32:
        raise ValueError("master key must be 32 bytes")
    nonce = os.urandom(12)
    return nonce + AESGCM(master_key).encrypt(nonce, key, None)


def unwrap_key_aesgcm(master_key: bytes, blob: bytes) -> bytes:
    """Inverse of :func:`wrap_key_aesgcm`."""
    nonce, ct = blob[:12], blob[12:]
    return AESGCM(master_key).decrypt(nonce, ct, None)


def _load_public_key(public_key_der: bytes):
    return serialization.load_der_public_key(public_key_der)


def normalize_public_key(public_key) -> bytes:
    """Normalize a PEM/DER bytes or RSAPublicKey object to DER bytes."""
    if isinstance(public_key, bytes):
        data = public_key
        if b"-----BEGIN" in data:
            key = serialization.load_pem_public_key(data)
        else:
            key = serialization.load_der_public_key(data)
    else:
        key = public_key
    return key.public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def wrap_key_rsa(public_key_der: bytes, key: bytes) -> bytes:
    """Wrap a symmetric key with an RSA public key (OAEP, SHA-256)."""
    pub = _load_public_key(public_key_der)
    return pub.encrypt(
        key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def unwrap_key_rsa(private_key, blob: bytes) -> bytes:
    """Unwrap with the matching RSA private key (used by recipients/tests)."""
    return private_key.decrypt(
        blob,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )


def sha256_stream(src: BinaryIO) -> bytes:
    """Compute SHA-256 over a stream without loading it into memory."""
    h = hashlib.sha256()
    while True:
        chunk = src.read(CHUNK_SIZE)
        if not chunk:
            break
        h.update(chunk)
    return h.digest()
