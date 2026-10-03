"""Standalone decryption helper for delivered copies.

An independent program holding only the recipient's RSA-2048 private key and
an ``EncryptedCopy`` (as returned by ``DeliveryStore.read``) can recover the
original message bytes with ``decrypt_copy`` — no access to the store, the
master key, or any sender-side secret is required.
"""

from __future__ import annotations

import io

from . import crypto
from .store import EncryptedCopy


def decrypt_copy(private_key_pem: bytes, copy: EncryptedCopy) -> bytes:
    """Decrypt an EncryptedCopy with the recipient's RSA private key."""
    data_key = crypto.rsa_unwrap(private_key_pem, copy.wrapped_data_key)
    out = io.BytesIO()
    crypto.decrypt_chunks(
        data_key, copy.nonce_prefix, io.BytesIO(copy.ciphertext), out
    )
    return out.getvalue()
