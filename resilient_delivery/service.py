"""Public API: submit / advance / read."""
from __future__ import annotations

import hashlib
from dataclasses import dataclass
from pathlib import Path
from typing import BinaryIO, Optional, Sequence, Union

from cryptography.hazmat.primitives.asymmetric.rsa import RSAPublicKey
from cryptography.hazmat.primitives.serialization import load_der_public_key

from . import crypto
from .errors import ConflictError, DeliveryError, NotFoundError, NotVisibleError
from .store import Store

MAX_MESSAGE_SIZE = 64 << 20  # 64 MiB
MAX_RECIPIENTS = 100

_KEY_CHECK_PLAINTEXT = b"resilient-delivery-key-check-v1"


@dataclass(frozen=True)
class Recipient:
    """One expanded, deduplicated recipient supplied by the caller."""

    recipient_id: str
    public_key: Union[bytes, object]  # PEM/DER bytes or an RSAPublicKey


@dataclass(frozen=True)
class DeliveryStatus:
    """Snapshot returned by submit() and advance()."""

    request_id: str
    state: str  # "accepted" | "published"
    committed: int
    total: int


@dataclass(frozen=True)
class EncryptedCopy:
    """Everything an independent program needs to decrypt with the private key."""

    request_id: str
    recipient_id: str
    algorithm: str          # chunked AES-256-GCM stream format
    key_wrap: str           # key encapsulation mechanism
    wrapped_data_key: bytes
    nonce_prefix: bytes
    chunk_size: int
    ciphertext: bytes


def decrypt_copy(private_key, copy: EncryptedCopy) -> bytes:
    """Standalone decryption of an :class:`EncryptedCopy` with the RSA private key.

    Mirrors what an independent recipient program does; kept dependency-light
    (only this package's stream format module and ``cryptography``).
    """
    import io

    if copy.key_wrap != "RSA-OAEP-SHA256":
        raise DeliveryError(f"unsupported key wrap: {copy.key_wrap}")
    if copy.algorithm != "AES-256-GCM-CHUNKED":
        raise DeliveryError(f"unsupported algorithm: {copy.algorithm}")
    data_key = crypto.unwrap_key_rsa(private_key, copy.wrapped_data_key)
    out = io.BytesIO()
    crypto.decrypt_stream(data_key, copy.nonce_prefix,
                          io.BytesIO(copy.ciphertext), out)
    return out.getvalue()


def _recipients_hash(pairs: Sequence[tuple]) -> bytes:
    """Order-independent hash of the (recipient_id, pubkey_der) set."""
    h = hashlib.sha256()
    for rid, der in sorted(pairs):
        h.update(len(rid.encode("utf-8")).to_bytes(4, "big"))
        h.update(rid.encode("utf-8"))
        h.update(len(der).to_bytes(4, "big"))
        h.update(der)
    return h.digest()


class DeliveryService:
    """Resumable fan-out delivery backed by SQLite and local files."""

    def __init__(self, storage_dir: Union[str, Path], master_key: bytes,
                 _hook=None) -> None:
        """``_hook`` is a test-only callable invoked with a label at internal
        commit boundaries so crash-recovery tests can kill the process at
        precise points. Not part of the public API."""
        if len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes")
        self._master_key = master_key
        self._hook = _hook
        self._store = Store(Path(storage_dir))
        self._check_master_key()
        self._store.sweep_orphans()

    def _fire(self, point: str) -> None:
        if self._hook is not None:
            self._hook(point)

    def _check_master_key(self) -> None:
        blob = self._store.get_meta("key_check")
        if blob is None:
            self._store.set_meta(
                "key_check",
                crypto.wrap_key_aesgcm(self._master_key, _KEY_CHECK_PLAINTEXT),
            )
            return
        try:
            plain = crypto.unwrap_key_aesgcm(self._master_key, blob)
        except Exception as exc:
            raise DeliveryError("master key does not match this store") from exc
        if plain != _KEY_CHECK_PLAINTEXT:
            raise DeliveryError("master key does not match this store")

    def close(self) -> None:
        self._store.close()

    def __enter__(self) -> "DeliveryService":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- helpers ----------------------------------------------------------
    def _status(self, request_id: str) -> DeliveryStatus:
        delivery = self._store.get_delivery(request_id)
        if delivery is None:
            raise NotFoundError(f"unknown request_id: {request_id!r}")
        committed, total = self._store.counts(request_id)
        return DeliveryStatus(
            request_id=request_id,
            state=delivery["state"],
            committed=committed,
            total=total,
        )

    @staticmethod
    def _normalize_recipients(recipients: Sequence[Recipient]) -> list:
        if not 1 <= len(recipients) <= MAX_RECIPIENTS:
            raise DeliveryError(
                f"recipient count must be 1..{MAX_RECIPIENTS}"
            )
        pairs = []
        seen = set()
        for r in recipients:
            if not r.recipient_id:
                raise DeliveryError("recipient_id must be non-empty")
            if r.recipient_id in seen:
                raise DeliveryError(
                    f"duplicate recipient_id: {r.recipient_id!r}"
                )
            seen.add(r.recipient_id)
            der = crypto.normalize_public_key(r.public_key)
            key = load_der_public_key(der)
            if not isinstance(key, RSAPublicKey) or key.key_size != 2048:
                raise DeliveryError("public keys must be RSA-2048")
            pairs.append((r.recipient_id, der))
        return pairs

    # -- submit -----------------------------------------------------------
    def submit(self, request_id: str,
               recipients: Sequence[Recipient],
               stream: BinaryIO) -> DeliveryStatus:
        """Durably accept a message. Idempotent per (request_id, content, recipients)."""
        if not request_id:
            raise DeliveryError("request_id must be non-empty")
        pairs = self._normalize_recipients(recipients)
        recipients_hash = _recipients_hash(pairs)

        existing = self._store.get_delivery(request_id)
        if existing is not None:
            if existing["recipients_hash"] != recipients_hash:
                raise ConflictError(
                    f"request_id {request_id!r} already used with different recipients"
                )
            import io

            content_hash = crypto.sha256_stream(stream)
            if content_hash != existing["content_hash"]:
                raise ConflictError(
                    f"request_id {request_id!r} already used with different content"
                )
            return self._status(request_id)

        message_key = crypto.generate_key()
        digest = hashlib.sha256()
        size = 0

        def hook(chunk: bytes) -> None:
            nonlocal size
            size += len(chunk)
            if size > MAX_MESSAGE_SIZE:
                raise DeliveryError("message exceeds 64 MiB limit")
            digest.update(chunk)

        final_path = self._store.message_path(request_id)
        with self._store.atomic_write(final_path) as fh:
            message_nonce = crypto.encrypt_stream(message_key, stream, fh,
                                                  chunk_hook=hook)
        self._fire("message_written")
        self._store.insert_delivery(
            request_id=request_id,
            content_hash=digest.digest(),
            recipients_hash=recipients_hash,
            message_nonce=message_nonce,
            message_key_wrapped=crypto.wrap_key_aesgcm(self._master_key, message_key),
            recipients=pairs,
        )
        self._fire("delivery_inserted")
        return self._status(request_id)

    # -- advance ----------------------------------------------------------
    def advance(self, request_id: str, limit: int) -> DeliveryStatus:
        """Generate and durably commit copies for up to ``limit`` pending recipients."""
        if limit < 1:
            raise DeliveryError("limit must be >= 1")
        delivery = self._store.get_delivery(request_id)
        if delivery is None:
            raise NotFoundError(f"unknown request_id: {request_id!r}")
        if delivery["state"] == "published":
            return self._status(request_id)

        pending = self._store.pending_recipients(request_id, limit)
        if pending:
            message_key = crypto.unwrap_key_aesgcm(
                self._master_key, delivery["message_key_wrapped"]
            )
            message_nonce = delivery["message_nonce"]
            message_path = self._store.message_path(request_id)
            for row in pending:
                recipient_id = row["recipient_id"]
                data_key = crypto.generate_key()
                copy_path = self._store.copy_path(request_id, recipient_id)
                with open(message_path, "rb") as src, \
                        self._store.atomic_write(copy_path) as dst:
                    copy_nonce = crypto.reencrypt_stream(
                        message_key, message_nonce, src, data_key, dst
                    )
                self._fire("copy_written")
                wrapped = crypto.wrap_key_rsa(row["pubkey_der"], data_key)
                self._store.commit_recipient(
                    request_id, recipient_id, copy_nonce, wrapped
                )
                self._fire("recipient_committed")

        if self._store.all_committed(request_id):
            self._fire("before_publish")
            self._store.publish(request_id)
            self._fire("after_publish")
        return self._status(request_id)

    # -- read -------------------------------------------------------------
    def read(self, request_id: str, recipient_id: str) -> EncryptedCopy:
        """Return the recipient's encrypted copy, only if the delivery is published."""
        delivery = self._store.get_delivery(request_id)
        if delivery is None:
            raise NotFoundError(f"unknown request_id: {request_id!r}")
        if delivery["state"] != "published":
            raise NotVisibleError(f"delivery {request_id!r} is not published")
        row = self._store.get_recipient(request_id, recipient_id)
        if row is None:
            raise NotFoundError(
                f"unknown recipient {recipient_id!r} for {request_id!r}"
            )
        copy_path = self._store.copy_path(request_id, recipient_id)
        ciphertext = copy_path.read_bytes()
        return EncryptedCopy(
            request_id=request_id,
            recipient_id=recipient_id,
            algorithm="AES-256-GCM-CHUNKED",
            key_wrap="RSA-OAEP-SHA256",
            wrapped_data_key=bytes(row["data_key_wrapped"]),
            nonce_prefix=bytes(row["copy_nonce"]),
            chunk_size=crypto.CHUNK_SIZE,
            ciphertext=ciphertext,
        )
