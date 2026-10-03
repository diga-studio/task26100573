"""SQLite + local-file backed resumable fan-out delivery store.

Layout under the store directory::

    store.db                     SQLite database (WAL, synchronous=FULL)
    messages/<request_id>.msg    chunked-AES-GCM ciphertext of the message,
                                 key wrapped by the local master key in the DB;
                                 deleted once the delivery is published
    copies/<rid>/<rid2>.bin      committed per-recipient encrypted copies

Crash-safety rules:
  * Files are written to ``*.tmp`` then atomically renamed and dir-fsynced.
  * A recipient copy becomes visible to recovery only via its DB commit.
  * Publication is a single SQLite commit; a delivery is either fully
    readable by everyone or by no one.
  * On open, orphaned message files (unknown or published requests) and
    leftover ``*.tmp`` files are removed; committed copies are reused as-is.

``LUNA_DELIVERY_KILL_AT`` (test-only): if set, the store SIGKILLs itself at
the named hook point (``after_msg_file``, ``after_copy_file``,
``before_publish``, ``after_publish``).
"""

from __future__ import annotations

import hashlib
import os
import shutil
import signal
import sqlite3
from dataclasses import dataclass
from typing import BinaryIO, Iterable

from . import crypto
from .errors import ConflictError, NotFoundError, NotVisibleError

MAX_RECIPIENTS = 100
COPY_ALGORITHM = "RSA-OAEP-SHA256+AES-256-GCM-chunked"

_SCHEMA = """
CREATE TABLE IF NOT EXISTS requests (
    request_id      TEXT PRIMARY KEY,
    state           TEXT NOT NULL CHECK (state IN ('accepted', 'published')),
    content_hash    BLOB NOT NULL,
    recipients_hash BLOB NOT NULL,
    total_size      INTEGER NOT NULL,
    chunk_size      INTEGER NOT NULL,
    msg_nonce_prefix BLOB,
    wrapped_msg_key BLOB
);
CREATE TABLE IF NOT EXISTS recipients (
    request_id       TEXT NOT NULL REFERENCES requests(request_id),
    recipient_id     TEXT NOT NULL,
    public_key_pem   BLOB NOT NULL,
    state            TEXT NOT NULL CHECK (state IN ('pending', 'done')),
    wrapped_data_key BLOB,
    nonce_prefix     BLOB,
    copy_hash        BLOB,
    PRIMARY KEY (request_id, recipient_id)
);
"""


@dataclass(frozen=True)
class Recipient:
    recipient_id: str
    public_key_pem: bytes


@dataclass(frozen=True)
class Status:
    request_id: str
    state: str  # "accepted" | "published"
    total: int
    completed: int


@dataclass(frozen=True)
class EncryptedCopy:
    request_id: str
    recipient_id: str
    algorithm: str
    wrapped_data_key: bytes
    nonce_prefix: bytes
    chunk_size: int
    ciphertext: bytes


def _kill_hook(point: str) -> None:
    if os.environ.get("LUNA_DELIVERY_KILL_AT") == point:
        os.kill(os.getpid(), signal.SIGKILL)
        os._exit(1)  # pragma: no cover


def _fsync_dir(path: str) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def _recipients_hash(recipients: list[Recipient]) -> bytes:
    hasher = hashlib.sha256()
    for rec in sorted(recipients, key=lambda r: r.recipient_id):
        hasher.update(rec.recipient_id.encode("utf-8"))
        hasher.update(b"\0")
        hasher.update(bytes(rec.public_key_pem))
        hasher.update(b"\0")
    return hasher.digest()


class DeliveryStore:
    def __init__(self, path: str, master_key: bytes) -> None:
        if len(master_key) != 32:
            raise ValueError("master_key must be 32 bytes")
        self._master_key = master_key
        self._dir = os.path.abspath(path)
        self._msg_dir = os.path.join(self._dir, "messages")
        self._copies_dir = os.path.join(self._dir, "copies")
        os.makedirs(self._msg_dir, exist_ok=True)
        os.makedirs(self._copies_dir, exist_ok=True)
        self._db = sqlite3.connect(os.path.join(self._dir, "store.db"))
        self._db.execute("PRAGMA journal_mode=WAL")
        self._db.execute("PRAGMA synchronous=FULL")
        self._db.execute("PRAGMA foreign_keys=ON")
        self._db.executescript(_SCHEMA)
        self._db.commit()
        self._recover()

    def close(self) -> None:
        self._db.close()

    def __enter__(self) -> "DeliveryStore":
        return self

    def __exit__(self, *exc) -> None:
        self.close()

    # -- paths ---------------------------------------------------------

    def _msg_path(self, request_id: str) -> str:
        return os.path.join(self._msg_dir, request_id + ".msg")

    def _copy_dir(self, request_id: str) -> str:
        return os.path.join(self._copies_dir, request_id)

    def _copy_path(self, request_id: str, recipient_id: str) -> str:
        return os.path.join(self._copy_dir(request_id), recipient_id + ".bin")

    # -- recovery ------------------------------------------------------

    def _recover(self) -> None:
        live_msgs = {
            row[0]
            for row in self._db.execute(
                "SELECT request_id FROM requests WHERE state='accepted'"
            )
        }
        for name in os.listdir(self._msg_dir):
            rid = name[: -len(".msg")] if name.endswith(".msg") else None
            if rid not in live_msgs:
                os.unlink(os.path.join(self._msg_dir, name))
        known = {
            row[0] for row in self._db.execute("SELECT request_id FROM requests")
        }
        for name in os.listdir(self._copies_dir):
            full = os.path.join(self._copies_dir, name)
            if name not in known:
                shutil.rmtree(full, ignore_errors=True)
                continue
            for fname in os.listdir(full):
                if fname.endswith(".tmp"):
                    os.unlink(os.path.join(full, fname))

    # -- submit ----------------------------------------------------------

    def submit(
        self,
        request_id: str,
        recipients: Iterable[Recipient],
        stream: BinaryIO,
    ) -> str:
        recs = [Recipient(r.recipient_id, bytes(r.public_key_pem)) for r in recipients]
        if not 1 <= len(recs) <= MAX_RECIPIENTS:
            raise ValueError("recipients must contain 1..100 entries")
        if len({r.recipient_id for r in recs}) != len(recs):
            raise ValueError("duplicate recipient_id")
        rec_hash = _recipients_hash(recs)

        row = self._db.execute(
            "SELECT content_hash, recipients_hash FROM requests WHERE request_id=?",
            (request_id,),
        ).fetchone()

        if row is not None:
            # Idempotent retry: verify the stream bytes and recipient set match.
            hasher = hashlib.sha256()
            while True:
                chunk = stream.read(crypto.CHUNK_SIZE)
                if not chunk:
                    break
                hasher.update(chunk)
            if hasher.digest() != row[0] or rec_hash != row[1]:
                raise ConflictError(
                    "request_id reused with different content or recipients"
                )
            return request_id

        msg_key = crypto.new_data_key()
        msg_prefix = crypto.new_nonce_prefix()
        tmp_path = self._msg_path(request_id) + ".tmp"
        final_path = self._msg_path(request_id)
        with open(tmp_path, "wb") as writer:
            total_size, content_hash = crypto.encrypt_chunks(
                msg_key, msg_prefix, stream, writer
            )
            writer.flush()
            os.fsync(writer.fileno())
        os.replace(tmp_path, final_path)
        _fsync_dir(self._msg_dir)
        _kill_hook("after_msg_file")

        with self._db:
            self._db.execute(
                "INSERT INTO requests (request_id, state, content_hash,"
                " recipients_hash, total_size, chunk_size, msg_nonce_prefix,"
                " wrapped_msg_key) VALUES (?, 'accepted', ?, ?, ?, ?, ?, ?)",
                (
                    request_id,
                    content_hash,
                    rec_hash,
                    total_size,
                    crypto.CHUNK_SIZE,
                    msg_prefix,
                    crypto.wrap_key(self._master_key, msg_key),
                ),
            )
            self._db.executemany(
                "INSERT INTO recipients (request_id, recipient_id,"
                " public_key_pem, state) VALUES (?, ?, ?, 'pending')",
                [(request_id, r.recipient_id, r.public_key_pem) for r in recs],
            )
        os.makedirs(self._copy_dir(request_id), exist_ok=True)
        _fsync_dir(self._copies_dir)
        return request_id

    # -- advance ---------------------------------------------------------

    def advance(self, request_id: str, limit: int) -> Status:
        row = self._db.execute(
            "SELECT state, msg_nonce_prefix, wrapped_msg_key FROM requests"
            " WHERE request_id=?",
            (request_id,),
        ).fetchone()
        if row is None:
            raise NotFoundError(request_id)
        if row[0] == "published":
            return self.status(request_id)

        pending = self._db.execute(
            "SELECT recipient_id, public_key_pem FROM recipients"
            " WHERE request_id=? AND state='pending' ORDER BY recipient_id"
            " LIMIT ?",
            (request_id, max(0, limit)),
        ).fetchall()

        if pending:
            msg_key = crypto.unwrap_key(self._master_key, row[2])
            msg_prefix = row[1]
            copy_dir = self._copy_dir(request_id)
            os.makedirs(copy_dir, exist_ok=True)
            for recipient_id, pub_pem in pending:
                data_key = crypto.new_data_key()
                copy_prefix = crypto.new_nonce_prefix()
                tmp_path = self._copy_path(request_id, recipient_id) + ".tmp"
                final_path = self._copy_path(request_id, recipient_id)
                copy_hasher = hashlib.sha256()
                with open(self._msg_path(request_id), "rb") as src, open(
                    tmp_path, "wb"
                ) as dst:
                    for out_chunk in crypto.reencrypt_chunks(
                        msg_key, msg_prefix, data_key, copy_prefix, src
                    ):
                        copy_hasher.update(out_chunk)
                        dst.write(out_chunk)
                    dst.flush()
                    os.fsync(dst.fileno())
                os.replace(tmp_path, final_path)
                _fsync_dir(copy_dir)
                _kill_hook("after_copy_file")
                with self._db:
                    self._db.execute(
                        "UPDATE recipients SET state='done', wrapped_data_key=?,"
                        " nonce_prefix=?, copy_hash=? WHERE request_id=?"
                        " AND recipient_id=?",
                        (
                            crypto.rsa_wrap(pub_pem, data_key),
                            copy_prefix,
                            copy_hasher.digest(),
                            request_id,
                            recipient_id,
                        ),
                    )

        remaining = self._db.execute(
            "SELECT COUNT(*) FROM recipients WHERE request_id=?"
            " AND state='pending'",
            (request_id,),
        ).fetchone()[0]
        if remaining == 0:
            _kill_hook("before_publish")
            with self._db:
                self._db.execute(
                    "UPDATE requests SET state='published',"
                    " msg_nonce_prefix=NULL, wrapped_msg_key=NULL"
                    " WHERE request_id=?",
                    (request_id,),
                )
            _kill_hook("after_publish")
            try:
                os.unlink(self._msg_path(request_id))
                _fsync_dir(self._msg_dir)
            except FileNotFoundError:
                pass
        return self.status(request_id)

    # -- read / status -----------------------------------------------------

    def status(self, request_id: str) -> Status:
        row = self._db.execute(
            "SELECT state FROM requests WHERE request_id=?", (request_id,)
        ).fetchone()
        if row is None:
            raise NotFoundError(request_id)
        total, completed = self._db.execute(
            "SELECT COUNT(*), SUM(state='done') FROM recipients WHERE request_id=?",
            (request_id,),
        ).fetchone()
        return Status(request_id, row[0], total, completed or 0)

    def read(self, request_id: str, recipient_id: str) -> EncryptedCopy:
        row = self._db.execute(
            "SELECT r.wrapped_data_key, r.nonce_prefix, q.chunk_size"
            " FROM recipients r JOIN requests q ON q.request_id = r.request_id"
            " WHERE r.request_id=? AND r.recipient_id=? AND q.state='published'"
            " AND r.state='done'",
            (request_id, recipient_id),
        ).fetchone()
        if row is None:
            exists = self._db.execute(
                "SELECT 1 FROM recipients WHERE request_id=? AND recipient_id=?",
                (request_id, recipient_id),
            ).fetchone()
            if exists is None:
                raise NotFoundError(f"{request_id}/{recipient_id}")
            raise NotVisibleError(request_id)
        with open(self._copy_path(request_id, recipient_id), "rb") as fh:
            ciphertext = fh.read()
        return EncryptedCopy(
            request_id=request_id,
            recipient_id=recipient_id,
            algorithm=COPY_ALGORITHM,
            wrapped_data_key=row[0],
            nonce_prefix=row[1],
            chunk_size=row[2],
            ciphertext=ciphertext,
        )
