"""SQLite schema and on-disk file layout.

Layout under the storage directory::

    delivery.db                     SQLite metadata (single writer)
    messages/<request_id>.msg       message ciphertext (chunked AES-256-GCM)
    copies/<request_id>/<rid>.copy  per-recipient ciphertext
    tmp/                            staging area for atomic rename

All files are written under ``tmp/``, fsynced, then atomically renamed into
place (and the target directory fsynced). Files not referenced by any
committed DB row are removed on open, so a crash between file rename and
DB commit never leaves stale state.
"""
from __future__ import annotations

import os
import sqlite3
import time
from contextlib import contextmanager
from hashlib import sha256
from pathlib import Path
from typing import Iterator, List, Optional, Tuple
from urllib.parse import quote

SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (
    key TEXT PRIMARY KEY,
    value BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS deliveries (
    request_id TEXT PRIMARY KEY,
    content_hash BLOB NOT NULL,
    recipients_hash BLOB NOT NULL,
    message_nonce BLOB NOT NULL,
    message_key_wrapped BLOB NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('accepted', 'published')),
    created_at REAL NOT NULL
);
CREATE TABLE IF NOT EXISTS recipients (
    request_id TEXT NOT NULL,
    recipient_id TEXT NOT NULL,
    position INTEGER NOT NULL,
    pubkey_der BLOB NOT NULL,
    status TEXT NOT NULL CHECK (status IN ('pending', 'committed')),
    copy_nonce BLOB,
    data_key_wrapped BLOB,
    PRIMARY KEY (request_id, recipient_id)
);
"""


def _fname(identifier: str) -> str:
    """Map an arbitrary identifier to a safe, bounded-length file name."""
    name = quote(identifier, safe="")
    if len(name) > 80:
        name = sha256(identifier.encode("utf-8")).hexdigest()
    return name


def _fsync_dir(path: Path) -> None:
    fd = os.open(path, os.O_RDONLY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


class Store:
    """Owns the SQLite connection and the storage directory layout."""

    def __init__(self, root: Path) -> None:
        self.root = Path(root)
        self.root.mkdir(parents=True, exist_ok=True)
        (self.root / "messages").mkdir(exist_ok=True)
        (self.root / "copies").mkdir(exist_ok=True)
        (self.root / "tmp").mkdir(exist_ok=True)
        self.conn = sqlite3.connect(
            self.root / "delivery.db", isolation_level=None
        )
        self.conn.row_factory = sqlite3.Row
        self.conn.execute("PRAGMA journal_mode=WAL")
        self.conn.execute("PRAGMA synchronous=FULL")
        self.conn.execute("PRAGMA foreign_keys=ON")
        self.conn.execute("PRAGMA busy_timeout=5000")
        self.conn.executescript(SCHEMA)

    def close(self) -> None:
        self.conn.close()

    # -- path helpers -----------------------------------------------------
    def message_path(self, request_id: str) -> Path:
        return self.root / "messages" / (_fname(request_id) + ".msg")

    def copy_path(self, request_id: str, recipient_id: str) -> Path:
        return (
            self.root / "copies" / _fname(request_id) / (_fname(recipient_id) + ".copy")
        )

    @contextmanager
    def atomic_write(self, final: Path) -> Iterator:
        """Write to a tmp file, fsync, then atomically rename to ``final``."""
        tmp = self.root / "tmp" / (final.name + "." + str(os.getpid()) + ".tmp")
        try:
            with open(tmp, "wb") as fh:
                yield fh
                fh.flush()
                os.fsync(fh.fileno())
            final.parent.mkdir(parents=True, exist_ok=True)
            os.replace(tmp, final)
            _fsync_dir(final.parent)
        except BaseException:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
            raise

    # -- meta -------------------------------------------------------------
    def get_meta(self, key: str) -> Optional[bytes]:
        row = self.conn.execute(
            "SELECT value FROM meta WHERE key = ?", (key,)
        ).fetchone()
        return None if row is None else bytes(row["value"])

    def set_meta(self, key: str, value: bytes) -> None:
        with self.conn:
            self.conn.execute(
                "INSERT OR REPLACE INTO meta (key, value) VALUES (?, ?)", (key, value)
            )

    # -- deliveries -------------------------------------------------------
    def get_delivery(self, request_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM deliveries WHERE request_id = ?", (request_id,)
        ).fetchone()

    def insert_delivery(self, request_id: str, content_hash: bytes,
                        recipients_hash: bytes, message_nonce: bytes,
                        message_key_wrapped: bytes,
                        recipients: List[Tuple[str, bytes]]) -> None:
        """Insert a delivery row plus all recipient rows in one transaction."""
        with self.conn:
            self.conn.execute(
                "INSERT INTO deliveries (request_id, content_hash, recipients_hash,"
                " message_nonce, message_key_wrapped, state, created_at)"
                " VALUES (?, ?, ?, ?, ?, 'accepted', ?)",
                (request_id, content_hash, recipients_hash, message_nonce,
                 message_key_wrapped, time.time()),
            )
            self.conn.executemany(
                "INSERT INTO recipients (request_id, recipient_id, position,"
                " pubkey_der, status) VALUES (?, ?, ?, ?, 'pending')",
                [
                    (request_id, rid, pos, pub)
                    for pos, (rid, pub) in enumerate(recipients)
                ],
            )

    def publish(self, request_id: str) -> None:
        """Atomically flip a delivery to the published state."""
        with self.conn:
            self.conn.execute(
                "UPDATE deliveries SET state = 'published'"
                " WHERE request_id = ? AND state = 'accepted'",
                (request_id,),
            )

    # -- recipients -------------------------------------------------------
    def pending_recipients(self, request_id: str, limit: int) -> List[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM recipients WHERE request_id = ? AND status = 'pending'"
            " ORDER BY position LIMIT ?",
            (request_id, limit),
        ).fetchall()

    def commit_recipient(self, request_id: str, recipient_id: str,
                         copy_nonce: bytes, data_key_wrapped: bytes) -> None:
        """Mark one recipient committed in its own transaction."""
        with self.conn:
            self.conn.execute(
                "UPDATE recipients SET status = 'committed', copy_nonce = ?,"
                " data_key_wrapped = ? WHERE request_id = ? AND recipient_id = ?",
                (copy_nonce, data_key_wrapped, request_id, recipient_id),
            )

    def all_committed(self, request_id: str) -> bool:
        row = self.conn.execute(
            "SELECT COUNT(*) AS n FROM recipients"
            " WHERE request_id = ? AND status != 'committed'",
            (request_id,),
        ).fetchone()
        return row["n"] == 0

    def get_recipient(self, request_id: str, recipient_id: str) -> Optional[sqlite3.Row]:
        return self.conn.execute(
            "SELECT * FROM recipients WHERE request_id = ? AND recipient_id = ?",
            (request_id, recipient_id),
        ).fetchone()

    def counts(self, request_id: str) -> Tuple[int, int]:
        row = self.conn.execute(
            "SELECT COUNT(*) AS total,"
            " SUM(CASE WHEN status = 'committed' THEN 1 ELSE 0 END) AS committed"
            " FROM recipients WHERE request_id = ?",
            (request_id,),
        ).fetchone()
        return (row["committed"] or 0, row["total"])

    # -- recovery ---------------------------------------------------------
    def sweep_orphans(self) -> None:
        """Remove files not referenced by any committed DB row."""
        tmp = self.root / "tmp"
        for entry in tmp.iterdir():
            entry.unlink(missing_ok=True)

        valid_messages = set()
        valid_copies = set()
        for row in self.conn.execute("SELECT request_id FROM deliveries"):
            valid_messages.add(self.message_path(row["request_id"]).resolve())
        for row in self.conn.execute(
            "SELECT request_id, recipient_id FROM recipients"
            " WHERE status = 'committed'"
        ):
            valid_copies.add(
                self.copy_path(row["request_id"], row["recipient_id"]).resolve()
            )

        messages_dir = self.root / "messages"
        for entry in messages_dir.iterdir():
            if entry.resolve() not in valid_messages:
                entry.unlink(missing_ok=True)

        copies_dir = self.root / "copies"
        for req_dir in list(copies_dir.iterdir()):
            if not req_dir.is_dir():
                req_dir.unlink(missing_ok=True)
                continue
            for entry in list(req_dir.iterdir()):
                if entry.resolve() not in valid_copies:
                    entry.unlink(missing_ok=True)
            if not any(req_dir.iterdir()):
                req_dir.rmdir()
