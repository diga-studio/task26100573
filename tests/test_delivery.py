import io
import os

import pytest

from conftest import (make_recipients, pattern_bytes, run_child,
                      write_recipients_json)

from luna_delivery import (ConflictError, DeliveryStore, NotFoundError,
                           NotVisibleError, Recipient, decrypt_copy)

MSG_SIZE = 2 * 1024 * 1024 + 123  # crosses the 1 MiB chunk boundary


def read_copy_file(store_dir, request_id, recipient_id):
    path = os.path.join(store_dir, "copies", request_id, recipient_id + ".bin")
    with open(path, "rb") as fh:
        return fh.read()


def test_basic_roundtrip_and_all_or_nothing_visibility(tmp_path, master_key):
    recipients, privs = make_recipients(3)
    message = pattern_bytes(MSG_SIZE)
    store = DeliveryStore(str(tmp_path / "s"), master_key)

    assert store.submit("r1", recipients, io.BytesIO(message)) == "r1"
    # Until publication nobody can read anything.
    for rec in recipients:
        with pytest.raises(NotVisibleError):
            store.read("r1", rec.recipient_id)

    status = store.advance("r1", 1)
    assert (status.state, status.completed) == ("accepted", 1)
    for rec in recipients:
        with pytest.raises(NotVisibleError):
            store.read("r1", rec.recipient_id)

    status = store.advance("r1", 100)
    assert (status.state, status.total, status.completed) == ("published", 3, 3)
    for rec in recipients:
        copy = store.read("r1", rec.recipient_id)
        assert decrypt_copy(privs[rec.recipient_id], copy) == message
    # Message ciphertext is gone after publication.
    assert os.listdir(tmp_path / "s" / "messages") == []
    store.close()


def test_idempotent_resubmit_with_reordered_recipients(tmp_path, master_key):
    recipients, privs = make_recipients(4)
    message = pattern_bytes(500_000)
    store = DeliveryStore(str(tmp_path / "s"), master_key)

    assert store.submit("r1", recipients, io.BytesIO(message)) == "r1"
    store.advance("r1", 2)
    # Same bytes, same set, different order -> original delivery, no reset.
    reordered = list(reversed(recipients))
    assert store.submit("r1", reordered, io.BytesIO(message)) == "r1"
    status = store.status("r1")
    assert (status.state, status.completed) == ("accepted", 2)
    store.advance("r1", 100)
    for rec in recipients:
        assert decrypt_copy(privs[rec.recipient_id],
                            store.read("r1", rec.recipient_id)) == message
    store.close()


def test_conflicting_resubmit_rejected_without_damage(tmp_path, master_key):
    recipients, privs = make_recipients(3)
    message = pattern_bytes(300_000)
    store = DeliveryStore(str(tmp_path / "s"), master_key)
    store.submit("r1", recipients, io.BytesIO(message))
    store.advance("r1", 1)

    # Different content -> conflict.
    with pytest.raises(ConflictError):
        store.submit("r1", recipients, io.BytesIO(pattern_bytes(300_001)))
    # Different public key for one member -> conflict.
    other, _ = make_recipients(1)
    tampered = [recipients[0], recipients[1],
                Recipient(recipients[2].recipient_id, other[0].public_key_pem)]
    with pytest.raises(ConflictError):
        store.submit("r1", tampered, io.BytesIO(message))
    # Different membership -> conflict.
    with pytest.raises(ConflictError):
        store.submit("r1", recipients[:2], io.BytesIO(message))

    # Original progress and outcome are intact.
    assert store.status("r1").completed == 1
    store.advance("r1", 100)
    for rec in recipients:
        assert decrypt_copy(privs[rec.recipient_id],
                            store.read("r1", rec.recipient_id)) == message
    store.close()


def test_crash_mid_fanout_then_restart_finishes(tmp_path, master_key):
    """Some recipients committed, child SIGKILLed, input source removed;
    restart must finish with old ciphertext reused byte-for-byte."""
    store_dir = tmp_path / "s"
    recipients, privs = make_recipients(4)
    rec_json = write_recipients_json(tmp_path / "recips.json", recipients)
    message = pattern_bytes(MSG_SIZE)
    src = tmp_path / "input.bin"
    src.write_bytes(message)

    # Submit (durable), then commit exactly one recipient in a second process.
    proc = run_child(store_dir, master_key, "r1", rec_json,
                     mode="submit", size=MSG_SIZE, message_file=src)
    assert proc.returncode == 0, proc.stderr
    proc = run_child(store_dir, master_key, "r1", rec_json,
                     mode="advance", size=MSG_SIZE, limit=1, once=True)
    assert proc.returncode == 0, proc.stderr
    # Third process is SIGKILLed while writing the second recipient's copy.
    proc = run_child(store_dir, master_key, "r1", rec_json,
                     mode="advance", size=MSG_SIZE, limit=1,
                     kill_at="after_copy_file", once=True)
    assert proc.returncode == -9, proc.stderr

    os.unlink(src)  # input source is gone for good

    done_before = {}
    store = DeliveryStore(str(store_dir), master_key)
    status = store.status("r1")
    assert status.state == "accepted" and status.completed == 1
    for rec in recipients:
        with pytest.raises(NotVisibleError):
            store.read("r1", rec.recipient_id)
    store.close()
    import sqlite3
    db = sqlite3.connect(store_dir / "store.db")
    committed = [row[0] for row in db.execute(
        "SELECT recipient_id FROM recipients WHERE state='done'")]
    db.close()
    assert len(committed) == 1
    copy_dir = store_dir / "copies" / "r1"
    for rid in committed:
        done_before[rid] = (copy_dir / f"{rid}.bin").read_bytes()

    # Restart (new master-key-only process state) and finish via advance.
    store = DeliveryStore(str(store_dir), master_key)
    status = store.advance("r1", 1)
    assert status.state == "accepted"
    status = store.advance("r1", 100)
    assert status.state == "published" and status.completed == 4

    # Previously committed copy reused unchanged.
    for rid, blob in done_before.items():
        assert (copy_dir / f"{rid}.bin").read_bytes() == blob
    # Exactly one decryptable copy per recipient, all byte-identical.
    assert len([f for f in os.listdir(copy_dir) if f.endswith(".bin")]) == 4
    for rec in recipients:
        copy = store.read("r1", rec.recipient_id)
        assert decrypt_copy(privs[rec.recipient_id], copy) == message
    store.close()


def test_crash_between_copy_file_and_commit(tmp_path, master_key):
    store_dir = tmp_path / "s"
    recipients, privs = make_recipients(3)
    rec_json = write_recipients_json(tmp_path / "recips.json", recipients)
    message = pattern_bytes(MSG_SIZE)

    proc = run_child(store_dir, master_key, "r1", rec_json,
                     mode="submit_advance", size=MSG_SIZE, limit=1,
                     kill_at="after_copy_file")
    assert proc.returncode == -9, proc.stderr

    store = DeliveryStore(str(store_dir), master_key)
    # Nothing committed for any recipient; no partial visibility.
    assert store.status("r1").completed == 0
    for rec in recipients:
        with pytest.raises(NotVisibleError):
            store.read("r1", rec.recipient_id)
    # Recovery converges to exactly one copy per recipient.
    status = store.advance("r1", 100)
    assert status.state == "published"
    copy_dir = store_dir / "copies" / "r1"
    files = sorted(os.listdir(copy_dir))
    assert files == sorted(f"{r.recipient_id}.bin" for r in recipients)
    for rec in recipients:
        assert decrypt_copy(privs[rec.recipient_id],
                            store.read("r1", rec.recipient_id)) == message
    store.close()


def test_crash_around_publish(tmp_path, master_key):
    recipients, privs = make_recipients(3)
    rec_json = write_recipients_json(tmp_path / "recips.json", recipients)
    message = pattern_bytes(MSG_SIZE)

    for kill_at, expect_published in (("before_publish", False),
                                      ("after_publish", True)):
        store_dir = tmp_path / kill_at
        proc = run_child(store_dir, master_key, "r1", rec_json,
                         mode="submit_advance", size=MSG_SIZE, limit=1,
                         kill_at=kill_at)
        assert proc.returncode == -9, proc.stderr

        store = DeliveryStore(str(store_dir), master_key)
        status = store.status("r1")
        if expect_published:
            # Publish committed before the kill: must stay visible.
            assert status.state == "published"
        else:
            # Publish never committed: nothing may be visible.
            assert status.state == "accepted"
            assert status.completed == len(recipients)
            for rec in recipients:
                with pytest.raises(NotVisibleError):
                    store.read("r1", rec.recipient_id)
            status = store.advance("r1", 1)
            assert status.state == "published"
        # Repeated advance is a no-op once published.
        assert store.advance("r1", 1).state == "published"
        for rec in recipients:
            assert decrypt_copy(privs[rec.recipient_id],
                                store.read("r1", rec.recipient_id)) == message
        store.close()


def test_crash_after_message_file_before_submit_commit(tmp_path, master_key):
    store_dir = tmp_path / "s"
    recipients, privs = make_recipients(2)
    rec_json = write_recipients_json(tmp_path / "recips.json", recipients)
    message = pattern_bytes(MSG_SIZE)

    proc = run_child(store_dir, master_key, "r1", rec_json,
                     mode="submit", size=MSG_SIZE, kill_at="after_msg_file")
    assert proc.returncode == -9, proc.stderr

    store = DeliveryStore(str(store_dir), master_key)
    # Submit never committed: request unknown, orphan ciphertext cleaned up.
    with pytest.raises(NotFoundError):
        store.status("r1")
    assert os.listdir(store_dir / "messages") == []
    # Resubmission of the same request works normally.
    store.submit("r1", recipients, io.BytesIO(message))
    store.advance("r1", 100)
    for rec in recipients:
        assert decrypt_copy(privs[rec.recipient_id],
                            store.read("r1", rec.recipient_id)) == message
    store.close()


def test_submit_and_advance_memory_bounded_64mib(tmp_path, master_key):
    store_dir = tmp_path / "s"
    recipients, _ = make_recipients(3)
    rec_json = write_recipients_json(tmp_path / "recips.json", recipients)
    size = 64 * 1024 * 1024
    proc = run_child(store_dir, master_key, "r1", rec_json,
                     mode="submit_advance", size=size, limit=1)
    assert proc.returncode == 0, proc.stderr
    import json
    report = json.loads(proc.stdout.strip().splitlines()[-1])
    limit = 24 * 1024 * 1024
    assert report["peak_delta_bytes"] < limit, report

    store = DeliveryStore(str(store_dir), master_key)
    assert store.status("r1").state == "published"
    store.close()
