"""Crash-recovery tests using real SIGKILLed subprocesses (no catchable exceptions)."""
import io
import os

import pytest

from resilient_delivery import DeliveryService, Recipient, decrypt_copy
from resilient_delivery.errors import NotVisibleError

from helpers import make_job, make_private_keys, public_der, run_worker

N_RECIPIENTS = 4


@pytest.fixture
def job_setup(tmp_path):
    keys = make_private_keys(N_RECIPIENTS)
    data = os.urandom(1 * 1024 * 1024 + 999)
    job, master_key = make_job(tmp_path, keys, data)
    storage = tmp_path / "store"
    return storage, job, master_key, keys, data


def recipients_from_job(job):
    return [
        Recipient(p.stem, p.read_bytes())
        for p in sorted((job / "pubkeys").glob("*.der"))
    ]


def copy_files(storage, request_id):
    return sorted((storage / "copies" / request_id).glob("*.copy"))


def finish_in_process(storage, master_key, request_id, limit=1):
    svc = DeliveryService(storage, master_key)
    status = svc.advance(request_id, limit)
    while status.state != "published":
        status = svc.advance(request_id, limit)
    return svc, status


def test_partial_then_kill_then_restart_completes(job_setup):
    storage, job, master_key, keys, data = job_setup
    req = "req-crash"

    run_worker(storage, job, req, "submit", "-")
    # commit 2 recipients, then die between the 3rd copy file and its commit
    run_worker(storage, job, req, "advance", 3, "copy_written:3",
               expect_signal=True)

    # input source is gone; restart must not depend on it
    (job / "data.bin").unlink()

    before = {p.name: p.read_bytes() for p in copy_files(storage, req)}
    assert len(before) >= 2  # committed copies survive the crash

    svc, status = finish_in_process(storage, master_key, req, limit=1)
    assert (status.state, status.committed, status.total) == (
        "published", N_RECIPIENTS, N_RECIPIENTS)

    # previously committed copies are reused byte-for-byte
    for i in range(2):
        name = f"user{i:03d}.copy"
        assert before[name] == (storage / "copies" / req / name).read_bytes()

    # every copy decrypts byte-identically to the original message
    for i, key in enumerate(keys):
        copy = svc.read(req, f"user{i:03d}")
        assert decrypt_copy(key, copy) == data
    svc.close()


def test_crash_between_copy_and_commit_leaves_no_partial_state(job_setup):
    storage, job, master_key, keys, data = job_setup
    req = "req-mid"

    run_worker(storage, job, req, "submit", "-")
    run_worker(storage, job, req, "advance", 1, "copy_written", expect_signal=True)

    svc = DeliveryService(storage, master_key)
    status = svc._status(req)
    assert (status.state, status.committed) == ("accepted", 0)
    # nothing visible, orphan copy file swept on open
    for i in range(N_RECIPIENTS):
        with pytest.raises(NotVisibleError):
            svc.read(req, f"user{i:03d}")
    assert not (storage / "copies" / req).exists() or not copy_files(storage, req)

    status = svc.advance(req, 100)
    assert (status.state, status.committed) == ("published", N_RECIPIENTS)
    # exactly one decryptable copy per recipient
    assert len(copy_files(storage, req)) == N_RECIPIENTS
    for i, key in enumerate(keys):
        assert decrypt_copy(key, svc.read(req, f"user{i:03d}")) == data
    svc.close()


def test_crash_before_publish_not_visible_then_converges(job_setup):
    storage, job, master_key, keys, data = job_setup
    req = "req-prepub"

    run_worker(storage, job, req, "submit", "-")
    # all copies committed, killed right before the publish update
    run_worker(storage, job, req, "advance", 100, "before_publish",
               expect_signal=True)

    svc = DeliveryService(storage, master_key)
    status = svc._status(req)
    assert (status.state, status.committed) == ("accepted", N_RECIPIENTS)
    for i in range(N_RECIPIENTS):
        with pytest.raises(NotVisibleError):
            svc.read(req, f"user{i:03d}")

    # next advance publishes without regenerating any copy
    before = {p.name: p.read_bytes() for p in copy_files(storage, req)}
    status = svc.advance(req, 1)
    assert status.state == "published"
    for p in copy_files(storage, req):
        assert before[p.name] == p.read_bytes()
    for i, key in enumerate(keys):
        assert decrypt_copy(key, svc.read(req, f"user{i:03d}")) == data
    svc.close()


def test_crash_after_publish_stays_visible(job_setup):
    storage, job, master_key, keys, data = job_setup
    req = "req-postpub"

    run_worker(storage, job, req, "submit", "-")
    # publish committed, killed before advance() returned
    run_worker(storage, job, req, "advance", 100, "after_publish",
               expect_signal=True)

    svc = DeliveryService(storage, master_key)
    status = svc._status(req)
    assert status.state == "published"  # never regresses to invisible
    for i, key in enumerate(keys):
        assert decrypt_copy(key, svc.read(req, f"user{i:03d}")) == data
    # advance on a published delivery is a no-op
    assert svc.advance(req, 1).state == "published"
    svc.close()


def test_crash_after_submit_commit_message_not_lost(job_setup):
    storage, job, master_key, keys, data = job_setup
    req = "req-submit"

    # killed after the delivery row committed but before submit() returned
    run_worker(storage, job, req, "submit", "delivery_inserted",
               expect_signal=True)

    svc = DeliveryService(storage, master_key)
    status = svc._status(req)  # accepted message survives
    assert (status.state, status.total) == ("accepted", N_RECIPIENTS)

    # idempotent retry with same content and reordered recipients
    recips = list(reversed(recipients_from_job(job)))
    with open(job / "data.bin", "rb") as fh:
        again = svc.submit(req, recips, fh)
    assert again == status

    svc.advance(req, 100)
    for i, key in enumerate(keys):
        assert decrypt_copy(key, svc.read(req, f"user{i:03d}")) == data
    svc.close()


def test_crash_between_message_file_and_db_commit(job_setup):
    storage, job, master_key, keys, data = job_setup
    req = "req-halfsubmit"

    # killed after the message file was renamed but before the DB commit
    run_worker(storage, job, req, "submit", "message_written",
               expect_signal=True)

    svc = DeliveryService(storage, master_key)
    # orphan message file swept, no delivery recorded
    assert not list((storage / "messages").iterdir())
    with pytest.raises(Exception):
        svc._status(req)

    # clean resubmit works
    with open(job / "data.bin", "rb") as fh:
        svc.submit(req, recipients_from_job(job), fh)
    svc.advance(req, 100)
    for i, key in enumerate(keys):
        assert decrypt_copy(key, svc.read(req, f"user{i:03d}")) == data
    svc.close()


def test_repeated_single_step_crashes_converge(job_setup):
    storage, job, master_key, keys, data = job_setup
    req = "req-steps"

    run_worker(storage, job, req, "submit", "-")
    # die right after each commit; each restart reuses committed copies
    for _ in range(2):
        run_worker(storage, job, req, "advance", 100, "recipient_committed",
                   expect_signal=True)
    svc, status = finish_in_process(storage, master_key, req, limit=1)
    assert (status.state, status.committed) == ("published", N_RECIPIENTS)
    assert len(copy_files(storage, req)) == N_RECIPIENTS
    for i, key in enumerate(keys):
        assert decrypt_copy(key, svc.read(req, f"user{i:03d}")) == data
    svc.close()
