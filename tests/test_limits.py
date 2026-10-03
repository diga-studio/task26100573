"""64 MiB input support, peak-memory bound, and 100-recipient fan-out."""
import hashlib
import io
import json
import os

import pytest

from resilient_delivery import DeliveryService, Recipient, decrypt_copy

from helpers import make_job, make_private_keys, run_worker

MIB = 1 << 20


def test_submit_advance_peak_memory_bounded(tmp_path):
    """Extra peak RSS of submit+advance must stay under 24 MiB for 64 MiB input."""
    keys = make_private_keys(5)
    data = os.urandom(64 * MIB)
    job, master_key = make_job(tmp_path, keys, data)
    del data
    proc = run_worker(tmp_path / "store", job, "req-mem", "memory")
    report = json.loads(proc.stdout.strip())
    assert report["delta_mib"] <= 24, f"peak extra memory {report['delta_mib']} MiB"


def test_full_size_roundtrip(tmp_path):
    keys = make_private_keys(3)
    data = os.urandom(64 * MIB)
    expected = hashlib.sha256(data).hexdigest()
    master_key = os.urandom(32)
    svc = DeliveryService(tmp_path / "store", master_key)
    recipients = [Recipient(f"u{i}", k.public_key()) for i, k in enumerate(keys)]
    svc.submit("req-64m", recipients, io.BytesIO(data))
    status = svc.advance("req-64m", 1)
    while status.state != "published":
        status = svc.advance("req-64m", 1)
    plain = decrypt_copy(keys[2], svc.read("req-64m", "u2"))
    assert hashlib.sha256(plain).hexdigest() == expected
    svc.close()


def test_max_recipients(tmp_path):
    keys = make_private_keys(100)
    data = os.urandom(50_000)
    master_key = os.urandom(32)
    svc = DeliveryService(tmp_path / "store", master_key)
    recipients = [Recipient(f"u{i:03d}", k.public_key()) for i, k in enumerate(keys)]
    status = svc.submit("req-100", recipients, io.BytesIO(data))
    assert status.total == 100
    status = svc.advance("req-100", 30)
    assert (status.state, status.committed) == ("accepted", 30)
    status = svc.advance("req-100", 100)
    assert (status.state, status.committed) == ("published", 100)
    for i in (0, 50, 99):
        copy = svc.read("req-100", f"u{i:03d}")
        assert decrypt_copy(keys[i], copy) == data
    svc.close()
