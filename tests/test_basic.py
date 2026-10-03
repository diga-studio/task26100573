"""Basic flow, all-or-nothing visibility, idempotency and conflict semantics."""
import io
import os

import pytest

from resilient_delivery import (
    DeliveryService,
    Recipient,
    decrypt_copy,
)
from resilient_delivery.errors import (
    ConflictError,
    DeliveryError,
    NotFoundError,
    NotVisibleError,
)

from helpers import make_private_keys, public_der


@pytest.fixture
def keys():
    return make_private_keys(4)


@pytest.fixture
def recipients(keys):
    return [Recipient(f"user{i}", k.public_key()) for i, k in enumerate(keys)]


@pytest.fixture
def master_key():
    return os.urandom(32)


def test_submit_advance_read_roundtrip(tmp_path, master_key, keys, recipients):
    data = os.urandom(2 * 1024 * 1024 + 123)
    svc = DeliveryService(tmp_path / "store", master_key)
    status = svc.submit("req-1", recipients, io.BytesIO(data))
    assert (status.state, status.committed, status.total) == ("accepted", 0, 4)

    # not visible before publish
    with pytest.raises(NotVisibleError):
        svc.read("req-1", "user0")

    status = svc.advance("req-1", 1)
    assert (status.state, status.committed) == ("accepted", 1)
    with pytest.raises(NotVisibleError):
        svc.read("req-1", "user0")

    status = svc.advance("req-1", 100)
    assert (status.state, status.committed) == ("published", 4)

    for i, key in enumerate(keys):
        copy = svc.read("req-1", f"user{i}")
        assert copy.key_wrap == "RSA-OAEP-SHA256"
        assert decrypt_copy(key, copy) == data
    svc.close()


def test_empty_message(tmp_path, master_key, keys, recipients):
    svc = DeliveryService(tmp_path / "store", master_key)
    svc.submit("req-empty", recipients[:1], io.BytesIO(b""))
    svc.advance("req-empty", 10)
    copy = svc.read("req-empty", "user0")
    assert decrypt_copy(keys[0], copy) == b""
    svc.close()


def test_read_unknown_ids(tmp_path, master_key, recipients):
    svc = DeliveryService(tmp_path / "store", master_key)
    svc.submit("req-1", recipients, io.BytesIO(b"x"))
    svc.advance("req-1", 10)
    with pytest.raises(NotFoundError):
        svc.read("nope", "user0")
    with pytest.raises(NotFoundError):
        svc.read("req-1", "nobody")
    with pytest.raises(NotFoundError):
        svc.advance("nope", 1)
    svc.close()


def test_idempotent_resubmit_reordered_recipients(tmp_path, master_key, recipients):
    data = os.urandom(100_000)
    svc = DeliveryService(tmp_path / "store", master_key)
    first = svc.submit("req-1", recipients, io.BytesIO(data))
    # make progress, then resubmit with reversed recipient order
    svc.advance("req-1", 2)
    again = svc.submit("req-1", list(reversed(recipients)), io.BytesIO(data))
    assert again == first.__class__("req-1", "accepted", 2, 4)
    # progress preserved
    status = svc.advance("req-1", 100)
    assert (status.state, status.committed) == ("published", 4)
    svc.close()


def test_conflicting_resubmit_does_not_change_delivery(
    tmp_path, master_key, keys, recipients
):
    data = b"original content"
    svc = DeliveryService(tmp_path / "store", master_key)
    svc.submit("req-1", recipients, io.BytesIO(data))
    svc.advance("req-1", 2)

    # different content
    with pytest.raises(ConflictError):
        svc.submit("req-1", recipients, io.BytesIO(b"tampered content"))
    # different recipient set (extra recipient)
    extra = make_private_keys(1)[0]
    with pytest.raises(ConflictError):
        svc.submit("req-1", recipients + [Recipient("userX", extra.public_key())],
                   io.BytesIO(data))
    # different public key for an existing recipient
    swapped = recipients[:]
    swapped[1] = Recipient("user1", extra.public_key())
    with pytest.raises(ConflictError):
        svc.submit("req-1", swapped, io.BytesIO(data))

    # original delivery untouched: progress intact, finishes, decrypts
    status = svc.advance("req-1", 100)
    assert (status.state, status.committed) == ("published", 4)
    for i, key in enumerate(keys):
        assert decrypt_copy(key, svc.read("req-1", f"user{i}")) == data
    svc.close()


def test_validation(tmp_path, master_key, recipients):
    svc = DeliveryService(tmp_path / "store", master_key)
    with pytest.raises(DeliveryError):
        svc.submit("req-1", [], io.BytesIO(b"x"))
    with pytest.raises(DeliveryError):
        svc.submit("req-1", recipients * 30, io.BytesIO(b"x"))  # >100 & dupes
    with pytest.raises(DeliveryError):
        svc.submit("req-1", [recipients[0], recipients[0]], io.BytesIO(b"x"))
    with pytest.raises(ValueError):
        DeliveryService(tmp_path / "other", b"short")
    svc.close()


def test_message_size_limit(tmp_path, master_key, recipients):
    svc = DeliveryService(tmp_path / "store", master_key)

    class Endless:
        def read(self, n=-1):
            return b"\x00" * n

    with pytest.raises(DeliveryError):
        svc.submit("req-big", recipients, Endless())
    # failed submit leaves no delivery behind
    with pytest.raises(NotFoundError):
        svc.advance("req-big", 1)
    svc.close()


def test_wrong_master_key_rejected(tmp_path, master_key, recipients):
    svc = DeliveryService(tmp_path / "store", master_key)
    svc.submit("req-1", recipients, io.BytesIO(b"secret"))
    svc.close()
    with pytest.raises(DeliveryError):
        DeliveryService(tmp_path / "store", os.urandom(32))


def test_no_plaintext_on_disk(tmp_path, master_key, recipients):
    data = b"A-VERY-RECOGNIZABLE-PLAINTEXT-MARKER" * 1000
    svc = DeliveryService(tmp_path / "store", master_key)
    svc.submit("req-1", recipients, io.BytesIO(data))
    svc.advance("req-1", 100)
    svc.close()
    store = tmp_path / "store"
    for path in store.rglob("*"):
        if path.is_file():
            assert b"A-VERY-RECOGNIZABLE-PLAINTEXT-MARKER" not in path.read_bytes(), path
