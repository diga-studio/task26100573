import json
import os
import subprocess
import sys

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from luna_delivery import Recipient  # noqa: E402

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CHILD = os.path.join(REPO_ROOT, "tests", "child_worker.py")


def make_recipients(n):
    recipients, private_keys = [], {}
    for i in range(n):
        priv = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        rid = f"user{i:03d}"
        pub_pem = priv.public_key().public_bytes(
            serialization.Encoding.PEM,
            serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        recipients.append(Recipient(rid, pub_pem))
        private_keys[rid] = priv.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    return recipients, private_keys


def write_recipients_json(path, recipients):
    data = [
        {"recipient_id": r.recipient_id, "public_key_pem": r.public_key_pem.decode()}
        for r in recipients
    ]
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(data, fh)
    return str(path)


def run_child(store_dir, master_key, request_id, recipients_json, mode,
              size=1024, limit=1, kill_at=None, message_file=None, once=False):
    cmd = [
        sys.executable, CHILD,
        "--store", str(store_dir),
        "--master-hex", master_key.hex(),
        "--request", request_id,
        "--recipients-json", str(recipients_json),
        "--mode", mode,
        "--size", str(size),
        "--limit", str(limit),
    ]
    if kill_at:
        cmd += ["--kill-at", kill_at]
    if message_file:
        cmd += ["--message-file", str(message_file)]
    if once:
        cmd += ["--once"]
    return subprocess.run(cmd, capture_output=True, text=True, timeout=300)


def pattern_bytes(size):
    return bytes((i * 31 + 7) % 256 for i in range(size))


@pytest.fixture
def master_key():
    return os.urandom(32)
