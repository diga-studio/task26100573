"""Shared helpers for the test suite."""
import json
import os
import subprocess
import sys
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

REPO_ROOT = Path(__file__).resolve().parent.parent
WORKER = REPO_ROOT / "tests" / "crash_worker.py"


def make_private_keys(n: int):
    return [rsa.generate_private_key(public_exponent=65537, key_size=2048)
            for _ in range(n)]


def public_der(key) -> bytes:
    return key.public_key().public_bytes(
        serialization.Encoding.DER,
        serialization.PublicFormat.SubjectPublicKeyInfo,
    )


def make_job(tmp_path: Path, private_keys, data: bytes, master_key: bytes = None):
    """Create a worker job directory; returns (job_dir, master_key)."""
    job = tmp_path / "job"
    (job / "pubkeys").mkdir(parents=True)
    master_key = master_key or os.urandom(32)
    (job / "master.key").write_bytes(master_key)
    (job / "data.bin").write_bytes(data)
    for i, key in enumerate(private_keys):
        (job / "pubkeys" / f"user{i:03d}.der").write_bytes(public_der(key))
    return job, master_key


def run_worker(*args, expect_signal: bool = False):
    cmd = [sys.executable, str(WORKER), *[str(a) for a in args]]
    proc = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
    if expect_signal:
        assert proc.returncode == -9, (
            f"expected SIGKILL, got rc={proc.returncode}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    else:
        assert proc.returncode == 0, (
            f"worker failed rc={proc.returncode}\n"
            f"stdout={proc.stdout}\nstderr={proc.stderr}"
        )
    return proc
