"""Subprocess worker for crash-recovery tests.

The parent test prepares a job directory containing ``master.key`` (32
bytes), ``pubkeys/<recipient_id>.der`` and ``data.bin``, then runs this
script. When ``crash_at`` matches an internal hook label the worker kills
itself with SIGKILL at that exact point, simulating a hard crash (no
Python exception, no cleanup).

Usage:
    crash_worker.py <storage> <job> <request_id> submit <crash_at|->
    crash_worker.py <storage> <job> <request_id> advance <limit> <crash_at|->
    crash_worker.py <storage> <job> <request_id> memory
"""
import json
import os
import platform
import signal
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from resilient_delivery import DeliveryService, Recipient  # noqa: E402


def load_recipients(job: Path):
    return [
        Recipient(p.stem, p.read_bytes())
        for p in sorted((job / "pubkeys").glob("*.der"))
    ]


def make_hook(crash_at: str):
    """``crash_at`` is ``label`` or ``label:N`` (kill on the Nth firing)."""
    label, _, count = crash_at.partition(":")
    target = int(count) if count else 1
    seen = {"n": 0}

    def hook(point: str) -> None:
        if point != label:
            return
        seen["n"] += 1
        if seen["n"] == target:
            os.kill(os.getpid(), signal.SIGKILL)

    return hook if crash_at != "-" else None


def main() -> None:
    storage, job, request_id, mode = sys.argv[1], Path(sys.argv[2]), sys.argv[3], sys.argv[4]
    master = (job / "master.key").read_bytes()

    if mode == "submit":
        hook = make_hook(sys.argv[5])
        svc = DeliveryService(storage, master, _hook=hook)
        with open(job / "data.bin", "rb") as fh:
            svc.submit(request_id, load_recipients(job), fh)
        svc.close()
    elif mode == "advance":
        limit, crash_at = int(sys.argv[5]), sys.argv[6]
        svc = DeliveryService(storage, master, _hook=make_hook(crash_at))
        svc.advance(request_id, limit)
        svc.close()
    elif mode == "memory":
        import resource

        svc = DeliveryService(storage, master)
        base = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        with open(job / "data.bin", "rb") as fh:
            svc.submit(request_id, load_recipients(job), fh)
        status = svc.advance(request_id, 7)
        while status.state != "published":
            status = svc.advance(request_id, 7)
        peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
        factor = 1 if platform.system() == "Darwin" else 1024
        print(json.dumps({"delta_mib": (peak - base) * factor / 2**20}))
        svc.close()
    else:
        raise SystemExit(f"unknown mode: {mode}")


if __name__ == "__main__":
    main()
