"""Child-process worker for crash-recovery tests.

Run as a real subprocess so the parent can rely on actual SIGKILL
termination (via LUNA_DELIVERY_KILL_AT inside the library) rather than
catchable exceptions.
"""

import argparse
import json
import os
import resource
import sys

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from luna_delivery import DeliveryStore, Recipient  # noqa: E402


class PatternStream:
    """Lazy, read-once deterministic byte stream (no big in-memory buffer)."""

    def __init__(self, size):
        self._remaining = size
        self._pos = 0

    def read(self, n=-1):
        if self._remaining <= 0:
            return b""
        if n is None or n < 0 or n > self._remaining:
            n = self._remaining
        start = self._pos
        self._pos += n
        self._remaining -= n
        return bytes((i * 31 + 7) % 256 for i in range(start, start + n))

    def close(self):
        pass


def load_recipients(path):
    with open(path, "r", encoding="utf-8") as fh:
        data = json.load(fh)
    return [Recipient(item["recipient_id"], item["public_key_pem"].encode()) for item in data]


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--store", required=True)
    parser.add_argument("--master-hex", required=True)
    parser.add_argument("--request", required=True)
    parser.add_argument("--recipients-json", required=True)
    parser.add_argument("--size", type=int, default=1024)
    parser.add_argument("--limit", type=int, default=1)
    parser.add_argument("--mode", choices=["submit", "advance", "submit_advance"], required=True)
    parser.add_argument("--once", action="store_true",
                        help="perform a single advance() call instead of looping to publish")
    parser.add_argument("--kill-at", default=None)
    parser.add_argument("--message-file", default=None,
                        help="read message bytes from this file instead of generating them")
    args = parser.parse_args()

    if args.kill_at:
        os.environ["LUNA_DELIVERY_KILL_AT"] = args.kill_at

    baseline = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss

    store = DeliveryStore(args.store, bytes.fromhex(args.master_hex))
    recipients = load_recipients(args.recipients_json)

    if args.mode in ("submit", "submit_advance"):
        if args.message_file:
            stream = open(args.message_file, "rb")
        else:
            stream = PatternStream(args.size)
        store.submit(args.request, recipients, stream)
        stream.close()

    if args.mode in ("advance", "submit_advance"):
        if args.once:
            store.advance(args.request, args.limit)
        else:
            while True:
                status = store.advance(args.request, args.limit)
                if status.state == "published":
                    break

    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    print(json.dumps({"peak_delta_bytes": peak - baseline}))
    store.close()


if __name__ == "__main__":
    main()
