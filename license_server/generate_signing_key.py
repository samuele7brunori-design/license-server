"""Generate an Ed25519 server signing key without committing it to source."""
from __future__ import annotations

import argparse
import json
import os
from pathlib import Path

from license_protocol import generate_device_keypair


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--key-id", required=True, help="Es. license-signing-2026-01")
    parser.add_argument("--private-out", required=True, type=Path)
    parser.add_argument("--public-out", required=True, type=Path)
    args = parser.parse_args()
    if args.private_out.exists() or args.public_out.exists():
        parser.error("Un file di destinazione esiste già; rotazione interrotta")
    private_key, public_key = generate_device_keypair()
    args.private_out.parent.mkdir(parents=True, exist_ok=True)
    args.public_out.parent.mkdir(parents=True, exist_ok=True)
    args.private_out.write_text(private_key + "\n", encoding="ascii")
    os.chmod(args.private_out, 0o600)
    args.public_out.write_text(
        json.dumps({args.key_id: public_key}, indent=2) + "\n", encoding="ascii"
    )
    print("Coppia generata. Conserva il file privato fuori dal repository e dai backup client.")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
