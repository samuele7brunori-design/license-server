"""Offline administration CLI for TapeSense licensing protocol v2."""
from __future__ import annotations

import argparse
import hashlib
import os
import re
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

try:
    from license_server.license_v2 import create_license, init_schema, store_activation_key
except ImportError:
    from license_v2 import create_license, init_schema, store_activation_key


def _database_path(value: str | None) -> Path:
    return Path(value or os.environ.get("LICENSE_DB_PATH", "licenses.db")).resolve()


def _connection(path: Path) -> sqlite3.Connection:
    connection = sqlite3.connect(path)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    init_schema(connection)
    connection.execute(
        "CREATE TABLE IF NOT EXISTS app_config (key TEXT PRIMARY KEY, value TEXT)"
    )
    connection.commit()
    return connection


def publish_release(
    connection: sqlite3.Connection,
    *,
    source: Path,
    uploads_dir: Path,
    version: str,
    notes: str,
) -> tuple[Path, str]:
    """Atomically publish an update binary and its server metadata."""
    if not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", version):
        raise ValueError("Versione non valida (usare es. 1.2.3)")
    if len(notes) > 10_000:
        raise ValueError("Note release troppo lunghe")
    source = source.resolve(strict=True)
    if not source.is_file() or source.stat().st_size < 1:
        raise ValueError("File release vuoto o non valido")
    uploads_dir.mkdir(parents=True, exist_ok=True)
    destination = uploads_dir / "TapeSense.exe"
    temporary = uploads_dir / "TapeSense.exe.tmp"
    previous = uploads_dir / "TapeSense.exe.previous"
    digest = hashlib.sha256()
    try:
        with source.open("rb") as incoming, temporary.open("wb") as outgoing:
            while True:
                block = incoming.read(1024 * 1024)
                if not block:
                    break
                digest.update(block)
                outgoing.write(block)
            outgoing.flush()
            os.fsync(outgoing.fileno())
        previous.unlink(missing_ok=True)
        had_previous = destination.exists()
        if had_previous:
            os.replace(destination, previous)
        try:
            os.replace(temporary, destination)
            connection.execute(
                "INSERT OR REPLACE INTO app_config(key,value) VALUES('current_version',?)",
                (version,),
            )
            connection.execute(
                "INSERT OR REPLACE INTO app_config(key,value) VALUES('version_notes',?)",
                (notes,),
            )
            connection.execute(
                "INSERT OR REPLACE INTO app_config(key,value) VALUES('exe_filename','TapeSense.exe')"
            )
            connection.commit()
            previous.unlink(missing_ok=True)
        except Exception:
            connection.rollback()
            destination.unlink(missing_ok=True)
            if had_previous and previous.exists():
                os.replace(previous, destination)
            raise
    finally:
        temporary.unlink(missing_ok=True)
    return destination, digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description="Gestione sicura licenze TapeSense v2")
    parser.add_argument("--db", help="Percorso database (default LICENSE_DB_PATH)")
    commands = parser.add_subparsers(dest="command", required=True)

    create = commands.add_parser("create", help="Crea una chiave, mostrata una sola volta")
    create.add_argument("--plan", choices=("lifetime", "yearly", "monthly"), default="lifetime")
    create.add_argument("--days", type=int, help="Scadenza tra N giorni")
    create.add_argument("--max-devices", type=int, default=2)

    commands.add_parser("list", help="Elenca solo ID e ultime quattro cifre")
    revoke = commands.add_parser("revoke", help="Revoca una licenza per ID")
    revoke.add_argument("license_id")
    restore = commands.add_parser("restore", help="Riattiva una licenza per ID")
    restore.add_argument("license_id")
    device = commands.add_parser("revoke-device", help="Revoca un singolo dispositivo")
    device.add_argument("device_id")
    migrate = commands.add_parser(
        "migrate-legacy", help="Hasha le chiavi della tabella SQLite legacy nello schema v2"
    )
    migrate.add_argument("--default-plan", choices=("lifetime", "yearly", "monthly"), default="lifetime")
    migrate.add_argument("--max-devices", type=int, default=2)
    publish = commands.add_parser(
        "publish-release", help="Pubblica atomicamente exe, versione e note"
    )
    publish.add_argument("--file", required=True, type=Path)
    publish.add_argument("--version", required=True)
    publish.add_argument("--notes", default="")

    args = parser.parse_args()
    path = _database_path(args.db)
    path.parent.mkdir(parents=True, exist_ok=True)
    with _connection(path) as db:
        if args.command == "create":
            pepper = os.environ.get("LICENSE_KEY_PEPPER", "").strip()
            if not pepper:
                parser.error("LICENSE_KEY_PEPPER è obbligatoria")
            expires_at = None
            if args.days is not None:
                if args.days < 1:
                    parser.error("--days deve essere positivo")
                expires_at = (datetime.now(timezone.utc) + timedelta(days=args.days)).isoformat()
            license_id, raw_key = create_license(
                db,
                pepper=pepper,
                plan=args.plan,
                expires_at=expires_at,
                max_devices=args.max_devices,
            )
            print(f"ID: {license_id}")
            print(f"CHIAVE (visibile solo ora): {raw_key}")
        elif args.command == "list":
            rows = db.execute(
                "SELECT id,key_last4,plan,expires_at,max_devices,active,created_at "
                "FROM licenses_v2 ORDER BY created_at DESC"
            ).fetchall()
            for row in rows:
                status = "attiva" if row["active"] else "revocata"
                print(
                    f"{row['id']}  …{row['key_last4']}  {row['plan']}  {status}  "
                    f"devices={row['max_devices']}  expires={row['expires_at'] or 'mai'}"
                )
        elif args.command in {"revoke", "restore"}:
            active = 0 if args.command == "revoke" else 1
            cursor = db.execute(
                "UPDATE licenses_v2 SET active=? WHERE id=?", (active, args.license_id)
            )
            if cursor.rowcount != 1:
                parser.error("ID licenza non trovato")
            print("Operazione completata.")
        elif args.command == "revoke-device":
            cursor = db.execute(
                "UPDATE devices_v2 SET revoked=1 WHERE id=?", (args.device_id,)
            )
            if cursor.rowcount != 1:
                parser.error("ID dispositivo non trovato")
            print("Dispositivo revocato.")
        elif args.command == "migrate-legacy":
            pepper = os.environ.get("LICENSE_KEY_PEPPER", "").strip()
            if not pepper:
                parser.error("LICENSE_KEY_PEPPER è obbligatoria")
            table = db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name='licenses'"
            ).fetchone()
            if not table:
                parser.error("Tabella legacy 'licenses' non trovata")
            columns = {
                row["name"] for row in db.execute("PRAGMA table_info(licenses)").fetchall()
            }
            if "key" not in columns:
                parser.error("Schema legacy non riconosciuto")
            imported = skipped = 0
            for row in db.execute("SELECT * FROM licenses").fetchall():
                plan = row["plan"] if "plan" in columns and row["plan"] else args.default_plan
                expires_at = row["expires_at"] if "expires_at" in columns else None
                max_devices = (
                    row["max_machines"]
                    if "max_machines" in columns and row["max_machines"]
                    else args.max_devices
                )
                active = bool(row["active"]) if "active" in columns else not bool(
                    row["revoked"] if "revoked" in columns else 0
                )
                try:
                    store_activation_key(
                        db,
                        activation_key=row["key"],
                        pepper=pepper,
                        plan=plan if plan in {"lifetime", "yearly", "monthly"} else args.default_plan,
                        expires_at=expires_at,
                        max_devices=max_devices,
                        active=active,
                    )
                    imported += 1
                except sqlite3.IntegrityError:
                    skipped += 1
            print(f"Migrazione completata: {imported} importate, {skipped} già presenti.")
        elif args.command == "publish-release":
            uploads = Path(
                os.environ.get(
                    "LICENSE_UPLOADS_DIR", str(path.parent / "uploads")
                )
            ).resolve()
            destination, digest = publish_release(
                db,
                source=args.file,
                uploads_dir=uploads,
                version=args.version,
                notes=args.notes,
            )
            print(f"Release pubblicata: {destination}")
            print(f"SHA256: {digest}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
