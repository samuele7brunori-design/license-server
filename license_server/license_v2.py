"""Signed, device-bound licensing API for TapeSense protocol v2."""
from __future__ import annotations

import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import uuid
from datetime import datetime, timedelta, timezone
from typing import Callable

from flask import Blueprint, jsonify, request

from license_protocol import (
    LicenseProtocolError,
    decode_and_verify_lease,
    public_key_from_b64,
    public_key_from_private_b64,
    public_key_sha256,
    sign_lease,
    verify_challenge_signature,
)


GENERIC_INVALID = "Licenza o dispositivo non validi."
PEPPER_FINGERPRINT_CONTEXT = b"TapeSense licensing v2 pepper fingerprint"


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).isoformat()


def _required_secret(name: str) -> str:
    value = os.environ.get(name, "").strip()
    if not value:
        raise RuntimeError(f"Configurazione licensing v2 mancante: {name}")
    return value


def _key_hash(activation_key: str, pepper: str) -> str:
    if len(pepper) < 32:
        raise RuntimeError("LICENSE_KEY_PEPPER troppo corta")
    normalized = activation_key.strip().upper().encode("utf-8")
    return hmac.new(pepper.encode("utf-8"), normalized, hashlib.sha256).hexdigest()


def pepper_fingerprint(pepper: str) -> str:
    """Return a non-secret identifier used to detect admin/server mismatch."""
    if len(pepper) < 32:
        raise RuntimeError("LICENSE_KEY_PEPPER troppo corta")
    return hmac.new(
        pepper.encode("utf-8"), PEPPER_FINGERPRINT_CONTEXT, hashlib.sha256
    ).hexdigest()


def init_schema(connection: sqlite3.Connection) -> None:
    if getattr(connection, "is_postgres", False):
        connection.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses_v2 (
                id             TEXT PRIMARY KEY,
                key_hash       TEXT NOT NULL UNIQUE,
                key_last4      TEXT NOT NULL,
                plan           TEXT NOT NULL,
                features_json  TEXT NOT NULL,
                expires_at     TEXT,
                max_devices    INTEGER NOT NULL,
                active         INTEGER NOT NULL DEFAULT 1,
                created_at     TEXT NOT NULL
            );
            CREATE TABLE IF NOT EXISTS devices_v2 (
                id                 TEXT PRIMARY KEY,
                license_id         TEXT NOT NULL REFERENCES licenses_v2(id),
                public_key         TEXT NOT NULL,
                public_key_sha256  TEXT NOT NULL,
                activated_at       TEXT NOT NULL,
                last_seen          TEXT NOT NULL,
                revoked            INTEGER NOT NULL DEFAULT 0
            );
            CREATE INDEX IF NOT EXISTS idx_devices_v2_license
                ON devices_v2(license_id);
            CREATE TABLE IF NOT EXISTS challenges_v2 (
                id          TEXT PRIMARY KEY,
                license_id  TEXT NOT NULL REFERENCES licenses_v2(id),
                device_id   TEXT NOT NULL REFERENCES devices_v2(id),
                challenge   TEXT NOT NULL UNIQUE,
                expires_at  TEXT NOT NULL,
                consumed_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_challenges_v2_device
                ON challenges_v2(device_id, expires_at);
            CREATE TABLE IF NOT EXISTS license_audit_v2 (
                id           BIGSERIAL PRIMARY KEY,
                occurred_at  TEXT NOT NULL,
                event_type   TEXT NOT NULL,
                license_id   TEXT,
                device_id    TEXT,
                details_json TEXT NOT NULL
            )
            """
        )
        connection.commit()
        return
    connection.execute("PRAGMA foreign_keys=ON")
    connection.executescript(
        """
        CREATE TABLE IF NOT EXISTS licenses_v2 (
            id             TEXT PRIMARY KEY,
            key_hash       TEXT NOT NULL UNIQUE,
            key_last4      TEXT NOT NULL,
            plan           TEXT NOT NULL,
            features_json  TEXT NOT NULL,
            expires_at     TEXT,
            max_devices    INTEGER NOT NULL,
            active         INTEGER NOT NULL DEFAULT 1,
            created_at     TEXT NOT NULL
        );
        CREATE TABLE IF NOT EXISTS devices_v2 (
            id                 TEXT PRIMARY KEY,
            license_id         TEXT NOT NULL,
            public_key         TEXT NOT NULL,
            public_key_sha256  TEXT NOT NULL,
            activated_at       TEXT NOT NULL,
            last_seen          TEXT NOT NULL,
            revoked            INTEGER NOT NULL DEFAULT 0,
            FOREIGN KEY (license_id) REFERENCES licenses_v2(id)
        );
        CREATE INDEX IF NOT EXISTS idx_devices_v2_license
            ON devices_v2(license_id);
        CREATE TABLE IF NOT EXISTS challenges_v2 (
            id          TEXT PRIMARY KEY,
            license_id  TEXT NOT NULL,
            device_id   TEXT NOT NULL,
            challenge   TEXT NOT NULL UNIQUE,
            expires_at  TEXT NOT NULL,
            consumed_at TEXT,
            FOREIGN KEY (license_id) REFERENCES licenses_v2(id),
            FOREIGN KEY (device_id) REFERENCES devices_v2(id)
        );
        CREATE INDEX IF NOT EXISTS idx_challenges_v2_device
            ON challenges_v2(device_id, expires_at);
        CREATE TABLE IF NOT EXISTS license_audit_v2 (
            id          INTEGER PRIMARY KEY AUTOINCREMENT,
            occurred_at TEXT NOT NULL,
            event_type  TEXT NOT NULL,
            license_id  TEXT,
            device_id   TEXT,
            details_json TEXT NOT NULL
        );
        """
    )
    connection.commit()


def create_license(
    connection: sqlite3.Connection,
    *,
    pepper: str,
    plan: str = "lifetime",
    features: list[str] | None = None,
    expires_at: str | None = None,
    max_devices: int = 2,
) -> tuple[str, str]:
    if plan not in {"lifetime", "yearly", "monthly"}:
        raise ValueError("Piano non valido")
    if not 1 <= int(max_devices) <= 10:
        raise ValueError("Numero dispositivi non valido")
    raw_key = "TAPE-" + "-".join(secrets.token_hex(4).upper() for _ in range(4))
    license_id = store_activation_key(
        connection,
        activation_key=raw_key,
        pepper=pepper,
        plan=plan,
        features=features,
        expires_at=expires_at,
        max_devices=max_devices,
    )
    return license_id, raw_key


def store_activation_key(
    connection: sqlite3.Connection,
    *,
    activation_key: str,
    pepper: str,
    plan: str = "lifetime",
    features: list[str] | None = None,
    expires_at: str | None = None,
    max_devices: int = 2,
    active: bool = True,
) -> str:
    """Hash and import an existing key without ever returning it again."""
    normalized = activation_key.strip().upper()
    if not normalized or len(normalized) > 128:
        raise ValueError("Chiave di attivazione non valida")
    if plan not in {"lifetime", "yearly", "monthly"}:
        raise ValueError("Piano non valido")
    if not 1 <= int(max_devices) <= 10:
        raise ValueError("Numero dispositivi non valido")
    license_id = f"lic_{uuid.uuid4().hex}"
    connection.execute(
        "INSERT INTO licenses_v2 "
        "(id,key_hash,key_last4,plan,features_json,expires_at,max_devices,active,created_at) "
        "VALUES(?,?,?,?,?,?,?,?,?)",
        (
            license_id,
            _key_hash(normalized, pepper),
            normalized[-4:],
            plan,
            json.dumps(features or ["journal", "report", "market"], separators=(",", ":")),
            expires_at,
            int(max_devices),
            int(bool(active)),
            _iso(_now()),
        ),
    )
    connection.commit()
    return license_id


def _valid_license(connection: sqlite3.Connection, license_id: str):
    row = connection.execute(
        "SELECT * FROM licenses_v2 WHERE id=?", (license_id,)
    ).fetchone()
    if not row or not row["active"]:
        return None
    if row["expires_at"]:
        expires = datetime.fromisoformat(row["expires_at"].replace("Z", "+00:00"))
        if expires.astimezone(timezone.utc) <= _now():
            return None
    return row


def _audit(connection, event_type: str, license_id=None, device_id=None, **details) -> None:
    connection.execute(
        "INSERT INTO license_audit_v2 "
        "(occurred_at,event_type,license_id,device_id,details_json) VALUES(?,?,?,?,?)",
        (_iso(_now()), event_type, license_id, device_id, json.dumps(details, sort_keys=True)),
    )


def _issue_lease(connection, license_row, device_row) -> str:
    private_key = _required_secret("LICENSE_SIGNING_PRIVATE_KEY_B64")
    key_id = _required_secret("LICENSE_SIGNING_KEY_ID")
    issued = _now()
    refresh_hours = min(168, max(1, int(os.environ.get("LICENSE_REFRESH_HOURS", "24"))))
    lease_days = min(30, max(1, int(os.environ.get("LICENSE_LEASE_DAYS", "7"))))
    payload = {
        "protocol_version": 2,
        "audience": "tapesense-desktop",
        "license_id": license_row["id"],
        "device_id": device_row["id"],
        "device_public_key_sha256": device_row["public_key_sha256"],
        "plan": license_row["plan"],
        "features": json.loads(license_row["features_json"]),
        "issued_at": _iso(issued),
        "refresh_after": _iso(issued + timedelta(hours=refresh_hours)),
        "lease_expires_at": _iso(issued + timedelta(days=lease_days)),
        "token_id": f"tok_{uuid.uuid4().hex}",
    }
    return sign_lease(payload, private_key, key_id)


def _verification_keys() -> dict[str, str]:
    """Current trust key plus explicitly retained keys used during rotation."""
    private_key = _required_secret("LICENSE_SIGNING_PRIVATE_KEY_B64")
    key_id = _required_secret("LICENSE_SIGNING_KEY_ID")
    keys = {key_id: public_key_from_private_b64(private_key)}
    previous = os.environ.get("LICENSE_VERIFY_PUBLIC_KEYS_JSON", "").strip()
    if previous:
        parsed = json.loads(previous)
        if not isinstance(parsed, dict) or not all(
            isinstance(k, str) and isinstance(v, str) for k, v in parsed.items()
        ):
            raise RuntimeError("LICENSE_VERIFY_PUBLIC_KEYS_JSON non valido")
        keys.update(parsed)
    return keys


def authenticate_bearer_lease(
    connection: sqlite3.Connection, authorization: str
) -> dict:
    """Authenticate an unexpired signed lease and its live DB bindings."""
    if not authorization.startswith("Bearer "):
        raise LicenseProtocolError(GENERIC_INVALID)
    token = authorization[7:].strip()
    payload = decode_and_verify_lease(token, _verification_keys())
    lic = _valid_license(connection, payload["license_id"])
    device = connection.execute(
        "SELECT * FROM devices_v2 WHERE id=? AND license_id=? AND revoked=0",
        (payload["device_id"], payload["license_id"]),
    ).fetchone()
    if (
        not lic
        or not device
        or not hmac.compare_digest(
            device["public_key_sha256"], payload["device_public_key_sha256"]
        )
    ):
        raise LicenseProtocolError(GENERIC_INVALID)
    return payload


def create_blueprint(
    get_db: Callable[[], sqlite3.Connection],
    check_rate: Callable[[str, int, int], bool],
) -> Blueprint:
    bp = Blueprint("license_v2", __name__)

    def limited(limit: int = 20) -> bool:
        return check_rate(request.remote_addr or "unknown", limit, 60)

    @bp.post("/api/v2/activate")
    def activate_v2():
        if not limited(10):
            return jsonify({"ok": False, "message": "Troppe richieste."}), 429
        body = request.get_json(silent=True) or {}
        activation_key = str(body.get("activation_key") or "").strip().upper()
        device_id = str(body.get("device_id") or "").strip()
        public_key = str(body.get("device_public_key") or "").strip()
        if (
            not activation_key
            or len(activation_key) > 128
            or not device_id.startswith("dev_")
            or len(device_id) > 80
            or len(public_key) > 128
        ):
            return jsonify({"ok": False, "message": GENERIC_INVALID}), 400
        try:
            public_key_from_b64(public_key)
            fingerprint = public_key_sha256(public_key)
            pepper = _required_secret("LICENSE_KEY_PEPPER")
        except (LicenseProtocolError, RuntimeError):
            return jsonify({"ok": False, "message": "Servizio licensing non configurato."}), 503

        db = get_db()
        db.execute("BEGIN IMMEDIATE")
        try:
            lic = db.execute(
                "SELECT * FROM licenses_v2 WHERE key_hash=?",
                (_key_hash(activation_key, pepper),),
            ).fetchone()
            if not lic or not _valid_license(db, lic["id"]):
                db.rollback()
                return jsonify({"ok": False, "message": GENERIC_INVALID}), 403
            device = db.execute("SELECT * FROM devices_v2 WHERE id=?", (device_id,)).fetchone()
            if device:
                if device["license_id"] != lic["id"] or not hmac.compare_digest(
                    device["public_key_sha256"], fingerprint
                ) or device["revoked"]:
                    db.rollback()
                    return jsonify({"ok": False, "message": GENERIC_INVALID}), 403
                db.execute(
                    "UPDATE devices_v2 SET last_seen=? WHERE id=?",
                    (_iso(_now()), device_id),
                )
            else:
                count = db.execute(
                    "SELECT COUNT(*) FROM devices_v2 WHERE license_id=? AND revoked=0",
                    (lic["id"],),
                ).fetchone()[0]
                if count >= lic["max_devices"]:
                    db.rollback()
                    return jsonify({"ok": False, "message": "Limite dispositivi raggiunto."}), 409
                now = _iso(_now())
                db.execute(
                    "INSERT INTO devices_v2 "
                    "(id,license_id,public_key,public_key_sha256,activated_at,last_seen,revoked) "
                    "VALUES(?,?,?,?,?,?,0)",
                    (device_id, lic["id"], public_key, fingerprint, now, now),
                )
                _audit(db, "device_activated", lic["id"], device_id)
            device = db.execute("SELECT * FROM devices_v2 WHERE id=?", (device_id,)).fetchone()
            lease = _issue_lease(db, lic, device)
            db.commit()
            return jsonify({"ok": True, "lease": lease})
        except Exception:
            db.rollback()
            raise

    @bp.post("/api/v2/challenge")
    def challenge_v2():
        if not limited(30):
            return jsonify({"ok": False, "message": "Troppe richieste."}), 429
        body = request.get_json(silent=True) or {}
        license_id = str(body.get("license_id") or "")
        device_id = str(body.get("device_id") or "")
        if len(license_id) > 80 or len(device_id) > 80:
            return jsonify({"ok": False, "message": GENERIC_INVALID}), 400
        db = get_db()
        lic = _valid_license(db, license_id)
        device = db.execute(
            "SELECT * FROM devices_v2 WHERE id=? AND license_id=? AND revoked=0",
            (device_id, license_id),
        ).fetchone()
        if not lic or not device:
            return jsonify({"ok": False, "message": GENERIC_INVALID}), 403
        now = _now()
        db.execute(
            "DELETE FROM challenges_v2 WHERE expires_at<? OR consumed_at IS NOT NULL",
            (_iso(now),),
        )
        challenge = secrets.token_urlsafe(32)
        db.execute(
            "INSERT INTO challenges_v2 "
            "(id,license_id,device_id,challenge,expires_at,consumed_at) VALUES(?,?,?,?,?,NULL)",
            (f"chl_{uuid.uuid4().hex}", license_id, device_id, challenge, _iso(now + timedelta(minutes=5))),
        )
        db.commit()
        return jsonify({"ok": True, "challenge": challenge})

    @bp.post("/api/v2/verify")
    def verify_v2():
        if not limited(30):
            return jsonify({"ok": False, "message": "Troppe richieste."}), 429
        body = request.get_json(silent=True) or {}
        license_id = str(body.get("license_id") or "")
        device_id = str(body.get("device_id") or "")
        challenge = str(body.get("challenge") or "")
        signature = str(body.get("signature") or "")
        if any(len(value) > 256 for value in (license_id, device_id, challenge, signature)):
            return jsonify({"ok": False, "message": GENERIC_INVALID}), 400
        db = get_db()
        db.execute("BEGIN IMMEDIATE")
        try:
            challenge_row = db.execute(
                "SELECT * FROM challenges_v2 WHERE license_id=? AND device_id=? "
                "AND challenge=? AND consumed_at IS NULL",
                (license_id, device_id, challenge),
            ).fetchone()
            if not challenge_row or datetime.fromisoformat(
                challenge_row["expires_at"].replace("Z", "+00:00")
            ).astimezone(timezone.utc) <= _now():
                db.rollback()
                return jsonify({"ok": False, "message": GENERIC_INVALID}), 403
            lic = _valid_license(db, license_id)
            device = db.execute(
                "SELECT * FROM devices_v2 WHERE id=? AND license_id=? AND revoked=0",
                (device_id, license_id),
            ).fetchone()
            if not lic or not device:
                db.rollback()
                return jsonify({"ok": False, "message": GENERIC_INVALID}), 403
            try:
                verify_challenge_signature(
                    device["public_key"], signature, license_id, device_id, challenge
                )
            except LicenseProtocolError:
                db.rollback()
                return jsonify({"ok": False, "message": GENERIC_INVALID}), 403
            now = _iso(_now())
            db.execute(
                "UPDATE challenges_v2 SET consumed_at=? WHERE id=?",
                (now, challenge_row["id"]),
            )
            db.execute("UPDATE devices_v2 SET last_seen=? WHERE id=?", (now, device_id))
            _audit(db, "lease_refreshed", license_id, device_id)
            lease = _issue_lease(db, lic, device)
            db.commit()
            return jsonify({"ok": True, "lease": lease})
        except Exception:
            db.rollback()
            raise

    return bp
