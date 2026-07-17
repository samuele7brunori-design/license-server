"""Cryptographic protocol primitives shared by TapeSense and its license server.

The module intentionally contains no private key or deployment configuration.
It implements a fixed-algorithm signed envelope using Ed25519 and a
domain-separated challenge signature.  Callers are responsible for obtaining
private keys from a secret manager and for pinning trusted public keys.
"""
from __future__ import annotations

import base64
import json
import re
from datetime import datetime, timezone
from typing import Any, Mapping

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import (
    Ed25519PrivateKey,
    Ed25519PublicKey,
)


LEASE_DOMAIN = b"TAPESENSE-LICENSE-LEASE-V2\0"
CHALLENGE_DOMAIN = b"TAPESENSE-LICENSE-CHALLENGE-V2\0"
RELEASE_DOMAIN = b"TAPESENSE-RELEASE-MANIFEST-V2\0"
MAX_TOKEN_BYTES = 16 * 1024
REQUIRED_LEASE_CLAIMS = {
    "protocol_version",
    "audience",
    "license_id",
    "device_id",
    "device_public_key_sha256",
    "plan",
    "issued_at",
    "refresh_after",
    "lease_expires_at",
    "token_id",
}
REQUIRED_RELEASE_CLAIMS = {
    "protocol_version",
    "audience",
    "version",
    "filename",
    "size",
    "sha256",
    "issued_at",
    "manifest_expires_at",
    "notes",
}


class LicenseProtocolError(ValueError):
    """Raised when a license message is malformed, untrusted, or expired."""


def _b64url_encode(value: bytes) -> str:
    return base64.urlsafe_b64encode(value).rstrip(b"=").decode("ascii")


def _b64url_decode(value: str) -> bytes:
    if not isinstance(value, str) or not value:
        raise LicenseProtocolError("Valore base64url mancante")
    if not re.fullmatch(r"[A-Za-z0-9_-]+", value):
        raise LicenseProtocolError("Valore base64url non valido")
    try:
        encoded = value.encode("ascii")
        decoded = base64.urlsafe_b64decode(encoded + b"=" * (-len(encoded) % 4))
        if _b64url_encode(decoded) != value:
            raise LicenseProtocolError("Valore base64url non canonico")
        return decoded
    except Exception as exc:
        raise LicenseProtocolError("Valore base64url non valido") from exc


def canonical_json(value: Any) -> bytes:
    """Return deterministic UTF-8 JSON suitable for signing."""
    try:
        return json.dumps(
            value,
            ensure_ascii=False,
            allow_nan=False,
            separators=(",", ":"),
            sort_keys=True,
        ).encode("utf-8")
    except (TypeError, ValueError) as exc:
        raise LicenseProtocolError("Contenuto JSON non serializzabile") from exc


def _parse_timestamp(value: Any, claim: str) -> datetime:
    if not isinstance(value, str) or not value:
        raise LicenseProtocolError(f"Claim temporale mancante: {claim}")
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise LicenseProtocolError(f"Claim temporale non valido: {claim}") from exc
    if parsed.tzinfo is None:
        raise LicenseProtocolError(f"Claim temporale senza timezone: {claim}")
    return parsed.astimezone(timezone.utc)


def private_key_from_b64(value: str) -> Ed25519PrivateKey:
    raw = _b64url_decode(value)
    if len(raw) != 32:
        raise LicenseProtocolError("Chiave privata Ed25519 non valida")
    return Ed25519PrivateKey.from_private_bytes(raw)


def public_key_from_b64(value: str) -> Ed25519PublicKey:
    raw = _b64url_decode(value)
    if len(raw) != 32:
        raise LicenseProtocolError("Chiave pubblica Ed25519 non valida")
    return Ed25519PublicKey.from_public_bytes(raw)


def private_key_to_b64(key: Ed25519PrivateKey) -> str:
    return _b64url_encode(
        key.private_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PrivateFormat.Raw,
            encryption_algorithm=serialization.NoEncryption(),
        )
    )


def public_key_to_b64(key: Ed25519PublicKey) -> str:
    return _b64url_encode(
        key.public_bytes(
            encoding=serialization.Encoding.Raw,
            format=serialization.PublicFormat.Raw,
        )
    )


def public_key_from_private_b64(private_key_b64: str) -> str:
    """Derive the distributable public key from a private signing key."""
    return public_key_to_b64(private_key_from_b64(private_key_b64).public_key())


def generate_device_keypair() -> tuple[str, str]:
    private_key = Ed25519PrivateKey.generate()
    return private_key_to_b64(private_key), public_key_to_b64(private_key.public_key())


def public_key_sha256(public_key_b64: str) -> str:
    import hashlib

    return hashlib.sha256(_b64url_decode(public_key_b64)).hexdigest()


def sign_lease(payload: Mapping[str, Any], private_key_b64: str, key_id: str) -> str:
    if not key_id or len(key_id) > 128:
        raise LicenseProtocolError("Identificatore chiave di firma non valido")
    body = {"key_id": key_id, "payload": dict(payload)}
    signed = LEASE_DOMAIN + canonical_json(body)
    signature = private_key_from_b64(private_key_b64).sign(signed)
    envelope = {**body, "signature": _b64url_encode(signature)}
    token = _b64url_encode(canonical_json(envelope))
    if len(token.encode("ascii")) > MAX_TOKEN_BYTES:
        raise LicenseProtocolError("Lease troppo grande")
    return token


def sign_release_manifest(
    payload: Mapping[str, Any], private_key_b64: str, key_id: str
) -> str:
    if not key_id or len(key_id) > 128:
        raise LicenseProtocolError("Identificatore chiave di firma non valido")
    body = {"key_id": key_id, "payload": dict(payload)}
    signature = private_key_from_b64(private_key_b64).sign(
        RELEASE_DOMAIN + canonical_json(body)
    )
    token = _b64url_encode(canonical_json({**body, "signature": _b64url_encode(signature)}))
    if len(token.encode("ascii")) > MAX_TOKEN_BYTES:
        raise LicenseProtocolError("Manifest troppo grande")
    return token


def decode_and_verify_release_manifest(
    token: str,
    trusted_public_keys: Mapping[str, str],
    *,
    now: datetime | None = None,
) -> dict[str, Any]:
    if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise LicenseProtocolError("Manifest assente o troppo grande")
    try:
        envelope = json.loads(_b64url_decode(token).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LicenseProtocolError("Manifest non decodificabile") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"key_id", "payload", "signature"}:
        raise LicenseProtocolError("Struttura manifest non valida")
    key_id, payload = envelope["key_id"], envelope["payload"]
    if not isinstance(key_id, str) or not isinstance(payload, dict):
        raise LicenseProtocolError("Struttura manifest non valida")
    public_key = trusted_public_keys.get(key_id)
    if not public_key:
        raise LicenseProtocolError("Chiave firma manifest non attendibile")
    body = {"key_id": key_id, "payload": payload}
    try:
        public_key_from_b64(public_key).verify(
            _b64url_decode(envelope["signature"]),
            RELEASE_DOMAIN + canonical_json(body),
        )
    except (InvalidSignature, LicenseProtocolError) as exc:
        raise LicenseProtocolError("Firma manifest non valida") from exc
    missing = REQUIRED_RELEASE_CLAIMS.difference(payload)
    if missing:
        raise LicenseProtocolError("Claim manifest mancanti")
    if payload.get("protocol_version") != 2 or payload.get("audience") != "tapesense-update":
        raise LicenseProtocolError("Protocollo manifest non valido")
    if (
        not isinstance(payload.get("sha256"), str)
        or len(payload["sha256"]) != 64
        or any(c not in "0123456789abcdef" for c in payload["sha256"].lower())
        or not isinstance(payload.get("size"), int)
        or payload["size"] < 1
        or not isinstance(payload.get("filename"), str)
        or len(payload["filename"]) > 255
        or _filename_is_unsafe(payload["filename"])
        or not isinstance(payload.get("version"), str)
        or not re.fullmatch(r"[0-9]+(?:\.[0-9]+){1,3}", payload["version"])
        or not isinstance(payload.get("notes"), str)
        or len(payload["notes"]) > 10_000
    ):
        raise LicenseProtocolError("Metadati manifest non validi")
    issued = _parse_timestamp(payload["issued_at"], "issued_at")
    expires = _parse_timestamp(payload["manifest_expires_at"], "manifest_expires_at")
    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if expires <= issued or expires <= reference or (issued - reference).total_seconds() > 300:
        raise LicenseProtocolError("Validità temporale manifest non valida")
    return dict(payload)


def _filename_is_unsafe(filename: str) -> bool:
    """Reject paths; release manifests carry a plain filename only."""
    return filename in {"", ".", ".."} or "/" in filename or "\\" in filename


def decode_and_verify_lease(
    token: str,
    trusted_public_keys: Mapping[str, str],
    *,
    now: datetime | None = None,
    require_fresh: bool = True,
) -> dict[str, Any]:
    if not isinstance(token, str) or len(token.encode("utf-8")) > MAX_TOKEN_BYTES:
        raise LicenseProtocolError("Lease assente o troppo grande")
    try:
        envelope = json.loads(_b64url_decode(token).decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise LicenseProtocolError("Lease non decodificabile") from exc
    if not isinstance(envelope, dict) or set(envelope) != {"key_id", "payload", "signature"}:
        raise LicenseProtocolError("Struttura lease non valida")
    key_id = envelope["key_id"]
    payload = envelope["payload"]
    if not isinstance(key_id, str) or not isinstance(payload, dict):
        raise LicenseProtocolError("Struttura lease non valida")
    public_key_b64 = trusted_public_keys.get(key_id)
    if not public_key_b64:
        raise LicenseProtocolError("Chiave di firma lease non attendibile")
    body = {"key_id": key_id, "payload": payload}
    try:
        public_key_from_b64(public_key_b64).verify(
            _b64url_decode(envelope["signature"]),
            LEASE_DOMAIN + canonical_json(body),
        )
    except (InvalidSignature, LicenseProtocolError) as exc:
        raise LicenseProtocolError("Firma lease non valida") from exc

    missing = REQUIRED_LEASE_CLAIMS.difference(payload)
    if missing:
        raise LicenseProtocolError(f"Claim lease mancanti: {', '.join(sorted(missing))}")
    if payload.get("protocol_version") != 2 or payload.get("audience") != "tapesense-desktop":
        raise LicenseProtocolError("Protocollo o audience lease non validi")
    issued = _parse_timestamp(payload["issued_at"], "issued_at")
    refresh = _parse_timestamp(payload["refresh_after"], "refresh_after")
    expires = _parse_timestamp(payload["lease_expires_at"], "lease_expires_at")
    if not issued <= refresh <= expires:
        raise LicenseProtocolError("Intervalli temporali lease incoerenti")
    reference = (now or datetime.now(timezone.utc)).astimezone(timezone.utc)
    if (issued - reference).total_seconds() > 300:
        raise LicenseProtocolError("Lease emesso nel futuro")
    if require_fresh and expires <= reference:
        raise LicenseProtocolError("Lease scaduto")
    return dict(payload)


def challenge_message(license_id: str, device_id: str, challenge: str) -> bytes:
    fields = {
        "license_id": license_id,
        "device_id": device_id,
        "challenge": challenge,
    }
    if not all(isinstance(value, str) and value for value in fields.values()):
        raise LicenseProtocolError("Campi challenge mancanti")
    return CHALLENGE_DOMAIN + canonical_json(fields)


def sign_challenge(
    private_key_b64: str,
    license_id: str,
    device_id: str,
    challenge: str,
) -> str:
    signature = private_key_from_b64(private_key_b64).sign(
        challenge_message(license_id, device_id, challenge)
    )
    return _b64url_encode(signature)


def verify_challenge_signature(
    public_key_b64: str,
    signature_b64: str,
    license_id: str,
    device_id: str,
    challenge: str,
) -> None:
    try:
        public_key_from_b64(public_key_b64).verify(
            _b64url_decode(signature_b64),
            challenge_message(license_id, device_id, challenge),
        )
    except (InvalidSignature, LicenseProtocolError) as exc:
        raise LicenseProtocolError("Firma challenge non valida") from exc
