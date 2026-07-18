"""
license_server/server.py

Flask license server for TapeSense Trading Journal.
Deploys on a Hetzner VPS (Ubuntu).

Environment variables:
  ADMIN_USER       — HTTP Basic Auth username for /admin/
  ADMIN_PASSWORD   — HTTP Basic Auth password for /admin/
  PORT             — TCP port (default: 5001)

Database: license_server/licenses.db (SQLite, auto-created)
Uploads:  license_server/uploads/  (exe files)
"""

import os
import io
import csv
import json
import time
import secrets
import sqlite3
import hashlib
import functools
import string
from collections import defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path

from flask import (
    Flask, request, jsonify, redirect, url_for,
    send_file, Response, g,
)
from license_protocol import sign_release_manifest
from license_server.db import connect_database, is_postgres

# ---------------------------------------------------------------------------
# App setup
# ---------------------------------------------------------------------------

app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = 256 * 1024

if os.environ.get("TRUST_PROXY_HEADERS", "0") == "1":
    from werkzeug.middleware.proxy_fix import ProxyFix
    app.wsgi_app = ProxyFix(app.wsgi_app, x_for=1, x_proto=1, x_host=1)

BASE_DIR    = Path(__file__).parent
DB_PATH     = Path(os.environ.get("LICENSE_DB_PATH", str(BASE_DIR / "licenses.db")))
UPLOADS_DIR = Path(os.environ.get("LICENSE_UPLOADS_DIR", str(BASE_DIR / "uploads")))
UPLOADS_DIR.mkdir(parents=True, exist_ok=True)


def _safe_upload_path(filename: str) -> Path | None:
    """Resolve only regular files directly inside the configured upload dir."""
    if not isinstance(filename, str) or not filename or len(filename) > 255:
        return None
    root = UPLOADS_DIR.resolve()
    candidate = (root / filename).resolve()
    if candidate.parent != root or candidate.name != filename:
        return None
    return candidate

try:
    from license_server.license_v2 import create_blueprint as _create_v2_blueprint
    from license_server.license_v2 import init_schema as _init_v2_schema
    from license_server.license_v2 import authenticate_bearer_lease as _authenticate_v2
    from license_server.license_v2 import pepper_fingerprint as _pepper_fingerprint
except ImportError:  # deployed files live side-by-side under /opt/license_server
    from license_v2 import create_blueprint as _create_v2_blueprint
    from license_v2 import init_schema as _init_v2_schema
    from license_v2 import authenticate_bearer_lease as _authenticate_v2
    from license_v2 import pepper_fingerprint as _pepper_fingerprint


# ---------------------------------------------------------------------------
# Database helpers
# ---------------------------------------------------------------------------

def _get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = connect_database(os.environ.get("DATABASE_URL"), str(DB_PATH))
        if not is_postgres(g.db):
            g.db.execute("PRAGMA journal_mode=WAL")
            g.db.execute("PRAGMA foreign_keys=ON")
    return g.db


@app.teardown_appcontext
def _close_db(exc=None):
    db = g.pop("db", None)
    if db is not None:
        db.close()


def _init_db():
    """Create tables and initial config rows on first run."""
    if os.environ.get("DATABASE_URL"):
        conn = connect_database(os.environ["DATABASE_URL"], str(DB_PATH))
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS licenses (
                key TEXT PRIMARY KEY,
                plan TEXT DEFAULT 'lifetime',
                expires_at TEXT,
                max_machines INTEGER DEFAULT 2,
                notes TEXT,
                created_at TEXT NOT NULL,
                active INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS activations (
                license_key TEXT NOT NULL REFERENCES licenses(key),
                machine_id TEXT NOT NULL,
                activated_at TEXT NOT NULL,
                last_seen TEXT NOT NULL,
                PRIMARY KEY (license_key, machine_id)
            );
            CREATE TABLE IF NOT EXISTS app_config (
                key TEXT PRIMARY KEY,
                value TEXT
            )
            """
        )
        for key, value in (
            ("current_version", "1.1.0"),
            ("version_notes", ""),
            ("exe_filename", "TapeSense.exe"),
        ):
            conn.execute(
                "INSERT INTO app_config(key,value) VALUES(?,?) "
                "ON CONFLICT (key) DO NOTHING",
                (key, value),
            )
        _init_v2_schema(conn)
        conn.commit()
        conn.close()
        return
    conn = sqlite3.connect(str(DB_PATH))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS licenses (
            key         TEXT PRIMARY KEY,
            plan        TEXT DEFAULT 'lifetime',
            expires_at  TEXT,
            max_machines INTEGER DEFAULT 2,
            notes       TEXT,
            created_at  TEXT NOT NULL,
            active      INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS activations (
            license_key  TEXT NOT NULL,
            machine_id   TEXT NOT NULL,
            activated_at TEXT NOT NULL,
            last_seen    TEXT NOT NULL,
            PRIMARY KEY (license_key, machine_id),
            FOREIGN KEY (license_key) REFERENCES licenses(key)
        );

        CREATE TABLE IF NOT EXISTS app_config (
            key   TEXT PRIMARY KEY,
            value TEXT
        );
    """)
    conn.execute("INSERT OR IGNORE INTO app_config(key,value) VALUES('current_version','1.1.0')")
    conn.execute("INSERT OR IGNORE INTO app_config(key,value) VALUES('version_notes','')")
    conn.execute("INSERT OR IGNORE INTO app_config(key,value) VALUES('exe_filename','TapeSense.exe')")
    _init_v2_schema(conn)
    conn.commit()
    conn.close()


# ---------------------------------------------------------------------------
# Rate limiting
# ---------------------------------------------------------------------------

_rate_cache: dict = defaultdict(list)
_MAX_RATE_KEYS = 10_000


def _check_rate(ip: str, limit: int = 10, window: int = 60) -> bool:
    """Returns True if allowed, False if rate limited."""
    if ip not in _rate_cache and len(_rate_cache) >= _MAX_RATE_KEYS:
        _rate_cache.clear()
    now = time.time()
    _rate_cache[ip] = [t for t in _rate_cache[ip] if now - t < window]
    if len(_rate_cache[ip]) >= limit:
        return False
    _rate_cache[ip].append(now)
    return True


app.register_blueprint(_create_v2_blueprint(_get_db, _check_rate))


@app.get("/health")
def health():
    try:
        _get_db().execute("SELECT 1").fetchone()
        fingerprint = _pepper_fingerprint(
            os.environ.get("LICENSE_KEY_PEPPER", "").strip()
        )
        return jsonify({
            "ok": True,
            "protocol": 2,
            "service": "tapesense-licensing",
            "pepper_fingerprint": fingerprint,
        })
    except Exception:
        return jsonify({"ok": False}), 503


# ---------------------------------------------------------------------------
# License key generator
# ---------------------------------------------------------------------------

_KEY_CHARS = string.ascii_uppercase + string.digits

def _generate_key() -> str:
    """Generate TAPE-XXXX-XXXX-XXXX-XXXX (uppercase alphanumeric)."""
    parts = ["".join(secrets.choice(_KEY_CHARS) for _ in range(4)) for _ in range(4)]
    return "TAPE-" + "-".join(parts)


# ---------------------------------------------------------------------------
# Utility
# ---------------------------------------------------------------------------

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _get_config(key: str) -> str:
    db = _get_db()
    row = db.execute("SELECT value FROM app_config WHERE key=?", (key,)).fetchone()
    return row["value"] if row else ""


def _set_config(key: str, value: str):
    _get_db().execute(
        "INSERT INTO app_config(key,value) VALUES(?,?) "
        "ON CONFLICT (key) DO UPDATE SET value=EXCLUDED.value",
        (key, value),
    )
    _get_db().commit()


def _validate_license(key: str, hw_id: str) -> tuple[bool, str, sqlite3.Row | None]:
    """
    Validate key + machine_id combo.
    Returns (is_valid, error_message, license_row).
    """
    db = _get_db()
    lic = db.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
    if not lic:
        return False, "Chiave non trovata.", None
    if not lic["active"]:
        return False, "Licenza revocata.", None
    if lic["expires_at"]:
        exp = datetime.fromisoformat(lic["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            return False, "Licenza scaduta.", None
    act = db.execute(
        "SELECT * FROM activations WHERE license_key=? AND machine_id=?",
        (key, hw_id),
    ).fetchone()
    if not act:
        return False, "Dispositivo non autorizzato per questa licenza.", None
    return True, "", lic


# ---------------------------------------------------------------------------
# Admin auth
# ---------------------------------------------------------------------------

def _require_admin(f):
    @functools.wraps(f)
    def decorated(*args, **kwargs):
        return Response("Pannello legacy disabilitato. Usare la gestione licensing v2.", 410)
        admin_user = os.environ.get("ADMIN_USER", "")
        admin_pass = os.environ.get("ADMIN_PASSWORD", "")
        if not admin_user or not admin_pass:
            return Response("Pannello amministrativo non configurato.", 503)
        auth = request.authorization
        valid = bool(
            auth
            and secrets.compare_digest(auth.username or "", admin_user)
            and secrets.compare_digest(auth.password or "", admin_pass)
        )
        if not valid:
            return Response(
                "Autenticazione richiesta.",
                401,
                {"WWW-Authenticate": 'Basic realm="TapeSense Admin"'},
            )
        return f(*args, **kwargs)
    return decorated


@app.before_request
def _disable_legacy_license_api():
    legacy = {"/api/activate", "/api/verify", "/api/deactivate", "/api/version", "/api/download"}
    if request.path in legacy:
        return jsonify({"ok": False, "message": "Protocollo licensing obsoleto."}), 410


@app.after_request
def _security_headers(response):
    response.headers.setdefault("X-Content-Type-Options", "nosniff")
    response.headers.setdefault("X-Frame-Options", "DENY")
    response.headers.setdefault("Referrer-Policy", "no-referrer")
    response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
    response.headers.setdefault(
        "Content-Security-Policy",
        "default-src 'self'; style-src 'self' 'unsafe-inline'; "
        "script-src 'self' 'unsafe-inline'; frame-ancestors 'none'; base-uri 'none'",
    )
    if request.is_secure:
        response.headers.setdefault("Strict-Transport-Security", "max-age=31536000")
    return response


# ---------------------------------------------------------------------------
# API: /api/activate
# ---------------------------------------------------------------------------

@app.post("/api/activate")
def api_activate():
    ip = request.remote_addr
    if not _check_rate(ip):
        return jsonify({"ok": False, "message": "Troppe richieste. Riprova tra un minuto."}), 429

    body = request.get_json(silent=True) or {}
    key    = (body.get("key") or "").strip()
    hw_id  = (body.get("hardware_id") or "").strip()

    if not key or not hw_id:
        return jsonify({"ok": False, "message": "Parametri mancanti."}), 400

    db = _get_db()
    lic = db.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
    if not lic:
        return jsonify({"ok": False, "message": "Chiave non trovata."})
    if not lic["active"]:
        return jsonify({"ok": False, "message": "Licenza revocata."})

    if lic["expires_at"]:
        exp = datetime.fromisoformat(lic["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            return jsonify({"ok": False, "message": "Licenza scaduta."})

    # Check if machine already activated
    existing = db.execute(
        "SELECT * FROM activations WHERE license_key=? AND machine_id=?",
        (key, hw_id),
    ).fetchone()

    now = _now_iso()

    if existing:
        db.execute(
            "UPDATE activations SET last_seen=? WHERE license_key=? AND machine_id=?",
            (now, key, hw_id),
        )
        db.commit()
    else:
        # Count active activations
        count = db.execute(
            "SELECT COUNT(*) FROM activations WHERE license_key=?", (key,)
        ).fetchone()[0]
        if count >= lic["max_machines"]:
            return jsonify({
                "ok": False,
                "message": (
                    f"Limite macchine raggiunto (max {lic['max_machines']}). "
                    "Disattiva un dispositivo precedente."
                ),
            })
        db.execute(
            "INSERT INTO activations(license_key,machine_id,activated_at,last_seen) VALUES(?,?,?,?)",
            (key, hw_id, now, now),
        )
        db.commit()

    # Compute expires_at to return
    if lic["plan"] == "lifetime" or not lic["expires_at"]:
        expires_at = "2099-12-31T23:59:59+00:00"
    else:
        expires_at = lic["expires_at"]

    return jsonify({"ok": True, "expires_at": expires_at, "plan": lic["plan"]})


# ---------------------------------------------------------------------------
# API: /api/verify
# ---------------------------------------------------------------------------

@app.post("/api/verify")
def api_verify():
    ip = request.remote_addr
    if not _check_rate(ip):
        return jsonify({"ok": False, "message": "Troppe richieste. Riprova tra un minuto."}), 429

    body  = request.get_json(silent=True) or {}
    key   = (body.get("key") or "").strip()
    hw_id = (body.get("hardware_id") or "").strip()

    if not key or not hw_id:
        return jsonify({"ok": False, "message": "Parametri mancanti."}), 400

    db = _get_db()
    lic = db.execute("SELECT * FROM licenses WHERE key=?", (key,)).fetchone()
    if not lic:
        return jsonify({"ok": False, "message": "Chiave non trovata."})
    if not lic["active"]:
        return jsonify({"ok": False, "message": "Licenza revocata."})

    if lic["expires_at"]:
        exp = datetime.fromisoformat(lic["expires_at"])
        if exp.tzinfo is None:
            exp = exp.replace(tzinfo=timezone.utc)
        if exp < datetime.now(timezone.utc):
            return jsonify({"ok": False, "message": "Licenza scaduta."})

    act = db.execute(
        "SELECT * FROM activations WHERE license_key=? AND machine_id=?",
        (key, hw_id),
    ).fetchone()
    if not act:
        return jsonify({"ok": False, "message": "Dispositivo non autorizzato per questa licenza."})

    now = _now_iso()
    db.execute(
        "UPDATE activations SET last_seen=? WHERE license_key=? AND machine_id=?",
        (now, key, hw_id),
    )
    db.commit()

    if lic["plan"] == "lifetime" or not lic["expires_at"]:
        expires_at = "2099-12-31T23:59:59+00:00"
    else:
        expires_at = lic["expires_at"]

    return jsonify({"ok": True, "expires_at": expires_at})


# ---------------------------------------------------------------------------
# API: /api/deactivate
# ---------------------------------------------------------------------------

@app.post("/api/deactivate")
def api_deactivate():
    body  = request.get_json(silent=True) or {}
    key   = (body.get("key") or "").strip()
    hw_id = (body.get("hardware_id") or "").strip()

    if not key or not hw_id:
        return jsonify({"ok": False, "message": "Parametri mancanti."}), 400

    _get_db().execute(
        "DELETE FROM activations WHERE license_key=? AND machine_id=?",
        (key, hw_id),
    )
    _get_db().commit()
    return jsonify({"ok": True})


# ---------------------------------------------------------------------------
# API: /api/version
# ---------------------------------------------------------------------------

def _v2_authorized():
    try:
        return _authenticate_v2(_get_db(), request.headers.get("Authorization", ""))
    except Exception:
        return None


@app.get("/api/v2/version")
def api_version_v2():
    if not _v2_authorized():
        return jsonify({"ok": False, "message": "Licenza o dispositivo non validi."}), 403
    version = _get_config("current_version")
    notes = _get_config("version_notes")
    exe_name = _get_config("exe_filename") or "TapeSense.exe"
    exe_path = _safe_upload_path(exe_name)
    if exe_path is None:
        return jsonify({"ok": False, "message": "File release non valido."}), 503
    if not exe_path.is_file():
        return jsonify({"version": version, "notes": notes, "download_available": False})
    digest = hashlib.sha256()
    with exe_path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    issued = datetime.now(timezone.utc)
    manifest = sign_release_manifest({
        "protocol_version": 2,
        "audience": "tapesense-update",
        "version": version,
        "filename": exe_name,
        "size": exe_path.stat().st_size,
        "sha256": digest.hexdigest(),
        "issued_at": issued.isoformat(),
        "manifest_expires_at": (issued + timedelta(hours=1)).isoformat(),
        "notes": notes,
    }, os.environ["LICENSE_SIGNING_PRIVATE_KEY_B64"], os.environ["LICENSE_SIGNING_KEY_ID"])
    return jsonify({
        "version": version,
        "download_available": True,
        "manifest": manifest,
    })


@app.get("/api/v2/download")
def api_download_v2():
    if not _v2_authorized():
        return jsonify({"ok": False, "message": "Licenza o dispositivo non validi."}), 403
    exe_name = _get_config("exe_filename") or "TapeSense.exe"
    exe_path = _safe_upload_path(exe_name)
    if exe_path is None or not exe_path.is_file():
        return jsonify({"ok": False, "message": "File non disponibile sul server."}), 404
    return send_file(
        str(exe_path),
        as_attachment=True,
        download_name=exe_name,
        mimetype="application/octet-stream",
    )

@app.get("/api/version")
def api_version():
    key   = request.headers.get("X-License-Key", "").strip()
    hw_id = request.headers.get("X-Machine-Id", "").strip()

    if not key or not hw_id:
        return jsonify({"ok": False, "message": "Headers mancanti."}), 400

    valid, err, _ = _validate_license(key, hw_id)
    if not valid:
        return jsonify({"ok": False, "message": err}), 403

    version   = _get_config("current_version")
    notes     = _get_config("version_notes")
    exe_name  = _get_config("exe_filename") or "TapeSense.exe"
    exe_path  = _safe_upload_path(exe_name)
    if exe_path is None:
        return jsonify({"ok": False, "message": "File release non valido."}), 503
    available = exe_path.exists()

    return jsonify({
        "version":            version,
        "notes":              notes,
        "download_available": available,
    })


# ---------------------------------------------------------------------------
# API: /api/download
# ---------------------------------------------------------------------------

@app.get("/api/download")
def api_download():
    key   = (request.args.get("key") or "").strip()
    hw_id = (request.args.get("mid") or "").strip()

    if not key or not hw_id:
        return jsonify({"ok": False, "message": "Parametri mancanti."}), 400

    valid, err, _ = _validate_license(key, hw_id)
    if not valid:
        return jsonify({"ok": False, "message": err}), 403

    exe_name = _get_config("exe_filename") or "TapeSense.exe"
    exe_path = _safe_upload_path(exe_name)
    if exe_path is None or not exe_path.exists():
        return jsonify({"ok": False, "message": "File non disponibile sul server."}), 404

    return send_file(
        str(exe_path),
        as_attachment=True,
        download_name=exe_name,
        mimetype="application/octet-stream",
    )


# ---------------------------------------------------------------------------
# Admin: HTML helpers
# ---------------------------------------------------------------------------

_ADMIN_CSS = """
<style>
  *, *::before, *::after { box-sizing: border-box; margin: 0; padding: 0; }
  body { background: #0f1117; color: #c9d1d9; font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; font-size: 14px; }
  a { color: #58a6ff; text-decoration: none; }
  a:hover { text-decoration: underline; }
  .container { max-width: 1200px; margin: 0 auto; padding: 24px 16px; }
  h1 { font-size: 22px; font-weight: 600; margin-bottom: 4px; }
  h2 { font-size: 16px; font-weight: 600; margin: 24px 0 12px; color: #e6edf3; }
  .subtitle { color: #8b949e; font-size: 13px; margin-bottom: 24px; }
  .stats { display: flex; gap: 16px; margin-bottom: 24px; flex-wrap: wrap; }
  .stat { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 16px 24px; flex: 1; min-width: 120px; }
  .stat .num { font-size: 28px; font-weight: 700; color: #e6edf3; }
  .stat .lbl { font-size: 12px; color: #8b949e; margin-top: 2px; }
  table { width: 100%; border-collapse: collapse; background: #161b22; border: 1px solid #30363d; border-radius: 8px; overflow: hidden; }
  th { background: #21262d; color: #8b949e; font-size: 11px; text-transform: uppercase; letter-spacing: .05em; padding: 10px 14px; text-align: left; border-bottom: 1px solid #30363d; }
  td { padding: 10px 14px; border-bottom: 1px solid #21262d; vertical-align: middle; }
  tr:last-child td { border-bottom: none; }
  tr:hover td { background: #1c2128; }
  .mono { font-family: 'JetBrains Mono', 'Courier New', monospace; font-size: 12px; color: #e6edf3; cursor: pointer; }
  .mono:hover { color: #58a6ff; }
  .badge { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; }
  .badge-lifetime { background: #0d419d; color: #58a6ff; }
  .badge-yearly   { background: #1f4e2e; color: #3fb950; }
  .badge-monthly  { background: #4a2317; color: #f0883e; }
  .badge-unknown  { background: #2d333b; color: #8b949e; }
  .pill { display: inline-block; padding: 2px 8px; border-radius: 20px; font-size: 11px; font-weight: 600; }
  .pill-active  { background: #1f4e2e; color: #3fb950; }
  .pill-revoked { background: #4a1515; color: #f85149; }
  btn, .btn { display: inline-block; padding: 4px 12px; border: none; border-radius: 6px; cursor: pointer; font-size: 12px; font-weight: 500; text-decoration: none; }
  .btn-danger  { background: #4a1515; color: #f85149; }
  .btn-danger:hover  { background: #5a1a1a; }
  .btn-success { background: #1f4e2e; color: #3fb950; }
  .btn-success:hover { background: #265836; }
  .btn-primary { background: #0d419d; color: #58a6ff; }
  .btn-primary:hover { background: #1158cc; }
  .btn-secondary { background: #21262d; color: #c9d1d9; border: 1px solid #30363d; }
  .btn-secondary:hover { background: #2d333b; }
  .card { background: #161b22; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin-bottom: 20px; }
  .form-row { display: flex; gap: 12px; flex-wrap: wrap; align-items: flex-end; }
  .form-group { display: flex; flex-direction: column; gap: 4px; }
  .form-group label { font-size: 12px; color: #8b949e; }
  input, select { background: #0d1117; border: 1px solid #30363d; border-radius: 6px; color: #e6edf3; padding: 6px 10px; font-size: 13px; outline: none; }
  input:focus, select:focus { border-color: #388bfd; }
  .msg { padding: 10px 14px; border-radius: 6px; margin-bottom: 16px; font-size: 13px; }
  .msg-ok  { background: #1f4e2e; color: #3fb950; border: 1px solid #2ea043; }
  .msg-err { background: #4a1515; color: #f85149; border: 1px solid #da3633; }
  .actions { display: flex; gap: 6px; }
  .notes-cell { max-width: 160px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; color: #8b949e; font-size: 12px; }
  .top-bar { display: flex; justify-content: space-between; align-items: center; margin-bottom: 20px; }
  .top-bar-links { display: flex; gap: 12px; }
</style>
"""

_COPY_SCRIPT = """
<script>
function copyKey(el) {
  const txt = el.innerText;
  navigator.clipboard.writeText(txt).then(() => {
    el.style.color = '#3fb950';
    setTimeout(() => el.style.color = '', 1000);
  });
}
</script>
"""


def _plan_badge(plan: str) -> str:
    cls = {
        "lifetime": "badge-lifetime",
        "yearly":   "badge-yearly",
        "monthly":  "badge-monthly",
    }.get(plan, "badge-unknown")
    return f'<span class="badge {cls}">{plan}</span>'


def _status_pill(active: int) -> str:
    if active:
        return '<span class="pill pill-active">Attiva</span>'
    return '<span class="pill pill-revoked">Revocata</span>'


def _expires_display(expires_at: str | None, plan: str) -> str:
    if plan == "lifetime" or not expires_at:
        return '<span style="color:#8b949e">Mai</span>'
    return expires_at[:10]


def _flash_html(msg: str, kind: str = "ok") -> str:
    if not msg:
        return ""
    cls = "msg-ok" if kind == "ok" else "msg-err"
    return f'<div class="msg {cls}">{msg}</div>'


# ---------------------------------------------------------------------------
# Admin: /admin/
# ---------------------------------------------------------------------------

@app.get("/admin/")
@_require_admin
def admin_dashboard():
    msg      = request.args.get("msg", "")
    msg_kind = request.args.get("kind", "ok")
    db = _get_db()

    total   = db.execute("SELECT COUNT(*) FROM licenses").fetchone()[0]
    active  = db.execute("SELECT COUNT(*) FROM licenses WHERE active=1").fetchone()[0]
    revoked = total - active

    licenses = db.execute(
        "SELECT l.*, "
        "(SELECT COUNT(*) FROM activations a WHERE a.license_key=l.key) AS machines_used "
        "FROM licenses l ORDER BY l.created_at DESC"
    ).fetchall()

    rows_html = ""
    for lic in licenses:
        key  = lic["key"]
        used = lic["machines_used"]
        maxi = lic["max_machines"]
        rows_html += f"""
        <tr>
          <td><span class="mono" onclick="copyKey(this)" title="Clicca per copiare">{key}</span></td>
          <td>{_plan_badge(lic['plan'])}</td>
          <td>{_expires_display(lic['expires_at'], lic['plan'])}</td>
          <td style="color:#c9d1d9">{lic['notes'] or ''}</td>
          <td style="color:#c9d1d9">{used}/{maxi}</td>
          <td>{_status_pill(lic['active'])}</td>
          <td>
            <div class="actions">
              {"" if not lic['active'] else f'''
              <form method="post" action="/admin/license/revoke" style="display:inline">
                <input type="hidden" name="key" value="{key}">
                <button class="btn btn-danger" onclick="return confirm('Revocare {key}?')">Revoca</button>
              </form>'''}
              {"" if lic['active'] else f'''
              <form method="post" action="/admin/license/restore" style="display:inline">
                <input type="hidden" name="key" value="{key}">
                <button class="btn btn-success">Ripristina</button>
              </form>'''}
              <form method="post" action="/admin/license/extend" style="display:inline">
                <input type="hidden" name="key" value="{key}">
                <input type="date" name="new_expires_at" style="width:130px">
                <button class="btn btn-primary">Estendi</button>
              </form>
            </div>
          </td>
        </tr>
        """

    version = _get_config("current_version")
    version_notes = _get_config("version_notes")
    exe_name = _get_config("exe_filename") or "TapeSense.exe"
    exe_exists = (UPLOADS_DIR / exe_name).exists()
    exe_status = f'<span style="color:#3fb950">Disponibile ({exe_name})</span>' if exe_exists else '<span style="color:#8b949e">Non caricato</span>'

    html = f"""<!DOCTYPE html>
<html lang="it">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>TapeSense — Admin Panel</title>
  {_ADMIN_CSS}
  {_COPY_SCRIPT}
</head>
<body>
<div class="container">
  <div class="top-bar">
    <div>
      <h1>TapeSense — License Admin</h1>
      <p class="subtitle">Pannello di amministrazione licenze</p>
    </div>
    <div class="top-bar-links">
      <a class="btn btn-secondary" href="/admin/licenses/export">Esporta CSV</a>
    </div>
  </div>

  {_flash_html(msg, msg_kind)}

  <div class="stats">
    <div class="stat"><div class="num">{total}</div><div class="lbl">Totale licenze</div></div>
    <div class="stat"><div class="num" style="color:#3fb950">{active}</div><div class="lbl">Attive</div></div>
    <div class="stat"><div class="num" style="color:#f85149">{revoked}</div><div class="lbl">Revocate</div></div>
  </div>

  <!-- Create license -->
  <div class="card">
    <h2>Nuova licenza</h2>
    <form method="post" action="/admin/license/create">
      <div class="form-row">
        <div class="form-group">
          <label>Piano</label>
          <select name="plan">
            <option value="lifetime">Lifetime</option>
            <option value="yearly">Yearly</option>
            <option value="monthly">Monthly</option>
          </select>
        </div>
        <div class="form-group">
          <label>Scadenza (vuoto = mai)</label>
          <input type="date" name="expires_at">
        </div>
        <div class="form-group">
          <label>Max macchine</label>
          <input type="number" name="max_machines" value="2" min="1" max="10" style="width:80px">
        </div>
        <div class="form-group">
          <label>Note (email / cliente)</label>
          <input type="text" name="notes" placeholder="es. mario.rossi@email.com" style="width:240px">
        </div>
        <div class="form-group">
          <label>&nbsp;</label>
          <button class="btn btn-success" type="submit">Crea licenza</button>
        </div>
      </div>
    </form>
  </div>

  <!-- Version + Exe upload -->
  <div class="card">
    <h2>Versione app &amp; Download</h2>
    <div class="form-row" style="margin-bottom:16px">
      <form method="post" action="/admin/version/update">
        <div class="form-row">
          <div class="form-group">
            <label>Versione corrente</label>
            <input type="text" name="version" value="{version}" style="width:120px">
          </div>
          <div class="form-group">
            <label>Note release</label>
            <input type="text" name="notes" value="{version_notes}" style="width:320px" placeholder="Changelog breve...">
          </div>
          <div class="form-group">
            <label>&nbsp;</label>
            <button class="btn btn-primary" type="submit">Aggiorna</button>
          </div>
        </div>
      </form>
    </div>
    <div class="form-row">
      <form method="post" action="/admin/exe/upload" enctype="multipart/form-data">
        <div class="form-row">
          <div class="form-group">
            <label>Carica nuovo exe — {exe_status}</label>
            <input type="file" name="exe" accept=".exe">
          </div>
          <div class="form-group">
            <label>&nbsp;</label>
            <button class="btn btn-primary" type="submit">Carica</button>
          </div>
        </div>
      </form>
    </div>
  </div>

  <!-- License table -->
  <h2>Licenze ({total})</h2>
  <table>
    <thead>
      <tr>
        <th>Chiave</th>
        <th>Piano</th>
        <th>Scadenza</th>
        <th>Note</th>
        <th>Macchine</th>
        <th>Stato</th>
        <th>Azioni</th>
      </tr>
    </thead>
    <tbody>
      {rows_html if rows_html else '<tr><td colspan="7" style="text-align:center;color:#8b949e;padding:32px">Nessuna licenza ancora creata.</td></tr>'}
    </tbody>
  </table>
</div>
</body>
</html>"""

    return html


# ---------------------------------------------------------------------------
# Admin: license CRUD
# ---------------------------------------------------------------------------

@app.post("/admin/license/create")
@_require_admin
def admin_license_create():
    plan         = request.form.get("plan", "lifetime")
    expires_at   = request.form.get("expires_at", "").strip() or None
    max_machines = int(request.form.get("max_machines", 2))
    notes        = request.form.get("notes", "").strip() or None

    # If expires_at provided, normalise to ISO UTC
    if expires_at:
        try:
            dt = datetime.fromisoformat(expires_at)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            expires_at = dt.isoformat()
        except ValueError:
            return redirect(url_for("admin_dashboard", msg="Data scadenza non valida.", kind="err"))

    key = _generate_key()
    db  = _get_db()
    db.execute(
        "INSERT INTO licenses(key,plan,expires_at,max_machines,notes,created_at,active) VALUES(?,?,?,?,?,?,1)",
        (key, plan, expires_at, max_machines, notes, _now_iso()),
    )
    db.commit()
    return redirect(url_for("admin_dashboard", msg=f"Licenza creata: {key}", kind="ok"))


@app.post("/admin/license/revoke")
@_require_admin
def admin_license_revoke():
    key = request.form.get("key", "").strip()
    if not key:
        return redirect(url_for("admin_dashboard", msg="Chiave mancante.", kind="err"))
    db = _get_db()
    db.execute("UPDATE licenses SET active=0 WHERE key=?", (key,))
    db.commit()
    return redirect(url_for("admin_dashboard", msg=f"Licenza revocata: {key}", kind="ok"))


@app.post("/admin/license/restore")
@_require_admin
def admin_license_restore():
    key = request.form.get("key", "").strip()
    if not key:
        return redirect(url_for("admin_dashboard", msg="Chiave mancante.", kind="err"))
    db = _get_db()
    db.execute("UPDATE licenses SET active=1 WHERE key=?", (key,))
    db.commit()
    return redirect(url_for("admin_dashboard", msg=f"Licenza ripristinata: {key}", kind="ok"))


@app.post("/admin/license/extend")
@_require_admin
def admin_license_extend():
    key          = request.form.get("key", "").strip()
    new_exp_raw  = request.form.get("new_expires_at", "").strip()

    if not key or not new_exp_raw:
        return redirect(url_for("admin_dashboard", msg="Dati mancanti per estensione.", kind="err"))

    try:
        dt = datetime.fromisoformat(new_exp_raw)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        new_exp = dt.isoformat()
    except ValueError:
        return redirect(url_for("admin_dashboard", msg="Data non valida.", kind="err"))

    db = _get_db()
    db.execute("UPDATE licenses SET expires_at=? WHERE key=?", (new_exp, key))
    db.commit()
    return redirect(url_for("admin_dashboard", msg=f"Scadenza aggiornata per {key}", kind="ok"))


# ---------------------------------------------------------------------------
# Admin: version + exe upload
# ---------------------------------------------------------------------------

@app.post("/admin/version/update")
@_require_admin
def admin_version_update():
    version = request.form.get("version", "").strip()
    notes   = request.form.get("notes", "").strip()
    if version:
        _set_config("current_version", version)
    _set_config("version_notes", notes)
    return redirect(url_for("admin_dashboard", msg="Versione aggiornata.", kind="ok"))


@app.post("/admin/exe/upload")
@_require_admin
def admin_exe_upload():
    f = request.files.get("exe")
    if not f or not f.filename:
        return redirect(url_for("admin_dashboard", msg="Nessun file selezionato.", kind="err"))

    exe_name = "TapeSense.exe"
    dest = UPLOADS_DIR / exe_name
    f.save(str(dest))
    _set_config("exe_filename", exe_name)
    size_mb = dest.stat().st_size / (1024 * 1024)
    return redirect(url_for("admin_dashboard", msg=f"Exe caricato ({size_mb:.1f} MB).", kind="ok"))


# ---------------------------------------------------------------------------
# Admin: export CSV
# ---------------------------------------------------------------------------

@app.get("/admin/licenses/export")
@_require_admin
def admin_licenses_export():
    db       = _get_db()
    licenses = db.execute("SELECT * FROM licenses ORDER BY created_at DESC").fetchall()

    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["key", "plan", "expires_at", "max_machines", "notes", "created_at", "active"])
    for lic in licenses:
        writer.writerow([
            lic["key"], lic["plan"], lic["expires_at"] or "",
            lic["max_machines"], lic["notes"] or "",
            lic["created_at"], lic["active"],
        ])

    output.seek(0)
    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="tapesense_licenses_{ts}.csv"'},
    )


# ---------------------------------------------------------------------------
# Startup
# ---------------------------------------------------------------------------

_init_db()

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5001))
    app.run(host="0.0.0.0", port=port)
