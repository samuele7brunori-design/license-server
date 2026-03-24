import os
import secrets
import string
from datetime import datetime, timedelta, timezone
from functools import wraps

from flask import Flask, request, jsonify, render_template_string, Response
from database import (init_db, get_license, insert_license, activate_license,
                      update_last_check, revoke_license, all_licenses, USE_PG)

app = Flask(__name__)
ADMIN_PASSWORD = os.environ.get('ADMIN_PASSWORD', 'changeme')

# ---------------------------------------------------------------------------
# Bootstrap
# ---------------------------------------------------------------------------

init_db()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def now_iso():
    return datetime.now(timezone.utc).strftime('%Y-%m-%dT%H:%M:%SZ')


def check_admin(password: str) -> bool:
    return password == ADMIN_PASSWORD


def require_admin(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        data = request.get_json(silent=True) or {}
        pwd = data.get('password') or request.args.get('password', '')
        if not check_admin(pwd):
            return jsonify({'ok': False, 'message': 'Unauthorized'}), 401
        return f(*args, **kwargs)
    return decorated


def generate_key(prefix: str) -> str:
    chars = string.ascii_uppercase + string.digits
    segments = [''.join(secrets.choice(chars) for _ in range(4)) for _ in range(3)]
    return f"{prefix.upper()}-{'-'.join(segments)}"


# ---------------------------------------------------------------------------
# Public endpoints
# ---------------------------------------------------------------------------

@app.route('/api/activate', methods=['POST'])
def activate():
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip().upper()
    hardware_id = (data.get('hardware_id') or '').strip()

    if not key or not hardware_id:
        return jsonify({'ok': False, 'message': 'key and hardware_id are required'}), 400

    lic = get_license(key)
    if not lic:
        return jsonify({'ok': False, 'message': 'License key not found'}), 404

    if lic['revoked']:
        return jsonify({'ok': False, 'message': 'License key has been revoked'}), 403

    # Check expiry
    if lic['expires_at'] and now_iso() > lic['expires_at']:
        return jsonify({'ok': False, 'message': 'License key has expired'}), 403

    # Already activated on a different hardware
    if lic['hardware_id'] and lic['hardware_id'] != hardware_id:
        return jsonify({'ok': False, 'message': 'License key is already activated on another machine'}), 409

    # First activation or same hardware re-activating
    if not lic['hardware_id']:
        activate_license(key, hardware_id, now_iso())
        lic = get_license(key)
    else:
        update_last_check(key, now_iso())

    return jsonify({'ok': True, 'expires_at': lic['expires_at'], 'message': 'Activation successful'})


@app.route('/api/verify', methods=['POST'])
def verify():
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip().upper()
    hardware_id = (data.get('hardware_id') or '').strip()

    if not key or not hardware_id:
        return jsonify({'ok': False, 'message': 'key and hardware_id are required'}), 400

    lic = get_license(key)
    if not lic:
        return jsonify({'ok': False, 'message': 'License key not found'}), 404

    if lic['revoked']:
        return jsonify({'ok': False, 'message': 'License key has been revoked'}), 403

    if not lic['hardware_id'] or lic['hardware_id'] != hardware_id:
        return jsonify({'ok': False, 'message': 'License key not activated on this machine'}), 403

    if lic['expires_at'] and now_iso() > lic['expires_at']:
        return jsonify({'ok': False, 'message': 'License key has expired'}), 403

    update_last_check(key, now_iso())
    return jsonify({'ok': True, 'expires_at': lic['expires_at'], 'message': 'License valid'})


# ---------------------------------------------------------------------------
# Admin — protected endpoints
# ---------------------------------------------------------------------------

@app.route('/api/revoke', methods=['POST'])
@require_admin
def revoke():
    data = request.get_json(silent=True) or {}
    key = (data.get('key') or '').strip().upper()
    if not key:
        return jsonify({'ok': False, 'message': 'key is required'}), 400

    lic = get_license(key)
    if not lic:
        return jsonify({'ok': False, 'message': 'License key not found'}), 404

    revoke_license(key)
    return jsonify({'ok': True, 'message': f'License {key} revoked'})


@app.route('/api/generate', methods=['POST'])
@require_admin
def generate():
    data = request.get_json(silent=True) or {}
    prefix = (data.get('prefix') or 'LIC').strip()[:8]
    count = min(int(data.get('count', 1)), 100)
    expires_days = int(data.get('expires_days', 365))

    expires_at = (datetime.now(timezone.utc) + timedelta(days=expires_days)).strftime('%Y-%m-%dT%H:%M:%SZ')

    generated = []
    for _ in range(count):
        for attempt in range(20):
            key = generate_key(prefix)
            if not get_license(key):
                insert_license(key, expires_at)
                generated.append(key)
                break

    return jsonify({'ok': True, 'keys': generated, 'expires_at': expires_at})


# ---------------------------------------------------------------------------
# Admin — HTML page
# ---------------------------------------------------------------------------

ADMIN_HTML = '''<!DOCTYPE html>
<html lang="it">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>License Admin</title>
<style>
  *{box-sizing:border-box;margin:0;padding:0}
  body{font-family:system-ui,sans-serif;background:#0f172a;color:#e2e8f0;min-height:100vh;padding:2rem}
  h1{font-size:1.5rem;margin-bottom:1.5rem;color:#f1f5f9}
  .card{background:#1e293b;border:1px solid #334155;border-radius:.75rem;padding:1.5rem;margin-bottom:1.5rem}
  .card h2{font-size:1rem;margin-bottom:1rem;color:#94a3b8;text-transform:uppercase;letter-spacing:.05em}
  label{display:block;font-size:.85rem;color:#94a3b8;margin-bottom:.3rem}
  input,select{width:100%;padding:.45rem .75rem;background:#0f172a;border:1px solid #334155;border-radius:.4rem;color:#e2e8f0;font-size:.9rem;margin-bottom:.75rem}
  .row{display:flex;gap:1rem;flex-wrap:wrap}
  .row>div{flex:1;min-width:120px}
  button{padding:.5rem 1.2rem;border:none;border-radius:.4rem;cursor:pointer;font-size:.9rem;font-weight:600}
  .btn-primary{background:#3b82f6;color:#fff}
  .btn-primary:hover{background:#2563eb}
  .btn-danger{background:#ef4444;color:#fff}
  .btn-danger:hover{background:#dc2626}
  .msg{margin-top:.75rem;padding:.5rem .75rem;border-radius:.4rem;font-size:.85rem}
  .msg.ok{background:#14532d;color:#86efac}
  .msg.err{background:#450a0a;color:#fca5a5}
  table{width:100%;border-collapse:collapse;font-size:.82rem}
  th{text-align:left;padding:.5rem .75rem;background:#0f172a;color:#64748b;font-weight:600;border-bottom:1px solid #334155}
  td{padding:.5rem .75rem;border-bottom:1px solid #1e293b;font-family:monospace}
  tr:hover td{background:#172033}
  .badge{display:inline-block;padding:.15rem .5rem;border-radius:999px;font-size:.75rem;font-weight:700}
  .badge-ok{background:#14532d;color:#86efac}
  .badge-rev{background:#450a0a;color:#fca5a5}
  .badge-new{background:#1e3a5f;color:#93c5fd}
  .badge-exp{background:#431407;color:#fdba74}
</style>
</head>
<body>
<h1>🔑 License Server — Admin</h1>

<div class="card">
  <h2>Genera Chiavi</h2>
  <div class="row">
    <div><label>Prefisso</label><input id="g-prefix" value="PRO" maxlength="8"></div>
    <div><label>Quantità</label><input id="g-count" type="number" value="1" min="1" max="100"></div>
    <div><label>Durata (giorni)</label><input id="g-days" type="number" value="365" min="1"></div>
    <div><label>Admin Password</label><input id="g-pwd" type="password" placeholder="password"></div>
  </div>
  <button class="btn-primary" onclick="generateKeys()">Genera</button>
  <div id="g-msg"></div>
</div>

<div class="card">
  <h2>Revoca Chiave</h2>
  <div class="row">
    <div style="flex:3"><label>Chiave</label><input id="r-key" placeholder="PRO-XXXX-XXXX-XXXX"></div>
    <div><label>Admin Password</label><input id="r-pwd" type="password" placeholder="password"></div>
  </div>
  <button class="btn-danger" onclick="revokeKey()">Revoca</button>
  <div id="r-msg"></div>
</div>

<div class="card">
  <h2>Tutte le Licenze</h2>
  <table id="tbl">
    <thead><tr>
      <th>Chiave</th><th>Hardware ID</th><th>Attivata</th><th>Scadenza</th><th>Ultimo Check</th><th>Stato</th>
    </tr></thead>
    <tbody id="tbl-body">
      {% for lic in licenses %}
      <tr>
        <td>{{ lic.key }}</td>
        <td>{{ lic.hardware_id or '—' }}</td>
        <td>{{ lic.activated_at or '—' }}</td>
        <td>{{ lic.expires_at or '—' }}</td>
        <td>{{ lic.last_check or '—' }}</td>
        <td>
          {% if lic.revoked %}
            <span class="badge badge-rev">REVOCATA</span>
          {% elif not lic.hardware_id %}
            <span class="badge badge-new">NON ATTIVATA</span>
          {% elif lic.expires_at and lic.expires_at < now %}
            <span class="badge badge-exp">SCADUTA</span>
          {% else %}
            <span class="badge badge-ok">ATTIVA</span>
          {% endif %}
        </td>
      </tr>
      {% endfor %}
    </tbody>
  </table>
</div>

<script>
async function generateKeys() {
  const msg = document.getElementById('g-msg');
  const res = await fetch('/api/generate', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      prefix: document.getElementById('g-prefix').value,
      count: parseInt(document.getElementById('g-count').value),
      expires_days: parseInt(document.getElementById('g-days').value),
      password: document.getElementById('g-pwd').value
    })
  });
  const data = await res.json();
  if (data.ok) {
    msg.className = 'msg ok';
    msg.textContent = 'Generate: ' + data.keys.join('  |  ');
    setTimeout(() => location.reload(), 1500);
  } else {
    msg.className = 'msg err';
    msg.textContent = data.message;
  }
}

async function revokeKey() {
  const msg = document.getElementById('r-msg');
  const res = await fetch('/api/revoke', {
    method: 'POST',
    headers: {'Content-Type':'application/json'},
    body: JSON.stringify({
      key: document.getElementById('r-key').value,
      password: document.getElementById('r-pwd').value
    })
  });
  const data = await res.json();
  if (data.ok) {
    msg.className = 'msg ok';
    msg.textContent = data.message;
    setTimeout(() => location.reload(), 1200);
  } else {
    msg.className = 'msg err';
    msg.textContent = data.message;
  }
}
</script>
</body>
</html>'''


@app.route('/api/admin', methods=['GET'])
def admin_page():
    pwd = request.args.get('password', '')
    if not check_admin(pwd):
        return Response(
            '<!DOCTYPE html><html><body style="font-family:sans-serif;background:#0f172a;color:#e2e8f0;display:flex;justify-content:center;align-items:center;height:100vh;flex-direction:column">'
            '<h2>Admin Login</h2>'
            '<form method="get">'
            '<input name="password" type="password" placeholder="Admin password" style="padding:.5rem 1rem;border-radius:.4rem;border:1px solid #334155;background:#1e293b;color:#e2e8f0;font-size:1rem">'
            '<button type="submit" style="margin-left:.5rem;padding:.5rem 1rem;background:#3b82f6;color:#fff;border:none;border-radius:.4rem;cursor:pointer">Accedi</button>'
            '</form></body></html>',
            status=401, mimetype='text/html'
        )

    licenses = all_licenses()
    now = now_iso()
    return render_template_string(ADMIN_HTML, licenses=licenses, now=now)


# ---------------------------------------------------------------------------
# Health check
# ---------------------------------------------------------------------------

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'ok': True,
        'status': 'running',
        'backend': 'postgresql' if USE_PG else 'sqlite',
    })


if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5001))
    app.run(host='0.0.0.0', port=port, debug=False)
