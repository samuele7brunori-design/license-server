"""
database.py — dual-backend: PostgreSQL (DATABASE_URL) o SQLite (DB_PATH)

Differenze gestite internamente:
  - placeholder  : SQLite usa ?   | PostgreSQL usa %s
  - row factory  : sqlite3.Row    | psycopg2 RealDictCursor
  - URL prefix   : Render espone  postgres://  ma psycopg2 vuole postgresql://
  - AUTOCOMMIT   : SQLite con 'with' fa commit auto | psycopg2 richiede commit esplicito
"""

import os
import sqlite3
from contextlib import contextmanager

DATABASE_URL = os.environ.get('DATABASE_URL', '')
DB_PATH      = os.environ.get('DB_PATH', 'licenses.db')

# Render espone postgres://, psycopg2 vuole postgresql://
if DATABASE_URL.startswith('postgres://'):
    DATABASE_URL = DATABASE_URL.replace('postgres://', 'postgresql://', 1)

USE_PG = bool(DATABASE_URL)

if USE_PG:
    import psycopg2
    import psycopg2.extras

# ---------------------------------------------------------------------------
# Placeholder helper
# ---------------------------------------------------------------------------
# SQLite usa ? come placeholder, PostgreSQL usa %s.
# Tutti i moduli interni passano query scritte con ?, questa funzione
# le converte al volo per PostgreSQL.

def _q(sql: str) -> str:
    """Converte placeholder ? → %s quando si usa PostgreSQL."""
    if USE_PG:
        return sql.replace('?', '%s')
    return sql


# ---------------------------------------------------------------------------
# Connection context manager
# ---------------------------------------------------------------------------

@contextmanager
def get_conn():
    if USE_PG:
        conn = psycopg2.connect(DATABASE_URL)
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()
    else:
        conn = sqlite3.connect(DB_PATH)
        conn.row_factory = sqlite3.Row
        try:
            yield conn
            conn.commit()
        except Exception:
            conn.rollback()
            raise
        finally:
            conn.close()


def _fetchone(cursor, row):
    """Normalizza una riga: dict sia per SQLite (Row) che per psycopg2 (RealDict)."""
    if row is None:
        return None
    return dict(row)


def _execute(conn, sql: str, params=()):
    """Esegue una query con il cursor corretto per il backend attivo."""
    if USE_PG:
        cur = conn.cursor(cursor_factory=psycopg2.extras.RealDictCursor)
    else:
        cur = conn.cursor()
    cur.execute(_q(sql), params)
    return cur


# ---------------------------------------------------------------------------
# Schema
# ---------------------------------------------------------------------------

def init_db():
    with get_conn() as conn:
        _execute(conn, '''
            CREATE TABLE IF NOT EXISTS licenses (
                key          TEXT PRIMARY KEY,
                hardware_id  TEXT,
                activated_at TEXT,
                expires_at   TEXT,
                revoked      INTEGER DEFAULT 0,
                last_check   TEXT
            )
        ''')


# ---------------------------------------------------------------------------
# CRUD
# ---------------------------------------------------------------------------

def get_license(key: str):
    with get_conn() as conn:
        cur = _execute(conn, 'SELECT * FROM licenses WHERE key = ?', (key,))
        return _fetchone(conn, cur.fetchone())


def insert_license(key: str, expires_at: str):
    with get_conn() as conn:
        _execute(
            conn,
            'INSERT INTO licenses (key, expires_at, revoked) VALUES (?, ?, 0)',
            (key, expires_at),
        )


def activate_license(key: str, hardware_id: str, activated_at: str):
    with get_conn() as conn:
        _execute(
            conn,
            'UPDATE licenses SET hardware_id = ?, activated_at = ?, last_check = ? WHERE key = ?',
            (hardware_id, activated_at, activated_at, key),
        )


def update_last_check(key: str, ts: str):
    with get_conn() as conn:
        _execute(conn, 'UPDATE licenses SET last_check = ? WHERE key = ?', (ts, key))


def revoke_license(key: str):
    with get_conn() as conn:
        _execute(conn, 'UPDATE licenses SET revoked = 1 WHERE key = ?', (key,))


def all_licenses():
    with get_conn() as conn:
        cur = _execute(
            conn,
            'SELECT * FROM licenses ORDER BY activated_at DESC NULLS LAST',
        )
        rows = cur.fetchall()
        return [dict(r) for r in rows]
