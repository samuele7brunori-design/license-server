"""Small database compatibility layer for SQLite and PostgreSQL.

The local test suite continues to use sqlite3.  Render uses PostgreSQL when
DATABASE_URL is configured, so the server can run without an ephemeral local
database or persistent disk.
"""
from __future__ import annotations

import os
import re
import sqlite3
from typing import Any


class PostgresRow(dict):
    """Mapping row that also supports SQLite-style integer indexing."""

    def __getitem__(self, key: Any):
        if isinstance(key, int):
            return tuple(self.values())[key]
        return super().__getitem__(key)


class PostgresCursor:
    def __init__(self, cursor):
        self._cursor = cursor

    def fetchone(self):
        row = self._cursor.fetchone()
        if row is None:
            return None
        return PostgresRow(zip((column.name for column in self._cursor.description), row))

    def fetchall(self):
        return [PostgresRow(zip((column.name for column in self._cursor.description), row))
                for row in self._cursor.fetchall()]


class PostgresConnection:
    is_postgres = True

    def __init__(self, raw_connection):
        self._connection = raw_connection

    @classmethod
    def connect(cls, url: str) -> "PostgresConnection":
        import psycopg

        return cls(psycopg.connect(url))

    @staticmethod
    def _adapt_sql(sql: str) -> str:
        sql = sql.replace("BEGIN IMMEDIATE", "BEGIN")
        return re.sub(r"\?(?!\?)", "%s", sql)

    def execute(self, sql: str, params=()):
        statement = self._adapt_sql(sql)
        if params:
            return PostgresCursor(self._connection.execute(statement, params))
        return PostgresCursor(self._connection.execute(statement))

    def commit(self):
        self._connection.commit()

    def rollback(self):
        self._connection.rollback()

    def close(self):
        self._connection.close()


def connect_database(database_url: str | None, sqlite_path: str):
    if database_url:
        return PostgresConnection.connect(database_url)
    connection = sqlite3.connect(sqlite_path, detect_types=sqlite3.PARSE_DECLTYPES)
    connection.row_factory = sqlite3.Row
    return connection


def is_postgres(connection) -> bool:
    return bool(getattr(connection, "is_postgres", False))
