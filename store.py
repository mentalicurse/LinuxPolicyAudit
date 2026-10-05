"""SQLite-хранилище снимков политики, событий доступа и переходов состояний."""
from __future__ import annotations
import json
import sqlite3
import time
from typing import Any


class EventStore:
    def __init__(self, db_path: str = "policy_audit.db"):
        self.db_path = db_path
        self._conn = sqlite3.connect(db_path, check_same_thread=False)
        self._init_db()
        self._ensure_columns()

    def _init_db(self) -> None:
        # WAL позволяет читать БД во время записи; busy_timeout ждёт освобождения блокировки.
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA busy_timeout=5000")

        with self._conn:
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_versions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    hash TEXT NOT NULL,
                    timestamp REAL NOT NULL,
                    target_dir TEXT NOT NULL,
                    snapshot_json TEXT NOT NULL,
                    parent_version_id INTEGER,
                    source TEXT DEFAULT 'auto',
                    state_id INTEGER
                );
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS monitoring_sessions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    state_id INTEGER NOT NULL,
                    started_at REAL NOT NULL,
                    ended_at REAL,
                    status TEXT NOT NULL DEFAULT 'active',
                    description TEXT,
                    FOREIGN KEY(state_id) REFERENCES policy_versions(id)
                );
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS state_transitions (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    from_state_id INTEGER,
                    to_state_id INTEGER NOT NULL,
                    ts REAL NOT NULL,
                    reason TEXT,
                    details TEXT,
                    FOREIGN KEY(from_state_id) REFERENCES policy_versions(id),
                    FOREIGN KEY(to_state_id) REFERENCES policy_versions(id)
                );
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS access_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_version_id INTEGER NOT NULL,
                    state_id INTEGER,
                    session_id INTEGER,
                    ts REAL NOT NULL,
                    subject TEXT NOT NULL,
                    path TEXT NOT NULL,
                    action TEXT NOT NULL,
                    allowed INTEGER NOT NULL,
                    FOREIGN KEY(policy_version_id) REFERENCES policy_versions(id),
                    FOREIGN KEY(session_id) REFERENCES monitoring_sessions(id)
                );
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_access_events_ts ON access_events(ts);
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_access_events_version ON access_events(policy_version_id);
            """)
            self._conn.execute("""
                CREATE INDEX IF NOT EXISTS idx_access_events_triple ON access_events(subject, path, action);
            """)
            self._conn.execute("""
                CREATE TABLE IF NOT EXISTS policy_changes (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    policy_version_id INTEGER NOT NULL,
                    state_id INTEGER,
                    session_id INTEGER,
                    ts REAL NOT NULL,
                    subject TEXT NOT NULL,
                    path TEXT NOT NULL,
                    action TEXT NOT NULL,
                    new_mode TEXT,
                    process TEXT,
                    suspicious INTEGER NOT NULL DEFAULT 0,
                    FOREIGN KEY(policy_version_id) REFERENCES policy_versions(id),
                    FOREIGN KEY(session_id) REFERENCES monitoring_sessions(id)
                );
            """)

    def _ensure_columns(self) -> None:
        columns_by_table = {
            "policy_versions": ["state_id", "parent_version_id", "source"],
            "access_events": ["state_id", "session_id"],
            "policy_changes": ["state_id", "session_id", "suspicious"],
        }
        for table, cols in columns_by_table.items():
            existing = {
                row[1] for row in self._conn.execute(f"PRAGMA table_info({table})").fetchall()
            }
            for col in cols:
                if col not in existing:
                    if col in {"state_id", "parent_version_id", "session_id"}:
                        col_type = "INTEGER"
                    elif col == "source":
                        col_type = "TEXT DEFAULT 'auto'"
                    else:
                        col_type = "TEXT"
                    self._conn.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")

    # Снимки политики и их связь с предыдущим состоянием.

    def add_policy_version(self, snapshot: dict, parent_version_id: int | None = None, source: str = "auto") -> int:
        snap_hash = snapshot.get("snapshot_hash", "")
        target_dir = snapshot.get("target_dir", "")
        ts = snapshot.get("timestamp", time.time())
        snap_json = json.dumps(snapshot, ensure_ascii=False)

        with self._conn:
            version_id = self._conn.execute(
                "INSERT INTO policy_versions (hash, timestamp, target_dir, snapshot_json, parent_version_id, source, state_id) VALUES (?, ?, ?, ?, ?, ?, ?)",
                (snap_hash, ts, target_dir, snap_json, parent_version_id, source, 0),
            ).lastrowid
            self._conn.execute(
                "UPDATE policy_versions SET state_id = ? WHERE id = ?",
                (version_id, version_id),
            )
            return version_id

    def get_current_policy_version(self) -> tuple[int, dict] | None:
        row = self._conn.execute(
            "SELECT id, snapshot_json FROM policy_versions ORDER BY id DESC LIMIT 1"
        ).fetchone()
        if not row:
            return None
        return row[0], json.loads(row[1])

    def get_policy_version_by_id(self, version_id: int) -> tuple[int, dict] | None:
        row = self._conn.execute(
            "SELECT id, snapshot_json FROM policy_versions WHERE id = ? LIMIT 1",
            (version_id,),
        ).fetchone()
        if not row:
            return None
        return row[0], json.loads(row[1])

    def get_policy_versions(self, limit: int | None = None) -> list[tuple[int, dict]]:
        q = "SELECT id, snapshot_json FROM policy_versions ORDER BY id DESC"
        if limit is not None:
            q += f" LIMIT {limit}"
        rows = self._conn.execute(q).fetchall()
        return [(row[0], json.loads(row[1])) for row in rows]

    def get_policy_version_ids(self) -> list[int]:
        rows = self._conn.execute("SELECT id FROM policy_versions ORDER BY id DESC").fetchall()
        return [row[0] for row in rows]

    def count_policy_versions(self) -> int:
        row = self._conn.execute("SELECT COUNT(*) FROM policy_versions").fetchone()
        return row[0] if row else 0

    # Сессии мониторинга привязаны к конкретной версии политики.

    def create_monitoring_session(self, state_id: int, description: str = "") -> int:
        row = self._conn.execute(
            "SELECT id FROM monitoring_sessions WHERE state_id = ? AND status = 'active' ORDER BY started_at DESC LIMIT 1",
            (state_id,),
        ).fetchone()
        if row is not None:
            return row[0]

        with self._conn:
            cursor = self._conn.execute(
                "INSERT INTO monitoring_sessions (state_id, started_at, status, description) VALUES (?, ?, 'active', ?)",
                (state_id, time.time(), description),
            )
            return cursor.lastrowid

    def close_monitoring_session(self, session_id: int | None) -> None:
        if session_id is None:
            return
        with self._conn:
            self._conn.execute(
                "UPDATE monitoring_sessions SET ended_at = ?, status = 'closed' WHERE id = ?",
                (time.time(), session_id),
            )

    def get_active_session_for_state(self, state_id: int) -> int | None:
        row = self._conn.execute(
            "SELECT id FROM monitoring_sessions WHERE state_id = ? AND status = 'active' ORDER BY started_at DESC LIMIT 1",
            (state_id,),
        ).fetchone()
        return row[0] if row else None

    # Причина и время перехода между версиями политики.

    def record_transition(self, from_state_id: int | None, to_state_id: int, reason: str, details: str | None = None) -> None:
        with self._conn:
            self._conn.execute(
                "INSERT INTO state_transitions (from_state_id, to_state_id, ts, reason, details) VALUES (?, ?, ?, ?, ?)",
                (from_state_id, to_state_id, time.time(), reason, details),
            )

    def get_state_transitions(self, state_id: int | None = None) -> list[dict]:
        q = "SELECT from_state_id, to_state_id, ts, reason, details FROM state_transitions"
        params: list[Any] = []
        if state_id is not None:
            q += " WHERE from_state_id = ? OR to_state_id = ?"
            params.extend([state_id, state_id])
        q += " ORDER BY ts ASC"
        rows = self._conn.execute(q, params).fetchall()
        return [
            {
                "from_state_id": r[0],
                "to_state_id": r[1],
                "ts": r[2],
                "reason": r[3],
                "details": r[4],
            }
            for r in rows
        ]

    # События доступа и изменения прав хранятся вместе с версией и сессией.

    def _normalize_state_session(self, version_id: int, state_id: int | None, session_id: int | None) -> tuple[int, int | None]:
        state = version_id if state_id is None else int(state_id)
        if state != version_id:
            raise ValueError(
                f"state_id={state} mismatch: event for version_id={version_id} must belong to the same state"
            )
        if session_id is not None:
            session_state = self._conn.execute(
                "SELECT state_id FROM monitoring_sessions WHERE id = ? LIMIT 1",
                (session_id,),
            ).fetchone()
            if session_state is None:
                raise ValueError(f"session_id={session_id} does not exist")
            if session_state[0] != state:
                raise ValueError(
                    f"session_id={session_id} belongs to state {session_state[0]}, expected {state}"
                )
        return state, session_id

    def record_access(self, version_id, subject, path, action, allowed, ts,
                      state_id=None, session_id=None) -> None:
        state, session = self._normalize_state_session(version_id, state_id, session_id)
        with self._conn:
            self._conn.execute(
                "INSERT INTO access_events (policy_version_id, state_id, session_id, ts, subject, path, action, allowed) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (version_id, state, session, ts, subject, path, action, 1 if allowed else 0),
            )

    def record_policy_change(self, version_id, subject, path, action, new_mode,
                             process, ts, state_id=None, session_id=None,
                             suspicious=False) -> None:
        state, session = self._normalize_state_session(version_id, state_id, session_id)
        with self._conn:
            self._conn.execute(
                "INSERT INTO policy_changes (policy_version_id, state_id, session_id, ts, subject, path, action, new_mode, process, suspicious) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (version_id, state, session, ts, subject, path, action, new_mode, process, 1 if suspicious else 0),
            )

    def get_used_triples(self, since: float | None = None,
                         version_id: int | None = None) -> set[tuple[str, str, str]]:
        q = "SELECT DISTINCT subject, path, action FROM access_events WHERE allowed=1"
        params: list[Any] = []
        if version_id is not None:
            q += " AND policy_version_id = ?"
            params.append(version_id)
        if since is not None:
            q += " AND ts >= ?"
            params.append(since)
        rows = self._conn.execute(q, params).fetchall()
        return {(r[0], r[1], r[2]) for r in rows}

    def get_violations(self, since: float | None = None,
                       version_id: int | None = None) -> list[dict]:
        q = "SELECT ts, subject, path, action FROM access_events WHERE allowed=0"
        params: list[Any] = []
        if version_id is not None:
            q += " AND policy_version_id = ?"
            params.append(version_id)
        if since is not None:
            q += " AND ts >= ?"
            params.append(since)
        q += " ORDER BY ts"
        rows = self._conn.execute(q, params).fetchall()
        return [
            {"timestamp": r[0], "subject": r[1], "path": r[2], "action": r[3]}
            for r in rows
        ]

    def get_policy_changes(self, since: float | None = None) -> list[dict]:
        q = "SELECT ts, subject, path, action, new_mode, process, suspicious, state_id FROM policy_changes"
        params: list[Any] = []
        if since is not None:
            q += " WHERE ts >= ?"
            params.append(since)
        q += " ORDER BY ts"
        rows = self._conn.execute(q, params).fetchall()
        return [
            {
                "timestamp": r[0],
                "subject": r[1],
                "path": r[2],
                "action": r[3],
                "new_mode": r[4],
                "process": r[5],
                "suspicious": bool(r[6]),
                "state_id": r[7],
            }
            for r in rows
        ]

    def event_count(self, since: float | None = None, subject: str | None = None) -> int:
        q = "SELECT COUNT(*) FROM access_events WHERE 1=1"
        params: list[Any] = []
        if since is not None:
            q += " AND ts >= ?"
            params.append(since)
        if subject is not None:
            q += " AND subject = ?"
            params.append(subject)
        row = self._conn.execute(q, params).fetchone()
        return row[0] if row else 0

    def has_any_event(self, version_id: int) -> bool:
        row = self._conn.execute(
            "SELECT 1 FROM access_events WHERE policy_version_id=? LIMIT 1",
            (version_id,),
        ).fetchone()
        return row is not None

    def close(self) -> None:
        self._conn.close()