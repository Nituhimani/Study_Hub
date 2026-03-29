"""
Student desk — notes, to-dos per account (username + password, SQLite).
"""
from __future__ import annotations

import os
import re
import sqlite3
from datetime import datetime, timezone
from functools import wraps
from pathlib import Path

from flask import Flask, g, jsonify, redirect, render_template, request, session
from werkzeug.security import check_password_hash, generate_password_hash

BASE_DIR = Path(__file__).resolve().parent


def _env_clean(name: str) -> str | None:
    raw = os.environ.get(name)
    if raw is None:
        return None
    v = raw.strip()
    if len(v) >= 2 and v[0] == v[-1] and v[0] in "'\"":
        v = v[1:-1].strip()
    return v or None


# On Render (or any host), set DATABASE_PATH to a file on a persistent disk, e.g. /data/student_desk.db
_db_override = _env_clean("DATABASE_PATH")
DB_PATH = Path(_db_override) if _db_override else BASE_DIR / "student_desk.db"


def utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S")


def db() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def _table_columns(conn: sqlite3.Connection, table: str) -> set[str]:
    try:
        return {r[1] for r in conn.execute(f"PRAGMA table_info({table})")}
    except sqlite3.Error:
        return set()


def _migrate_users_to_name_keys(conn: sqlite3.Connection) -> None:
    """Upgrade old Google-based users table to display_name + name_key + password_hash."""
    conn.execute("PRAGMA foreign_keys=OFF")
    conn.execute("ALTER TABLE users RENAME TO users_legacy")
    conn.execute(
        """
        CREATE TABLE users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            display_name TEXT NOT NULL,
            name_key TEXT NOT NULL UNIQUE,
            password_hash TEXT,
            created_at TEXT NOT NULL,
            last_productivity_day TEXT
        )
        """
    )
    rows = conn.execute(
        "SELECT id, name, email, created_at, last_productivity_day FROM users_legacy"
    ).fetchall()
    for r in rows:
        disp = (r["name"] or r["email"] or "Student").strip() or "Student"
        disp = disp[:200]
        key_base = disp.lower()
        key = key_base
        n = 0
        while True:
            taken = conn.execute(
                "SELECT 1 FROM users WHERE name_key = ?", (key,)
            ).fetchone()
            if not taken:
                break
            n += 1
            key = f"{key_base}-{n}"
        conn.execute(
            """
            INSERT INTO users (id, display_name, name_key, password_hash, created_at, last_productivity_day)
            VALUES (?, ?, ?, NULL, ?, ?)
            """,
            (r["id"], disp, key, r["created_at"], r["last_productivity_day"]),
        )
    conn.execute("DROP TABLE users_legacy")
    conn.execute("PRAGMA foreign_keys=ON")


_USERNAME_RE = re.compile(r"^[\w.-]{3,40}$", re.UNICODE)


def _validate_username(username: str) -> bool:
    u = username.strip()
    if not _USERNAME_RE.fullmatch(u):
        return False
    return True


def _username_key(username: str) -> str:
    return username.strip().lower()


def _login_key(raw: str) -> str | None:
    """Normalize username for sign-in / claim (allows spaces for older profiles)."""
    s = (raw or "").strip().lower()
    if len(s) < 1 or len(s) > 80:
        return None
    return s


def init_db() -> None:
    conn = db()
    has_users = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='users'"
    ).fetchone()
    if not has_users:
        conn.execute(
            """
            CREATE TABLE users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                display_name TEXT NOT NULL,
                name_key TEXT NOT NULL UNIQUE,
                password_hash TEXT,
                created_at TEXT NOT NULL,
                last_productivity_day TEXT
            )
            """
        )
    else:
        ucols = _table_columns(conn, "users")
        if "name_key" not in ucols:
            _migrate_users_to_name_keys(conn)
        else:
            ucols = _table_columns(conn, "users")
            if "password_hash" not in ucols:
                conn.execute("ALTER TABLE users ADD COLUMN password_hash TEXT")

    have_notes = _table_columns(conn, "notes")
    if not have_notes:
        conn.execute(
            """
            CREATE TABLE notes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                body TEXT NOT NULL DEFAULT '',
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
    else:
        if "user_id" not in have_notes:
            conn.execute("ALTER TABLE notes ADD COLUMN user_id INTEGER REFERENCES users(id)")
        conn.execute("DELETE FROM notes WHERE user_id IS NULL")

    have_todos = _table_columns(conn, "todos")
    if not have_todos:
        conn.execute(
            """
            CREATE TABLE todos (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_id INTEGER NOT NULL,
                title TEXT NOT NULL DEFAULT '',
                done INTEGER NOT NULL DEFAULT 0,
                position INTEGER NOT NULL DEFAULT 0,
                created_at TEXT NOT NULL,
                completed_at TEXT,
                FOREIGN KEY (user_id) REFERENCES users(id)
            )
            """
        )
    else:
        if "user_id" not in have_todos:
            conn.execute("ALTER TABLE todos ADD COLUMN user_id INTEGER REFERENCES users(id)")
        if "completed_at" not in have_todos:
            conn.execute("ALTER TABLE todos ADD COLUMN completed_at TEXT")
        conn.execute("DELETE FROM todos WHERE user_id IS NULL")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS user_prefs (
            user_id INTEGER PRIMARY KEY,
            focus_intention TEXT NOT NULL DEFAULT '',
            updated_at TEXT NOT NULL,
            FOREIGN KEY (user_id) REFERENCES users(id)
        );
        """
    )

    conn.execute("DROP TABLE IF EXISTS productivity_daily")

    conn.commit()
    conn.close()


init_db()

app = Flask(__name__)
app.secret_key = _env_clean("SECRET_KEY") or "dev-secret-change-for-production"
app.config["SESSION_COOKIE_SAMESITE"] = "Lax"


def row_note(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "title": r["title"],
        "body": r["body"],
        "created_at": r["created_at"],
        "updated_at": r["updated_at"],
    }


def row_todo(r: sqlite3.Row) -> dict:
    return {
        "id": r["id"],
        "title": r["title"],
        "done": bool(r["done"]),
        "position": r["position"],
        "created_at": r["created_at"],
        "completed_at": r["completed_at"],
    }


def login_required(f):
    @wraps(f)
    def wrapped(*args, **kwargs):
        uid = session.get("user_id")
        if not uid:
            return jsonify({"error": "unauthorized"}), 401
        g.user_id = uid
        return f(*args, **kwargs)

    return wrapped


@app.route("/")
def index():
    return render_template("index.html")


def _session_response(user_id: int, display_name: str) -> tuple:
    session.clear()
    session["user_id"] = user_id
    session.permanent = True
    return jsonify({"ok": True, "user": {"id": user_id, "name": display_name}}), 200


@app.route("/api/register", methods=["POST"])
def register():
    """Create account: unique username (letters, digits, . _ -), password ≥ 8."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    disp_raw = (data.get("display_name") or username).strip()
    if not _validate_username(username):
        return jsonify(
            {
                "error": "Username: 3–40 characters, letters/numbers ._- only, no spaces "
                "(e.g. priya.sharma, alex_02).",
            }
        ), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "Password must be 8–128 characters."}), 400
    key = _username_key(username)
    disp = (disp_raw or username)[:200]
    conn = db()
    if conn.execute("SELECT 1 FROM users WHERE name_key = ?", (key,)).fetchone():
        conn.close()
        return jsonify({"error": "That username is taken. Pick another."}), 409
    ph = generate_password_hash(password)
    cur = conn.execute(
        """
        INSERT INTO users (display_name, name_key, password_hash, created_at, last_productivity_day)
        VALUES (?, ?, ?, ?, NULL)
        """,
        (disp, key, ph, utc_now()),
    )
    uid = int(cur.lastrowid)
    conn.commit()
    conn.close()
    return _session_response(uid, disp)


@app.route("/api/session", methods=["POST"])
def api_session():
    """Sign in with username + password (case-insensitive username match)."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    key = _login_key(username)
    if not key:
        return jsonify({"error": "Enter your username (1–80 characters)."}), 400
    conn = db()
    row = conn.execute(
        """
        SELECT id, password_hash, display_name FROM users WHERE name_key = ?
        """,
        (key,),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "Unknown username."}), 401
    ph = row["password_hash"]
    if not ph:
        return jsonify(
            {
                "error": "This profile has no password yet. Use “Set password (old profile)” below once.",
            }
        ), 403
    if not check_password_hash(ph, password):
        return jsonify({"error": "Wrong password."}), 401
    uid = int(row["id"])
    disp = row["display_name"] or username
    return _session_response(uid, disp)


@app.route("/api/claim-password", methods=["POST"])
def claim_password():
    """One-time: set password for rows created before passwords existed; then logs you in."""
    data = request.get_json(silent=True) or {}
    username = (data.get("username") or "").strip()
    password = data.get("password") or ""
    key = _login_key(username)
    if not key:
        return jsonify({"error": "Enter your username (1–80 characters)."}), 400
    if len(password) < 8 or len(password) > 128:
        return jsonify({"error": "Password must be 8–128 characters."}), 400
    conn = db()
    row = conn.execute(
        "SELECT id, password_hash, display_name FROM users WHERE name_key = ?",
        (key,),
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "Unknown username. Use Register instead."}), 404
    if row["password_hash"]:
        conn.close()
        return jsonify({"error": "This account already has a password. Sign in normally."}), 409
    ph = generate_password_hash(password)
    uid = int(row["id"])
    conn.execute(
        "UPDATE users SET password_hash = ? WHERE id = ?",
        (ph, uid),
    )
    conn.commit()
    disp = row["display_name"] or username
    conn.close()
    return _session_response(uid, disp)


@app.route("/logout")
def logout():
    session.clear()
    return redirect("/")


@app.route("/api/me", methods=["GET"])
def me():
    uid = session.get("user_id")
    if not uid:
        return jsonify({"logged_in": False})
    conn = db()
    try:
        u = conn.execute(
            "SELECT id, display_name, name_key, created_at FROM users WHERE id = ?",
            (uid,),
        ).fetchone()
    finally:
        conn.close()
    if not u:
        session.clear()
        return jsonify({"logged_in": False})
    return jsonify(
        {
            "logged_in": True,
            "user": {
                "id": u["id"],
                "name": u["display_name"],
                "username": u["name_key"],
                "created_at": u["created_at"],
            },
        }
    )


@app.route("/api/prefs", methods=["GET"])
@login_required
def get_prefs():
    conn = db()
    row = conn.execute(
        "SELECT focus_intention, updated_at FROM user_prefs WHERE user_id = ?",
        (g.user_id,),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"focus_intention": "", "updated_at": None})
    return jsonify(
        {"focus_intention": row["focus_intention"], "updated_at": row["updated_at"]}
    )


@app.route("/api/prefs", methods=["PATCH"])
@login_required
def patch_prefs():
    data = request.get_json(silent=True) or {}
    intention = (data.get("focus_intention") or "").strip()[:4000]
    now = utc_now()
    conn = db()
    conn.execute(
        """
        INSERT INTO user_prefs (user_id, focus_intention, updated_at)
        VALUES (?, ?, ?)
        ON CONFLICT(user_id) DO UPDATE SET
            focus_intention = excluded.focus_intention,
            updated_at = excluded.updated_at
        """,
        (g.user_id, intention, now),
    )
    conn.commit()
    conn.close()
    return jsonify({"focus_intention": intention, "updated_at": now})


@app.route("/api/notes", methods=["GET"])
@login_required
def list_notes():
    conn = db()
    rows = conn.execute(
        """
        SELECT id, title, body, created_at, updated_at FROM notes
        WHERE user_id = ?
        ORDER BY updated_at DESC
        """,
        (g.user_id,),
    ).fetchall()
    conn.close()
    return jsonify({"notes": [row_note(r) for r in rows]})


@app.route("/api/notes", methods=["POST"])
@login_required
def create_note():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "Untitled").strip()[:500]
    body = (data.get("body") or "").strip()[:100_000]
    now = utc_now()
    conn = db()
    cur = conn.execute(
        """
        INSERT INTO notes (user_id, title, body, created_at, updated_at)
        VALUES (?, ?, ?, ?, ?)
        """,
        (g.user_id, title, body, now, now),
    )
    nid = cur.lastrowid
    row = conn.execute(
        "SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?",
        (nid, g.user_id),
    ).fetchone()
    conn.commit()
    conn.close()
    return jsonify(row_note(row)), 201


@app.route("/api/notes/<int:nid>", methods=["GET"])
@login_required
def get_note(nid: int):
    conn = db()
    row = conn.execute(
        "SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?",
        (nid, g.user_id),
    ).fetchone()
    conn.close()
    if not row:
        return jsonify({"error": "not found"}), 404
    return jsonify(row_note(row))


@app.route("/api/notes/<int:nid>", methods=["PATCH"])
@login_required
def update_note(nid: int):
    data = request.get_json(silent=True) or {}
    conn = db()
    row = conn.execute(
        "SELECT id FROM notes WHERE id = ? AND user_id = ?", (nid, g.user_id)
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404
    fields: list[str] = []
    vals: list = []
    if "title" in data:
        fields.append("title = ?")
        vals.append((data.get("title") or "").strip()[:500])
    if "body" in data:
        fields.append("body = ?")
        vals.append((data.get("body") or "").strip()[:100_000])
    if fields:
        fields.append("updated_at = ?")
        vals.append(utc_now())
        vals.extend([nid, g.user_id])
        conn.execute(
            f"UPDATE notes SET {', '.join(fields)} WHERE id = ? AND user_id = ?",
            tuple(vals),
        )
        conn.commit()
    row = conn.execute(
        "SELECT id, title, body, created_at, updated_at FROM notes WHERE id = ? AND user_id = ?",
        (nid, g.user_id),
    ).fetchone()
    conn.close()
    return jsonify(row_note(row))


@app.route("/api/notes/<int:nid>", methods=["DELETE"])
@login_required
def delete_note(nid: int):
    conn = db()
    cur = conn.execute(
        "DELETE FROM notes WHERE id = ? AND user_id = ?", (nid, g.user_id)
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    return "", 204


@app.route("/api/todos", methods=["GET"])
@login_required
def list_todos():
    conn = db()
    rows = conn.execute(
        """
        SELECT id, title, done, position, created_at, completed_at FROM todos
        WHERE user_id = ?
        ORDER BY position ASC, id ASC
        """,
        (g.user_id,),
    ).fetchall()
    conn.close()
    return jsonify({"todos": [row_todo(r) for r in rows]})


@app.route("/api/todos", methods=["POST"])
@login_required
def create_todo():
    data = request.get_json(silent=True) or {}
    title = (data.get("title") or "").strip()[:500]
    if not title:
        return jsonify({"error": "title required"}), 400
    conn = db()
    max_pos = conn.execute(
        "SELECT COALESCE(MAX(position), -1) AS m FROM todos WHERE user_id = ?",
        (g.user_id,),
    ).fetchone()["m"]
    pos = int(max_pos) + 1
    now = utc_now()
    cur = conn.execute(
        """
        INSERT INTO todos (user_id, title, done, position, created_at, completed_at)
        VALUES (?, ?, 0, ?, ?, NULL)
        """,
        (g.user_id, title, pos, now),
    )
    tid = cur.lastrowid
    row = conn.execute(
        "SELECT id, title, done, position, created_at, completed_at FROM todos WHERE id = ? AND user_id = ?",
        (tid, g.user_id),
    ).fetchone()
    conn.commit()
    conn.close()
    return jsonify(row_todo(row)), 201


@app.route("/api/todos/<int:tid>", methods=["PATCH"])
@login_required
def update_todo(tid: int):
    data = request.get_json(silent=True) or {}
    conn = db()
    row = conn.execute(
        "SELECT id, done FROM todos WHERE id = ? AND user_id = ?",
        (tid, g.user_id),
    ).fetchone()
    if not row:
        conn.close()
        return jsonify({"error": "not found"}), 404

    fields: list[str] = []
    vals: list = []
    prev_done = bool(row["done"])

    if "title" in data:
        fields.append("title = ?")
        vals.append((data.get("title") or "").strip()[:500])

    if "done" in data:
        new_done = bool(data.get("done"))
        fields.append("done = ?")
        vals.append(1 if new_done else 0)
        if new_done and not prev_done:
            fields.append("completed_at = ?")
            vals.append(utc_now())
        elif not new_done:
            fields.append("completed_at = ?")
            vals.append(None)

    if fields:
        vals.extend([tid, g.user_id])
        conn.execute(
            f"UPDATE todos SET {', '.join(fields)} WHERE id = ? AND user_id = ?",
            tuple(vals),
        )
        conn.commit()

    row = conn.execute(
        "SELECT id, title, done, position, created_at, completed_at FROM todos WHERE id = ? AND user_id = ?",
        (tid, g.user_id),
    ).fetchone()
    conn.close()
    return jsonify(row_todo(row))


@app.route("/api/todos/<int:tid>", methods=["DELETE"])
@login_required
def delete_todo(tid: int):
    conn = db()
    cur = conn.execute(
        "DELETE FROM todos WHERE id = ? AND user_id = ?", (tid, g.user_id)
    )
    conn.commit()
    conn.close()
    if cur.rowcount == 0:
        return jsonify({"error": "not found"}), 404
    return "", 204


@app.route("/api/todos/clear-done", methods=["POST"])
@login_required
def clear_done_todos():
    conn = db()
    conn.execute("DELETE FROM todos WHERE user_id = ? AND done = 1", (g.user_id,))
    conn.commit()
    conn.close()
    return jsonify({"ok": True})


if __name__ == "__main__":
    app.run(
        host="127.0.0.1",
        port=int(os.environ.get("PORT", "5000")),
        debug=True,
        use_reloader=False,
    )
