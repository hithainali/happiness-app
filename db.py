import sqlite3
from contextlib import contextmanager
from datetime import datetime
from sqlite3 import Connection, Row
from typing import List, Optional, Tuple

from config import DB_PATH


def get_conn() -> Connection:
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    conn = get_conn()
    c = conn.cursor()

    c.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE,
        password_hash TEXT,
        created_at TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS moods (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        mood INTEGER,
        note TEXT,
        date TEXT
    )
    """)

    c.execute("""
    CREATE TABLE IF NOT EXISTS ai_chats (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT,
        user_message TEXT,
        ai_response TEXT,
        date TEXT
    )
    """)

    conn.commit()
    conn.close()


@contextmanager
def db_cursor():
    conn = get_conn()
    cur = conn.cursor()
    try:
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


# Helper functions

def create_user(username: str, password_hash: str) -> bool:
    with db_cursor() as (conn, cur):
        try:
            cur.execute(
                "INSERT INTO users (username, password_hash, created_at) VALUES (?, ?, ?)",
                (username, password_hash, datetime.now().isoformat()),
            )
            return True
        except sqlite3.IntegrityError:
            return False


def get_user_by_username(username: str) -> Optional[Row]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT * FROM users WHERE username = ?", (username,))
    row = cur.fetchone()
    conn.close()
    return row


def save_mood(username: str, mood: int, note: str) -> None:
    with db_cursor() as (conn, cur):
        cur.execute(
            "INSERT INTO moods (username, mood, note, date) VALUES (?, ?, ?, ?)",
            (username, mood, note, datetime.now().isoformat()),
        )


def get_moods_by_user(username: str) -> List[Tuple]:
    conn = get_conn()
    cur = conn.cursor()
    cur.execute("SELECT mood, note, date FROM moods WHERE username=? ORDER BY date DESC", (username,))
    rows = cur.fetchall()
    conn.close()
    return rows


def get_recent_moods(username: str, limit: int = 5):
    conn = get_conn()
    cur = conn.cursor()
    cur.execute(
        "SELECT mood, note, date FROM moods WHERE username=? ORDER BY date DESC LIMIT ?",
        (username, limit),
    )
    rows = cur.fetchall()
    conn.close()
    return rows


def save_ai_chat(username: str, user_message: str, ai_response: str) -> None:
    with db_cursor() as (conn, cur):
        cur.execute(
            "INSERT INTO ai_chats (username, user_message, ai_response, date) VALUES (?, ?, ?, ?)",
            (username, user_message, ai_response, datetime.now().isoformat()),
        )


def get_all_moods():
    import pandas as pd
    conn = get_conn()
    df = pd.read_sql_query("SELECT * FROM moods", conn)
    conn.close()
    return df


def get_all_chats():
    import pandas as pd
    conn = get_conn()
    df = pd.read_sql_query("SELECT * FROM ai_chats", conn)
    conn.close()
    return df
