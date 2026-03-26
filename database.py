import sqlite3
from pathlib import Path
from typing import Optional

DEFAULT_DB_PATH: Path = Path("vault.db")

CredentialRow = tuple[int, str, str, bytes, bytes]

def get_connection(db_path: Path = DEFAULT_DB_PATH) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path)
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.row_factory = sqlite3.Row
    return conn


def initialize_database(db_path: Path = DEFAULT_DB_PATH) -> None:
    with get_connection(db_path) as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS master (
                id            INTEGER PRIMARY KEY CHECK (id = 1),
                password_hash BLOB    NOT NULL,
                salt          BLOB    NOT NULL
            );

            CREATE TABLE IF NOT EXISTS credentials (
                id                 INTEGER PRIMARY KEY AUTOINCREMENT,
                service            TEXT    NOT NULL,
                username           TEXT    NOT NULL,
                encrypted_password BLOB    NOT NULL,
                salt               BLOB    NOT NULL
            );
            """
        )

def save_master_password(
    password_hash: bytes,
    salt: bytes,
    db_path: Path = DEFAULT_DB_PATH,
) -> None:
    with get_connection(db_path) as conn:
        conn.execute(
            "INSERT OR REPLACE INTO master (id, password_hash, salt) VALUES (1, ?, ?);",
            (password_hash, salt),
        )


def load_master_password(
    db_path: Path = DEFAULT_DB_PATH,
) -> Optional[tuple[bytes, bytes]]:
    with get_connection(db_path) as conn:
        row = conn.execute(
            "SELECT password_hash, salt FROM master WHERE id = 1;"
        ).fetchone()
    if row is None:
        return None
    return bytes(row["password_hash"]), bytes(row["salt"])


def is_initialized(db_path: Path = DEFAULT_DB_PATH) -> bool:
    return load_master_password(db_path) is not None

def add_credential(
    service: str,
    username: str,
    encrypted_password: bytes,
    salt: bytes,
    db_path: Path = DEFAULT_DB_PATH,
) -> int:
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            """
            INSERT INTO credentials (service, username, encrypted_password, salt)
            VALUES (?, ?, ?, ?);
            """,
            (service, username, encrypted_password, salt),
        )
        return cursor.lastrowid


def get_credential(
    service: str,
    db_path: Path = DEFAULT_DB_PATH,
) -> Optional[CredentialRow]:
    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, service, username, encrypted_password, salt
            FROM credentials
            WHERE LOWER(service) = LOWER(?)
            LIMIT 1;
            """,
            (service,),
        ).fetchone()
    if row is None:
        return None
    return (
        row["id"],
        row["service"],
        row["username"],
        bytes(row["encrypted_password"]),
        bytes(row["salt"]),
    )


def get_credential_by_id(
    credential_id: int,
    db_path: Path = DEFAULT_DB_PATH,
) -> Optional[CredentialRow]:
    with get_connection(db_path) as conn:
        row = conn.execute(
            """
            SELECT id, service, username, encrypted_password, salt
            FROM credentials
            WHERE id = ?;
            """,
            (credential_id,),
        ).fetchone()
    if row is None:
        return None
    return (
        row["id"],
        row["service"],
        row["username"],
        bytes(row["encrypted_password"]),
        bytes(row["salt"]),
    )


def list_credentials(
    db_path: Path = DEFAULT_DB_PATH,
) -> list[tuple[int, str, str]]:
    with get_connection(db_path) as conn:
        rows = conn.execute(
            "SELECT id, service, username FROM credentials ORDER BY service ASC;"
        ).fetchall()
    return [(row["id"], row["service"], row["username"]) for row in rows]


def delete_credential(
    credential_id: int,
    db_path: Path = DEFAULT_DB_PATH,
) -> bool:
    with get_connection(db_path) as conn:
        cursor = conn.execute(
            "DELETE FROM credentials WHERE id = ?;",
            (credential_id,),
        )
        return cursor.rowcount > 0
