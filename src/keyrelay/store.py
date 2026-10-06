from __future__ import annotations

import sqlite3
import uuid
from dataclasses import dataclass
from pathlib import Path

from .security import VaultCipher


@dataclass(frozen=True)
class Site:
    id: str
    name: str
    login_url: str
    username_selector: str
    password_selector: str
    submit_selector: str
    allowed_hosts: list[str]


class VaultStore:
    def __init__(self, path: Path, cipher: VaultCipher):
        path.parent.mkdir(parents=True, exist_ok=True)
        self._path = path
        self._cipher = cipher
        with self._connect() as db:
            db.execute(
                """
                CREATE TABLE IF NOT EXISTS sites (
                    id TEXT PRIMARY KEY,
                    name TEXT NOT NULL,
                    login_url TEXT NOT NULL,
                    username_selector TEXT NOT NULL,
                    password_selector TEXT NOT NULL,
                    submit_selector TEXT NOT NULL,
                    allowed_hosts TEXT NOT NULL,
                    credentials TEXT NOT NULL
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path)
        connection.row_factory = sqlite3.Row
        return connection

    @staticmethod
    def _site(row: sqlite3.Row) -> Site:
        return Site(
            id=row["id"],
            name=row["name"],
            login_url=row["login_url"],
            username_selector=row["username_selector"],
            password_selector=row["password_selector"],
            submit_selector=row["submit_selector"],
            allowed_hosts=row["allowed_hosts"].split(","),
        )

    def list_sites(self) -> list[Site]:
        with self._connect() as db:
            rows = db.execute(
                """SELECT id, name, login_url, username_selector, password_selector,
                          submit_selector, allowed_hosts
                   FROM sites ORDER BY name"""
            ).fetchall()
        return [self._site(row) for row in rows]

    def create_site(
        self,
        *,
        name: str,
        login_url: str,
        username: str,
        password: str,
        username_selector: str,
        password_selector: str,
        submit_selector: str,
        allowed_hosts: list[str],
    ) -> Site:
        site_id = uuid.uuid4().hex[:12]
        encrypted = self._cipher.encrypt({"username": username, "password": password})
        with self._connect() as db:
            db.execute(
                "INSERT INTO sites VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    site_id,
                    name,
                    login_url,
                    username_selector,
                    password_selector,
                    submit_selector,
                    ",".join(allowed_hosts),
                    encrypted,
                ),
            )
        return self.get_site(site_id)[0]

    def get_site(self, site_id: str) -> tuple[Site, dict[str, str]]:
        with self._connect() as db:
            row = db.execute("SELECT * FROM sites WHERE id = ?", (site_id,)).fetchone()
        if row is None:
            raise KeyError(site_id)
        return self._site(row), self._cipher.decrypt(row["credentials"])

    def delete_site(self, site_id: str) -> bool:
        with self._connect() as db:
            result = db.execute("DELETE FROM sites WHERE id = ?", (site_id,))
        return result.rowcount > 0
