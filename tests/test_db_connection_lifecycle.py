import sqlite3
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from app import db


class ConnectionLifecycleTests(unittest.TestCase):
    def test_commit_rollback_and_close(self):
        with tempfile.TemporaryDirectory() as directory:
            with patch.object(db, "DB_PATH", Path(directory) / "test.db"):
                with db.db_connect() as connection:
                    connection.execute("CREATE TABLE entries(value INTEGER)")
                    connection.execute("INSERT INTO entries VALUES (1)")
                with self.assertRaises(sqlite3.ProgrammingError):
                    connection.execute("SELECT 1")
                with self.assertRaisesRegex(RuntimeError, "abort"):
                    with db.db_connect() as failed:
                        failed.execute("INSERT INTO entries VALUES (2)")
                        raise RuntimeError("abort")
                with self.assertRaises(sqlite3.ProgrammingError):
                    failed.execute("SELECT 1")
                with db.db_connect() as check:
                    self.assertEqual(check.execute("SELECT value FROM entries").fetchall()[0][0], 1)
                    self.assertEqual(check.execute("SELECT COUNT(*) FROM entries").fetchone()[0], 1)

    def test_repeated_requests_release_connections_without_garbage_collection(self):
        with patch.object(db, "DB_PATH", ":memory:"):
            retained = []
            for _ in range(500):
                with db.db_connect() as connection:
                    connection.execute("SELECT 1").fetchone()
                retained.append(connection)
            for connection in retained:
                with self.assertRaises(sqlite3.ProgrammingError):
                    connection.execute("SELECT 1")
