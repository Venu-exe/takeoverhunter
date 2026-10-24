"""SQLite-backed scan history and findings store."""
import json
import os
import sqlite3
import time


class ScanDB:
    def __init__(self, path="takeoverhunter.db"):
        self.path = path
        self.conn = sqlite3.connect(path, check_same_thread=False)
        self.conn.row_factory = sqlite3.Row
        self._init()

    def _init(self):
        c = self.conn.cursor()
        c.execute("""CREATE TABLE IF NOT EXISTS scans (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            target TEXT NOT NULL,
            started_at REAL NOT NULL,
            finished_at REAL,
            total INTEGER DEFAULT 0,
            candidates INTEGER DEFAULT 0
        )""")
        c.execute("""CREATE TABLE IF NOT EXISTS results (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id INTEGER NOT NULL,
            host TEXT NOT NULL,
            cname TEXT,
            http_status INTEGER,
            service TEXT,
            confidence TEXT,
            fingerprint TEXT,
            vulnerable INTEGER DEFAULT 0,
            raw TEXT,
            FOREIGN KEY(scan_id) REFERENCES scans(id)
        )""")
        self.conn.commit()

    def start_scan(self, target):
        c = self.conn.cursor()
        c.execute("INSERT INTO scans(target, started_at) VALUES (?,?)", (target, time.time()))
        self.conn.commit()
        return c.lastrowid

    def finish_scan(self, scan_id, total, candidates):
        c = self.conn.cursor()
        c.execute("UPDATE scans SET finished_at=?, total=?, candidates=? WHERE id=?",
                  (time.time(), total, candidates, scan_id))
        self.conn.commit()

    def add_result(self, scan_id, rec):
        c = self.conn.cursor()
        c.execute("""INSERT INTO results(scan_id, host, cname, http_status, service, confidence, fingerprint, vulnerable, raw)
                     VALUES (?,?,?,?,?,?,?,?,?)""",
                  (scan_id, rec["host"], rec.get("cname"), rec.get("http_status"),
                   rec.get("service"), rec.get("confidence"), rec.get("fingerprint"),
                   1 if rec.get("vulnerable") else 0, json.dumps(rec)))
        self.conn.commit()

    def list_scans(self, limit=50):
        c = self.conn.cursor()
        rows = c.execute("SELECT * FROM scans ORDER BY id DESC LIMIT ?", (limit,)).fetchall()
        return [dict(r) for r in rows]

    def get_scan(self, scan_id):
        c = self.conn.cursor()
        scan = c.execute("SELECT * FROM scans WHERE id=?", (scan_id,)).fetchone()
        if not scan:
            return None
        results = c.execute("SELECT * FROM results WHERE scan_id=?", (scan_id,)).fetchall()
        return {"scan": dict(scan), "results": [dict(r) for r in results]}

    def close(self):
        self.conn.close()
