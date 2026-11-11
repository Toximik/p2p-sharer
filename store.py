"""SQLite persistence and in-memory peer store."""

import json
import os
import secrets
import sqlite3
import threading
import time

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY,
    username TEXT NOT NULL UNIQUE,
    pass_hash TEXT NOT NULL,
    is_admin INTEGER NOT NULL DEFAULT 0,
    created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS torrents (
    id INTEGER PRIMARY KEY,
    name TEXT NOT NULL,
    file_path TEXT NOT NULL,
    size INTEGER NOT NULL DEFAULT 0,
    piece_length INTEGER NOT NULL DEFAULT 0,
    infohash TEXT UNIQUE,
    status TEXT NOT NULL DEFAULT 'hashing',  -- hashing | ready | error
    error TEXT,
    torrent_blob BLOB,
    completed_count INTEGER NOT NULL DEFAULT 0,
    file_count INTEGER NOT NULL DEFAULT 1,
    created_at INTEGER NOT NULL
);
"""


def connect(db_path: str) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, timeout=30)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA foreign_keys=ON")
    return conn


def init_db(db_path: str):
    conn = connect(db_path)
    with conn:
        conn.executescript(SCHEMA)
    conn.close()


def load_config(data_dir: str) -> dict:
    """Load data/config.json, creating it with generated secrets on first run."""
    path = os.path.join(data_dir, "config.json")
    if os.path.exists(path):
        with open(path, encoding="utf-8") as f:
            cfg = json.load(f)
    else:
        cfg = {}
    changed = False
    if "announce_secret" not in cfg:
        cfg["announce_secret"] = secrets.token_urlsafe(16)
        changed = True
    if "secret_key" not in cfg:
        cfg["secret_key"] = secrets.token_urlsafe(32)
        changed = True
    cfg.setdefault("base_url", "")
    cfg.setdefault("files_root", "")
    cfg.setdefault("trust_proxy", False)
    if changed:
        save_config(data_dir, cfg)
    return cfg


def save_config(data_dir: str, cfg: dict):
    path = os.path.join(data_dir, "config.json")
    tmp = path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)
    os.replace(tmp, path)


class PeerStore:
    """In-memory swarm state: {infohash_hex: {peer_id: peer_dict}}."""

    PEER_TTL = 3600  # drop peers not seen for an hour

    def __init__(self):
        self._lock = threading.Lock()
        self._swarms = {}

    def announce(self, infohash: str, peer_id: bytes, ip: str, port: int,
                 left: int, event: str):
        now = time.time()
        with self._lock:
            swarm = self._swarms.setdefault(infohash, {})
            if event == "stopped":
                swarm.pop(peer_id, None)
            else:
                swarm[peer_id] = {
                    "ip": ip, "port": port,
                    "seeding": left == 0,
                    "last_seen": now,
                }
            stale = [pid for pid, p in swarm.items()
                     if now - p["last_seen"] > self.PEER_TTL]
            for pid in stale:
                del swarm[pid]
            if not swarm:
                self._swarms.pop(infohash, None)

    def get_peers(self, infohash: str, exclude_peer_id: bytes, numwant: int):
        with self._lock:
            swarm = self._swarms.get(infohash, {})
            peers = [p for pid, p in swarm.items() if pid != exclude_peer_id]
        return peers[:numwant]

    def counts(self, infohash: str):
        now = time.time()
        with self._lock:
            swarm = self._swarms.get(infohash, {})
            live = [p for p in swarm.values()
                    if now - p["last_seen"] <= self.PEER_TTL]
        seeders = sum(1 for p in live if p["seeding"])
        return seeders, len(live) - seeders
