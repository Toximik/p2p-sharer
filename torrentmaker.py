"""Create .torrent metainfo (single-file or folder) with private flag and webseed."""

import hashlib
import os
import time

from bencode import bencode

MIN_PIECE = 256 * 1024
MAX_PIECE = 16 * 1024 * 1024
TARGET_PIECES = 1500


def pick_piece_length(size: int) -> int:
    piece = MIN_PIECE
    while piece < MAX_PIECE and size / piece > TARGET_PIECES:
        piece *= 2
    return piece


def collect_files(root: str):
    """Deterministic recursive listing: [(path_parts, abspath, size), ...].

    Sorted by name at every level so the byte stream (and therefore the
    infohash) is reproducible. Hidden entries and symlinks are skipped —
    symlinks could point outside the shared directory, which the webseed
    endpoint refuses to serve.
    """
    out = []

    def walk(d, parts):
        for entry in sorted(os.scandir(d), key=lambda e: e.name):
            if entry.name.startswith(".") or entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                walk(entry.path, parts + [entry.name])
            elif entry.is_file(follow_symlinks=False):
                out.append((parts + [entry.name], entry.path, entry.stat().st_size))

    walk(root, [])
    return out


def hash_pieces(paths, piece_length: int) -> bytes:
    """SHA1 pieces over the concatenation of the given files, in order.
    Pieces cross file boundaries (BEP 3)."""
    pieces = []
    h = hashlib.sha1()
    filled = 0
    for path in paths:
        with open(path, "rb") as f:
            while True:
                chunk = f.read(piece_length - filled)
                if not chunk:
                    break
                h.update(chunk)
                filled += len(chunk)
                if filled == piece_length:
                    pieces.append(h.digest())
                    h = hashlib.sha1()
                    filled = 0
    if filled:
        pieces.append(h.digest())
    return b"".join(pieces)


def build_torrent(path: str, name: str, announce_url: str, webseed_url: str):
    """Returns (torrent_bytes, infohash_hex, total_size, piece_length, file_count).

    webseed_url must end with "/" (BEP 19): clients append the torrent name,
    plus the inner file path for folder torrents.
    """
    if os.path.isdir(path):
        files = collect_files(path)
        if not files:
            raise ValueError("folder contains no shareable files")
        size = sum(s for _, _, s in files)
        piece_length = pick_piece_length(size)
        info = {
            "name": name,
            "piece length": piece_length,
            "pieces": hash_pieces([p for _, p, _ in files], piece_length),
            "private": 1,
            "files": [{"length": s, "path": parts} for parts, _, s in files],
        }
        file_count = len(files)
    else:
        size = os.path.getsize(path)
        piece_length = pick_piece_length(size)
        info = {
            "name": name,
            "length": size,
            "piece length": piece_length,
            "pieces": hash_pieces([path], piece_length),
            "private": 1,
        }
        file_count = 1
    infohash = hashlib.sha1(bencode(info)).hexdigest()
    meta = {
        "announce": announce_url,
        "info": info,
        "url-list": [webseed_url],
        "created by": "Sharer",
        "creation date": int(time.time()),
    }
    return bencode(meta), infohash, size, piece_length, file_count
