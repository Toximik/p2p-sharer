"""Sharer — a private torrent tracker + web UI for sharing files with friends.

The server acts as a permanent seed via HTTP webseeds (BEP 19), so no
BitTorrent client needs to run on the server. The tracker only answers
announces for torrents it created itself (infohash whitelist), torrents
are flagged private (no DHT/PEX), and the announce endpoint hides behind
a secret path segment.
"""

import functools
import os
import re
import secrets
import socket
import threading
import time
from urllib.parse import unquote_to_bytes

from flask import (Flask, abort, flash, g, redirect, render_template,
                   request, send_file, session, url_for)
from werkzeug.security import check_password_hash, generate_password_hash

import store
import torrentmaker
from bencode import bencode

DATA_DIR = os.path.abspath(os.environ.get("SHARER_DATA", os.path.join(os.path.dirname(__file__), "data")))
DB_PATH = os.path.join(DATA_DIR, "sharer.db")

os.makedirs(DATA_DIR, exist_ok=True)
store.init_db(DB_PATH)
CONFIG = store.load_config(DATA_DIR)
PEERS = store.PeerStore()

app = Flask(__name__)
app.secret_key = CONFIG["secret_key"]
app.config.update(
    SESSION_COOKIE_SAMESITE="Lax",
    SESSION_COOKIE_HTTPONLY=True,
    SESSION_COOKIE_SECURE=CONFIG["base_url"].startswith("https"),
)

ANNOUNCE_INTERVAL = 1800
MIN_INTERVAL = 900

LOGIN_MAX_FAILS = 5
LOGIN_WINDOW = 900  # 15 minutes
_login_failures = {}  # ip -> [timestamps of recent failures]
_login_fail_lock = threading.Lock()


# ---------------------------------------------------------------- helpers

def db():
    if "db" not in g:
        g.db = store.connect(DB_PATH)
    return g.db


@app.teardown_appcontext
def close_db(_exc):
    conn = g.pop("db", None)
    if conn is not None:
        conn.close()


def login_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        return view(*args, **kwargs)
    return wrapped


def admin_required(view):
    @functools.wraps(view)
    def wrapped(*args, **kwargs):
        if not session.get("uid"):
            return redirect(url_for("login", next=request.path))
        if not session.get("is_admin"):
            abort(403)
        return view(*args, **kwargs)
    return wrapped


def needs_setup() -> bool:
    conn = db()
    row = conn.execute("SELECT COUNT(*) AS n FROM users").fetchone()
    return row["n"] == 0 or not CONFIG["base_url"] or not CONFIG["files_root"]


@app.before_request
def force_setup():
    exempt = {"setup", "static"}
    if request.endpoint in exempt or (request.endpoint or "").startswith(("announce", "scrape", "webseed", "public_link")):
        return
    if needs_setup():
        return redirect(url_for("setup"))


@app.template_filter("human_size")
def human_size(n):
    for unit in ("B", "KiB", "MiB", "GiB", "TiB"):
        if n < 1024 or unit == "TiB":
            return f"{n:.1f} {unit}" if unit != "B" else f"{n} B"
        n /= 1024


@app.template_filter("date")
def fmt_date(ts):
    return time.strftime("%Y-%m-%d %H:%M", time.localtime(ts))


@app.template_filter("remaining")
def fmt_remaining(seconds):
    if seconds >= 86400:
        return f"in {seconds // 86400} d {seconds % 86400 // 3600} h"
    if seconds >= 3600:
        return f"in {seconds // 3600} h {seconds % 3600 // 60} min"
    return f"in {max(seconds, 0) // 60} min"


# ---------------------------------------------------------------- setup / auth

@app.route("/setup", methods=["GET", "POST"])
def setup():
    if not needs_setup():
        return redirect(url_for("index"))
    if request.method == "POST":
        base_url = request.form.get("base_url", "").strip().rstrip("/")
        files_root = request.form.get("files_root", "").strip()
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not re.match(r"^https?://", base_url):
            flash("Base URL must start with http:// or https://")
        elif not os.path.isdir(files_root):
            flash(f"Shared files directory does not exist: {files_root}")
        elif not username or len(password) < 8:
            flash("Username required; password must be at least 8 characters.")
        else:
            CONFIG["base_url"] = base_url
            CONFIG["files_root"] = os.path.realpath(files_root)
            store.save_config(DATA_DIR, CONFIG)
            app.config["SESSION_COOKIE_SECURE"] = base_url.startswith("https")
            conn = db()
            with conn:
                conn.execute(
                    "INSERT INTO users (username, pass_hash, is_admin, created_at) VALUES (?,?,1,?)",
                    (username, generate_password_hash(password), int(time.time())),
                )
            flash("Setup complete — log in with your new admin account.")
            return redirect(url_for("login"))
    guess = os.environ.get("SHARER_BASE_URL") or request.url_root.rstrip("/")
    files_guess = os.environ.get("SHARER_FILES_ROOT", "")
    return render_template("setup.html", guess=guess, files_guess=files_guess)


def _login_blocked(ip: str) -> bool:
    now = time.time()
    with _login_fail_lock:
        recent = [t for t in _login_failures.get(ip, ()) if now - t < LOGIN_WINDOW]
        if recent:
            _login_failures[ip] = recent
        else:
            _login_failures.pop(ip, None)
        return len(recent) >= LOGIN_MAX_FAILS


def _login_failed(ip: str):
    now = time.time()
    with _login_fail_lock:
        if len(_login_failures) > 10_000:  # bound memory under scanner floods
            cutoff = now - LOGIN_WINDOW
            for k in [k for k, v in _login_failures.items() if v[-1] < cutoff]:
                del _login_failures[k]
        _login_failures.setdefault(ip, []).append(now)


@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        ip = _client_ip()
        if _login_blocked(ip):
            app.logger.warning("sharer-auth: rate-limited login attempt from %s", ip)
            flash("Too many failed attempts — try again in 15 minutes.")
            return render_template("login.html"), 429
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        row = db().execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        if row and check_password_hash(row["pass_hash"], password):
            with _login_fail_lock:
                _login_failures.pop(ip, None)
            session.permanent = True
            session["uid"] = row["id"]
            session["username"] = row["username"]
            session["is_admin"] = bool(row["is_admin"])
            target = request.args.get("next", "")
            if not target.startswith("/") or target.startswith("//"):
                target = url_for("index")
            return redirect(target)
        _login_failed(ip)
        app.logger.warning("sharer-auth: failed login for %r from %s", username, ip)
        flash("Wrong username or password.")
    return render_template("login.html")


@app.route("/logout", methods=["POST"])
def logout():
    session.clear()
    return redirect(url_for("login"))


# ---------------------------------------------------------------- torrent hashing

def _hash_torrent(torrent_id: int):
    """Background thread: hash the file and store the finished metainfo."""
    conn = store.connect(DB_PATH)
    try:
        row = conn.execute("SELECT * FROM torrents WHERE id = ?", (torrent_id,)).fetchone()
        if row is None:
            return
        announce = f"{CONFIG['base_url']}/announce/{CONFIG['announce_secret']}"
        webseed = f"{CONFIG['base_url']}/ws/{CONFIG['announce_secret']}/{torrent_id}/"
        try:
            blob, infohash, size, piece_length, file_count = torrentmaker.build_torrent(
                row["file_path"], row["name"], announce, webseed)
            with conn:
                conn.execute(
                    "UPDATE torrents SET status='ready', torrent_blob=?, infohash=?, size=?, piece_length=?, file_count=? WHERE id=?",
                    (blob, infohash, size, piece_length, file_count, torrent_id),
                )
        except store.sqlite3.IntegrityError:
            with conn:
                conn.execute("UPDATE torrents SET status='error', error=? WHERE id=?",
                             ("Duplicate: an identical torrent already exists.", torrent_id))
        except (OSError, ValueError) as exc:
            with conn:
                conn.execute("UPDATE torrents SET status='error', error=? WHERE id=?",
                             (str(exc), torrent_id))
    finally:
        conn.close()


def _requeue_unfinished():
    conn = store.connect(DB_PATH)
    rows = conn.execute("SELECT id FROM torrents WHERE status = 'hashing'").fetchall()
    conn.close()
    for row in rows:
        threading.Thread(target=_hash_torrent, args=(row["id"],), daemon=True).start()


_requeue_unfinished()


# ---------------------------------------------------------------- web UI

@app.route("/")
@login_required
def index():
    rows = db().execute("SELECT * FROM torrents ORDER BY created_at DESC").fetchall()
    torrents = []
    hashing = False
    for row in rows:
        seeders, leechers = PEERS.counts(row["infohash"]) if row["infohash"] else (0, 0)
        hashing = hashing or row["status"] == "hashing"
        torrents.append({**dict(row), "seeders": seeders, "leechers": leechers})
    return render_template("index.html", torrents=torrents, hashing=hashing)


def _resolve_shared(rel: str) -> str:
    """Resolve a relative path inside files_root; abort on traversal."""
    root = os.path.realpath(CONFIG["files_root"])
    target = os.path.realpath(os.path.join(root, rel))
    try:
        if os.path.commonpath([root, target]) != root:
            abort(404)
    except ValueError:  # different drives on Windows
        abort(404)
    return target


@app.route("/add")
@admin_required
def add():
    rel = request.args.get("d", "").strip("/\\")
    root = os.path.realpath(CONFIG["files_root"])
    target = _resolve_shared(rel)
    if not os.path.isdir(target):
        abort(404)
    registered = {row["file_path"] for row in
                  db().execute("SELECT file_path FROM torrents").fetchall()}
    dirs, files = [], []
    try:
        for entry in sorted(os.scandir(target), key=lambda e: e.name.lower()):
            if entry.name.startswith("."):
                continue
            entry_rel = os.path.relpath(entry.path, root).replace(os.sep, "/")
            if entry.is_dir(follow_symlinks=False):
                dirs.append({"name": entry.name, "rel": entry_rel,
                             "registered": os.path.realpath(entry.path) in registered})
            elif entry.is_file():
                files.append({"name": entry.name, "rel": entry_rel,
                              "size": entry.stat().st_size,
                              "registered": os.path.realpath(entry.path) in registered})
    except OSError as exc:
        flash(f"Cannot read directory: {exc}")
    parent = os.path.dirname(rel).replace(os.sep, "/") if rel else None
    return render_template("add.html", rel=rel, parent=parent, dirs=dirs,
                           files=files, root=root)


@app.route("/add", methods=["POST"])
@admin_required
def add_file():
    rel = request.form.get("path", "")
    target = _resolve_shared(rel)
    if not (os.path.isfile(target) or os.path.isdir(target)):
        flash("No such file or folder in the shared directory.")
        return redirect(url_for("add"))
    target = os.path.realpath(target)
    conn = db()
    exists = conn.execute("SELECT id FROM torrents WHERE file_path=?", (target,)).fetchone()
    if exists:
        flash("A torrent for that file already exists.")
        return redirect(url_for("add", d=os.path.dirname(rel)))
    name = os.path.basename(target)
    with conn:
        cur = conn.execute(
            "INSERT INTO torrents (name, file_path, created_at) VALUES (?,?,?)",
            (name, target, int(time.time())),
        )
        tid = cur.lastrowid
    threading.Thread(target=_hash_torrent, args=(tid,), daemon=True).start()
    flash(f"Creating torrent for “{name}” — hashing in the background.")
    return redirect(url_for("index"))


@app.route("/torrent/<int:tid>.torrent")
@login_required
def download_torrent(tid):
    row = db().execute("SELECT * FROM torrents WHERE id=? AND status='ready'", (tid,)).fetchone()
    if row is None:
        abort(404)
    fname = re.sub(r"[^\w.-]+", "_", row["name"]) + ".torrent"
    from io import BytesIO
    return send_file(BytesIO(row["torrent_blob"]), mimetype="application/x-bittorrent",
                     as_attachment=True, download_name=fname)


@app.route("/torrent/<int:tid>/delete", methods=["POST"])
@admin_required
def delete_torrent(tid):
    conn = db()
    row = conn.execute("SELECT * FROM torrents WHERE id=?", (tid,)).fetchone()
    if row is None:
        abort(404)
    with conn:
        conn.execute("DELETE FROM torrents WHERE id=?", (tid,))
    flash(f"Removed “{row['name']}” (the file itself stays on the server).")
    return redirect(url_for("index"))


# ---------------------------------------------------------------- temporary links

LINK_EXPIRY_CHOICES = [  # (hours, label)
    (1, "1 hour"), (6, "6 hours"), (24, "1 day"), (72, "3 days"),
    (168, "7 days"), (720, "30 days"),
]
LINK_RESUME_GRACE = 3600  # resumes allowed this long after the last counted download


def _link_url(token: str) -> str:
    # No filename in the URL: it would leak what's shared to anyone who sees the
    # link (chat previews, proxy logs). The download still gets the real name via
    # Content-Disposition. Old /d/<token>/<name> URLs keep working.
    return CONFIG["base_url"] + url_for("public_link", token=token, sub="")


def _purge_expired_links(conn):
    with conn:
        conn.execute("DELETE FROM links WHERE expires_at <= ?", (int(time.time()),))


@app.route("/links")
@admin_required
def links():
    conn = db()
    _purge_expired_links(conn)
    rows = conn.execute(
        "SELECT links.*, users.username FROM links LEFT JOIN users ON users.id = links.created_by "
        "ORDER BY links.created_at DESC").fetchall()
    items = [{**dict(r), "url": _link_url(r["token"]),
              "missing": not os.path.exists(r["path"])} for r in rows]
    return render_template("links.html", links=items, now=int(time.time()))


@app.route("/links/new", methods=["GET", "POST"])
@admin_required
def new_link():
    rel = (request.values.get("path") or "").strip("/\\")
    target = os.path.realpath(_resolve_shared(rel))
    if not rel or not (os.path.isfile(target) or os.path.isdir(target)):
        flash("No such file or folder in the shared directory.")
        return redirect(url_for("add"))
    is_dir = os.path.isdir(target)
    name = os.path.basename(target)
    if request.method == "POST":
        try:
            hours = int(request.form.get("hours", ""))
        except ValueError:
            hours = 0
        max_dl = None
        if not is_dir and request.form.get("max_downloads", "").strip():
            try:
                max_dl = int(request.form["max_downloads"])
            except ValueError:
                max_dl = 0
        if hours not in {h for h, _ in LINK_EXPIRY_CHOICES}:
            flash("Pick a valid expiry.")
        elif max_dl is not None and max_dl < 1:
            flash("Max downloads must be a positive number (or empty for unlimited).")
        else:
            now = int(time.time())
            token = secrets.token_urlsafe(16)
            with db() as conn:
                conn.execute(
                    "INSERT INTO links (token, name, path, is_dir, created_by, created_at, expires_at, max_downloads) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (token, name, target, int(is_dir), session["uid"], now, now + hours * 3600, max_dl),
                )
            flash(f"Link created for “{name}”.")
            return redirect(url_for("links"))
    return render_template("link_new.html", rel=rel, name=name, is_dir=is_dir,
                           choices=LINK_EXPIRY_CHOICES)


@app.route("/links/<int:lid>/delete", methods=["POST"])
@admin_required
def delete_link(lid):
    with db() as conn:
        conn.execute("DELETE FROM links WHERE id=?", (lid,))
    flash("Link revoked.")
    return redirect(url_for("links"))


@app.route("/users", methods=["GET", "POST"])
@admin_required
def users():
    conn = db()
    if request.method == "POST":
        username = request.form.get("username", "").strip()
        password = request.form.get("password", "")
        if not username or len(password) < 8:
            flash("Username required; password must be at least 8 characters.")
        else:
            try:
                with conn:
                    conn.execute(
                        "INSERT INTO users (username, pass_hash, is_admin, created_at) VALUES (?,?,?,?)",
                        (username, generate_password_hash(password),
                         1 if request.form.get("is_admin") else 0, int(time.time())),
                    )
                flash(f"Added user “{username}”.")
            except store.sqlite3.IntegrityError:
                flash("That username already exists.")
        return redirect(url_for("users"))
    rows = conn.execute("SELECT * FROM users ORDER BY created_at").fetchall()
    return render_template("users.html", users=rows)


@app.route("/users/<int:uid>/delete", methods=["POST"])
@admin_required
def delete_user(uid):
    if uid == session["uid"]:
        flash("You cannot delete your own account.")
        return redirect(url_for("users"))
    with db() as conn:
        conn.execute("DELETE FROM users WHERE id=?", (uid,))
    return redirect(url_for("users"))


@app.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        base_url = request.form.get("base_url", "").strip().rstrip("/")
        files_root = request.form.get("files_root", "").strip()
        if not re.match(r"^https?://", base_url):
            flash("Base URL must start with http:// or https://")
        elif not os.path.isdir(files_root):
            flash(f"Shared files directory does not exist: {files_root}")
        else:
            CONFIG["base_url"] = base_url
            CONFIG["files_root"] = os.path.realpath(files_root)
            CONFIG["trust_proxy"] = bool(request.form.get("trust_proxy"))
            store.save_config(DATA_DIR, CONFIG)
            app.config["SESSION_COOKIE_SECURE"] = base_url.startswith("https")
            flash("Saved. Note: torrents created earlier keep their old announce/webseed URLs.")
        return redirect(url_for("settings"))
    return render_template("settings.html", config=CONFIG)


# ---------------------------------------------------------------- tracker

def _client_ip() -> str:
    if CONFIG.get("trust_proxy"):
        fwd = request.headers.get("X-Forwarded-For", "")
        if fwd:
            return fwd.split(",")[0].strip()
    return request.remote_addr


def _raw_query(qs: bytes) -> dict:
    """Parse the query string without UTF-8 decoding — info_hash and peer_id
    are raw 20-byte values that percent-decoding must yield untouched."""
    out = {}
    for pair in qs.split(b"&"):
        key, _, val = pair.partition(b"=")
        out[unquote_to_bytes(key)] = unquote_to_bytes(val)
    return out


def _bencoded(payload: dict, status=200):
    return app.response_class(bencode(payload), status=status, mimetype="text/plain")


def _tracker_failure(message: str):
    return _bencoded({"failure reason": message})


@app.route("/announce/<secret>")
def announce(secret):
    if secret != CONFIG["announce_secret"]:
        abort(404)
    q = _raw_query(request.query_string)
    infohash_raw = q.get(b"info_hash", b"")
    peer_id = q.get(b"peer_id", b"")
    if len(infohash_raw) != 20 or len(peer_id) != 20:
        return _tracker_failure("missing or malformed info_hash/peer_id")
    infohash = infohash_raw.hex()

    row = db().execute("SELECT id FROM torrents WHERE infohash=? AND status='ready'",
                       (infohash,)).fetchone()
    if row is None:
        return _tracker_failure("unregistered torrent")

    try:
        port = int(q.get(b"port", b"0"))
        left = int(q.get(b"left", b"0"))
        numwant = min(int(q.get(b"numwant", b"50") or 50), 80)
    except ValueError:
        return _tracker_failure("malformed numeric parameter")
    if not 0 < port < 65536:
        return _tracker_failure("invalid port")
    event = q.get(b"event", b"").decode("ascii", "replace")

    if event == "completed":
        with db() as conn:
            conn.execute("UPDATE torrents SET completed_count = completed_count + 1 WHERE infohash=?",
                         (infohash,))

    ip = _client_ip()
    PEERS.announce(infohash, peer_id, ip, port, left, event)

    peers4, peers6 = b"", b""
    peer_dicts = []
    compact = q.get(b"compact", b"1") != b"0"
    for peer in PEERS.get_peers(infohash, peer_id, numwant):
        try:
            packed_port = peer["port"].to_bytes(2, "big")
            if ":" in peer["ip"]:
                peers6 += socket.inet_pton(socket.AF_INET6, peer["ip"]) + packed_port
            else:
                peers4 += socket.inet_pton(socket.AF_INET, peer["ip"]) + packed_port
        except OSError:
            continue
        peer_dicts.append({"ip": peer["ip"], "port": peer["port"]})

    seeders, leechers = PEERS.counts(infohash)
    resp = {
        "interval": ANNOUNCE_INTERVAL,
        "min interval": MIN_INTERVAL,
        "complete": seeders,
        "incomplete": leechers,
    }
    if compact:
        resp["peers"] = peers4
        if peers6:
            resp["peers6"] = peers6
    else:
        resp["peers"] = peer_dicts
    return _bencoded(resp)


@app.route("/scrape/<secret>")
def scrape(secret):
    if secret != CONFIG["announce_secret"]:
        abort(404)
    files = {}
    hashes = [unquote_to_bytes(pair.partition(b"=")[2])
              for pair in request.query_string.split(b"&")
              if pair.partition(b"=")[0] == b"info_hash"]
    for raw in hashes:
        if len(raw) != 20:
            continue
        infohash = raw.hex()
        row = db().execute(
            "SELECT completed_count FROM torrents WHERE infohash=? AND status='ready'",
            (infohash,)).fetchone()
        if row is None:
            continue
        seeders, leechers = PEERS.counts(infohash)
        files[raw] = {"complete": seeders, "incomplete": leechers,
                      "downloaded": row["completed_count"]}
    return _bencoded({"files": files})


@app.route("/ws/<secret>/<int:tid>/<path:reqpath>")
def webseed(secret, tid, reqpath):
    if secret != CONFIG["announce_secret"]:
        abort(404)
    row = db().execute("SELECT * FROM torrents WHERE id=?", (tid,)).fetchone()
    if row is None:
        abort(404)
    base = row["file_path"]
    # single-file torrent: client requests <name>
    if reqpath == row["name"] and os.path.isfile(base):
        return send_file(base, conditional=True, mimetype="application/octet-stream")
    # folder torrent: client requests <name>/<path/inside/folder>
    prefix = row["name"] + "/"
    if reqpath.startswith(prefix) and os.path.isdir(base):
        root = os.path.realpath(base)
        target = os.path.realpath(os.path.join(root, reqpath[len(prefix):]))
        try:
            if os.path.commonpath([root, target]) != root:
                abort(404)
        except ValueError:
            abort(404)
        if os.path.isfile(target):
            return send_file(target, conditional=True, mimetype="application/octet-stream")
    abort(404)


# ---------------------------------------------------------------- public temporary links

def _serve_link_file(link, path: str):
    """Send one file of a link. Only downloads that start at byte 0 count toward
    max_downloads; resumes (Range from a later offset) are let through for a grace
    period so a download that hit the limit can still finish."""
    now = int(time.time())
    rng = request.headers.get("Range", "").strip()
    m = re.match(r"bytes=(\d*)-", rng)
    fresh = request.method == "GET" and (not m or m.group(1) == "0")
    limit = link["max_downloads"]
    if limit is not None and link["download_count"] >= limit:
        if fresh or not link["last_download_at"] or now - link["last_download_at"] > LINK_RESUME_GRACE:
            abort(410)
    if fresh:
        with db() as conn:
            conn.execute("UPDATE links SET download_count = download_count + 1, last_download_at = ? WHERE id = ?",
                         (now, link["id"]))
    return send_file(path, conditional=True, as_attachment=True,
                     download_name=os.path.basename(path))


@app.route("/d/<token>/", defaults={"sub": ""})
@app.route("/d/<token>/<path:sub>")
def public_link(token, sub):
    link = db().execute("SELECT * FROM links WHERE token=? AND expires_at > ?",
                        (token, int(time.time()))).fetchone()
    if link is None:
        abort(404)
    root = link["path"]
    if not link["is_dir"]:
        if sub not in ("", link["name"]) or not os.path.isfile(root):
            abort(404)
        return _serve_link_file(link, root)

    # folder link: live view of the folder; hidden entries and symlinks are off-limits
    parts = [p for p in sub.split("/") if p]
    if any(p.startswith(".") for p in parts):
        abort(404)
    target = os.path.join(root, *parts)
    try:
        if os.path.commonpath([root, os.path.realpath(target)]) != root:
            abort(404)
    except ValueError:
        abort(404)
    cur = root
    for p in parts:
        cur = os.path.join(cur, p)
        if os.path.islink(cur):
            abort(404)
    if os.path.isfile(target):
        return _serve_link_file(link, target)
    if not os.path.isdir(target):
        abort(404)
    if sub and not sub.endswith("/"):
        return redirect(url_for("public_link", token=token, sub=sub + "/"))

    rel = "/".join(parts)
    dirs, files = [], []
    try:
        for entry in sorted(os.scandir(target), key=lambda e: e.name.lower()):
            if entry.name.startswith(".") or entry.is_symlink():
                continue
            entry_rel = f"{rel}/{entry.name}" if rel else entry.name
            if entry.is_dir(follow_symlinks=False):
                dirs.append({"name": entry.name, "sub": entry_rel + "/"})
            elif entry.is_file(follow_symlinks=False):
                files.append({"name": entry.name, "sub": entry_rel, "size": entry.stat().st_size})
    except OSError:
        abort(404)
    parent = None
    if parts:
        parent = "/".join(parts[:-1]) + ("/" if len(parts) > 1 else "")
    return render_template("public_link.html", link=link, token=token, rel=rel,
                           parent=parent, dirs=dirs, files=files)


# ---------------------------------------------------------------- entrypoint

if __name__ == "__main__":
    import logging
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    host = os.environ.get("SHARER_HOST", "0.0.0.0")
    port = int(os.environ.get("SHARER_PORT", "8080"))
    try:
        from waitress import serve
        print(f"Sharer listening on http://{host}:{port} (waitress)")
        serve(app, host=host, port=port, threads=8)
    except ImportError:
        print(f"Sharer listening on http://{host}:{port} (Flask dev server — install waitress for production)")
        app.run(host=host, port=port, threaded=True)
