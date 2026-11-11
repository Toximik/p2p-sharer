# Sharer — private torrent tracker + web UI

A small, self-contained BitTorrent tracker with a web UI for sharing your own
files with friends. Single-file Flask app, SQLite, no exotic dependencies.

## How it stays private

- **Secret announce path** — the tracker lives at `/announce/<random-secret>`;
  port scanners hitting the server see only a login page and 404s.
- **Infohash whitelist** — the tracker only answers for torrents it created
  itself, so strangers can't use it as a free open tracker.
- **`private=1` torrents** — clients disable DHT and peer exchange, so your
  swarms never leak into the public BitTorrent network.
- **Login-gated UI** — the admin creates an account per friend.
- `noindex` on all pages, in case a URL ever leaks to a crawler.

The one thing to know: **`.torrent` files contain the announce secret.** Only
share them with people you'd give access anyway. If the secret ever leaks,
delete `announce_secret` from `data/config.json`, restart, and re-create
torrents (old ones stop announcing).

## How the seeding works (no torrent client on the server!)

Every torrent embeds a **webseed** (BEP 19) URL pointing back at this server.
Torrent clients download over plain HTTP from the server *and* from each other
simultaneously — the server is a permanent seed without speaking the
BitTorrent wire protocol. qBittorrent, Transmission 4+, Deluge and anything
libtorrent-based all support webseeds.

## Run it

```sh
python -m venv venv
venv/bin/pip install -r requirements.txt        # Windows: venv\Scripts\pip
venv/bin/python app.py                          # listens on 0.0.0.0:8080
```

First visit shows a one-time setup page: set the **public base URL** (the
address friends will use, e.g. `http://203.0.113.5:8080`), the **shared
files directory** (where the files you want to share already live, e.g.
`/srv/media`), and create the admin account. Get the base URL right — it is
baked into every torrent.

To share something, open **Add file**, browse the shared directory, and hit
“Create torrent” on a file or “Share folder” on a directory — everything is
hashed in place, never copied or moved. Folder torrents include all files
inside (recursively), skipping hidden files and symlinks.

Environment variables: `SHARER_DATA` (data directory, default `./data`),
`SHARER_HOST`, `SHARER_PORT`, and optionally `SHARER_BASE_URL` /
`SHARER_FILES_ROOT` to pre-fill the setup page.

## Run it in Docker

```sh
cp .env.example .env      # set SHARER_FILES (host dir to share) and SHARER_BASE_URL
docker compose up -d --build
docker compose logs -f    # "Sharer listening on http://0.0.0.0:8080"
```

Open `http://<host>:8080` and finish the setup page — the shared files
directory is pre-filled with `/srv/files`, which is where the compose file
mounts `SHARER_FILES` (read-only). All state (SQLite DB, `config.json` with
the generated secrets) lives in the `sharer-data` volume; nothing secret is
baked into the image.

The container runs as UID/GID 1000. The shared files must be readable by
that user; to use a different one, build with
`docker compose build --build-arg UID=$(id -u) --build-arg GID=$(id -g)`.
If you swap the named volume for a bind mount, `chown` it to that UID.

Behind nginx, publish only on localhost (`"127.0.0.1:8080:8080"`), follow the
nginx/HTTPS steps below, and tick **“Behind a reverse proxy”** in Settings.
For fail2ban, run the container with the `journald` logging driver and match
on `CONTAINER_NAME=sharer` instead of the systemd unit.

## Deploy on Debian behind nginx

### 1. Install the app

```sh
sudo useradd -r -m -d /opt/sharer sharer
sudo rsync -a --exclude venv --exclude data ./ /opt/sharer/app/   # from your machine: rsync -a ... user@server:/tmp/sharer first
sudo chown -R sharer:sharer /opt/sharer
cd /opt/sharer/app
sudo apt install python3-venv
sudo -u sharer python3 -m venv venv
sudo -u sharer venv/bin/pip install -r requirements.txt
```

The `sharer` user needs read access to your shared files directory
(e.g. `sudo usermod -aG media sharer`, or make the files world-readable).

### 2. systemd service

`/etc/systemd/system/sharer.service` — note it binds to localhost only;
nginx is the public face:

```ini
[Unit]
Description=Sharer private tracker
After=network.target

[Service]
User=sharer
WorkingDirectory=/opt/sharer/app
ExecStart=/opt/sharer/app/venv/bin/python app.py
Restart=on-failure
Environment=SHARER_HOST=127.0.0.1
Environment=SHARER_PORT=8080

[Install]
WantedBy=multi-user.target
```

```sh
sudo systemctl enable --now sharer
sudo systemctl status sharer      # should say "Sharer listening on http://127.0.0.1:8080"
```

### 3. nginx site

`/etc/nginx/sites-available/sharer`:

```nginx
server {
    listen 80;
    server_name share.example.com;      # your domain, or the server IP

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
        # don't spool multi-GB webseed downloads to disk:
        proxy_buffering off;
    }
}
```

```sh
sudo ln -s /etc/nginx/sites-available/sharer /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

In Sharer's **Settings**, tick **“Behind a reverse proxy”** — otherwise the
tracker records every peer's IP as 127.0.0.1 and peers can't find each other.

### 4. HTTPS with Let's Encrypt (needs a domain)

```sh
sudo apt install certbot python3-certbot-nginx
sudo certbot --nginx -d share.example.com
```

Certbot rewrites the nginx site for TLS and auto-renews. Then set the base
URL in Settings to `https://share.example.com` (only affects new torrents —
create your torrents after this is done).

No domain, just a bare IP? Torrent clients won't accept self-signed
certificates, so skip HTTPS and use `http://your.ip` as the base URL —
everything works, it's just not encrypted in transit. Free options like
[DuckDNS](https://www.duckdns.org) give you a subdomain for a static IP if
you want TLS without buying a domain.

### Firewall

Only nginx needs to be reachable — 8080 stays internal:

```sh
sudo ufw allow 80,443/tcp
```

### Bots and brute force

A public HTTPS hostname gets scanned within days — that's normal and
handled: vulnerability probes hit 404s, and the login form locks an IP out
for 15 minutes after 5 failed attempts (HTTP 429, no resources spent).
Every failure is logged to the journal, so you can optionally have
**fail2ban** ban repeat offenders at the firewall:

`/etc/fail2ban/filter.d/sharer.conf`:

```ini
[Definition]
failregex = sharer-auth: .* from <HOST>\s*$
journalmatch = _SYSTEMD_UNIT=sharer.service
```

`/etc/fail2ban/jail.d/sharer.conf`:

```ini
[sharer]
enabled = true
backend = systemd
filter = sharer
port = http,https
maxretry = 10
findtime = 1h
bantime = 1d
```

```sh
sudo apt install fail2ban
sudo systemctl reload fail2ban
sudo fail2ban-client status sharer      # check it's watching
```

Note: fail2ban bans the IP reported in the log line, which behind nginx is
the `X-Forwarded-For` address — make sure "Behind a reverse proxy" is
ticked in Settings so real client IPs get logged (and banned).

## Friends' quick start

1. Log in with the account you made them, download the `.torrent`.
2. Open it in qBittorrent / Transmission / Deluge.
3. It downloads from the server (webseed) plus any other peers. Leaving the
   client running afterwards seeds for others — nice but optional, the server
   always seeds.

## Notes & limits

- A torrent is a snapshot: renaming, editing or deleting files inside a
  shared folder breaks that torrent (delete it and share the folder again).
- Removing a torrent in the UI never deletes the underlying file.
- Peer list lives in memory — a restart forgets peers until their next
  announce (at most 30 min); harmless.
