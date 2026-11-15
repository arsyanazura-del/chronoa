# Chronoa

Lightweight Linux monitoring and Pterodactyl backup control. The Go agent reads `/proc`, `/sys`, and mounted filesystem statistics on demand; a small background sample runs every 30 seconds so Timeline alerts and metric history continue while the dashboard is closed.

## Run

Requires Go 1.24 or newer. `CHRONOA_ADMIN_PASSWORD` is required at startup and must be a new password of at least 14 characters. Do not reuse the password previously shared in chat. Set it in a protected environment file, never in source control or command-line arguments.

```sh
go test ./...
go build -trimpath -ldflags="-s -w" -o chronoa .
./chronoa
```

The dashboard defaults to `http://127.0.0.1:8787`. On first login, enroll an authenticator app and save the one-time recovery codes. TOTP setup state is stored in `auth.json` with owner-only permissions; sessions are memory-only. Use HTTPS through a reverse proxy for remote access, preserve the original `Host` header, or use an SSH tunnel for local access.

Pterodactyl integration uses `PTERODACTYL_URL` and `PTERODACTYL_API_KEY`. The API key stays server-side; create a Client API key in Pterodactyl with only the required server and backup permissions. If unset, monitoring and login still work while Backup Manager stays disabled. Chronoa uses the backup destination and limits configured in Pterodactyl.

Timeline events persist in `./data/events.json` (up to 500 events). CPU alerts trigger at 85%, memory at 90% (critical at 95%), filesystem usage at 85%, and CPU temperature at 80 C. Thresholds currently use built-in defaults. To view the dashboard from another machine, open an SSH tunnel:

```sh
ssh -L 8787:127.0.0.1:8787 user@your-server
```

Then open `http://127.0.0.1:8787` locally. The agent binds to loopback by default; do not expose the unauthenticated metrics endpoint directly to the internet.

## Run with systemd

Build the binary on the server, then install it and the included unit:

```sh
sudo install -o root -g root -m 0755 chronoa /usr/local/bin/chronoa
sudo useradd --system --no-create-home --shell /usr/sbin/nologin chronoa
sudo install -d -o root -g root -m 0700 /etc/chronoa
sudo install -o root -g root -m 0600 /dev/null /etc/chronoa/chronoa.env
sudoedit /etc/chronoa/chronoa.env
sudo install -m 0644 chronoa.service /etc/systemd/system/chronoa.service
sudo systemctl daemon-reload
sudo systemctl enable --now chronoa
```

Put `CHRONOA_ADMIN_PASSWORD`, `PTERODACTYL_URL=https://panel.rsynzr.cloud`, and `PTERODACTYL_API_KEY` in `/etc/chronoa/chronoa.env`. Enter a newly rotated password and the API key directly on the server; do not send them in chat. The service runs without root privileges, restarts on failure, and stays bound to localhost. Check it with `systemctl status chronoa` and `journalctl -u chronoa`.

## Scope

Current metrics are collected from the local Linux host: CPU and per-core utilization, RAM and swap, mounted filesystems, network counters and rates, uptime, load, process count, TCP connections, and CPU-labeled temperature sensors when available. Compact metric samples are written every 30 seconds to daily JSONL files and pruned after 30 days; the CPU chart offers 1m, 5m, 1h, 24h, and 30d ranges. The Timeline stores alert transitions locally and retains the latest 500 events. Unsupported temperature sensors show `N/A`.

Backup Manager lists authorized Pterodactyl servers, displays their backups, and can request a manual backup. Pterodactyl/Wings performs and stores the backup; Chronoa does not copy Docker host volumes directly. The console link opens the official per-server Pterodactyl console. Chronoa intentionally has no unrestricted host-root terminal, backup deletion/restore, or automatic backup scheduler yet. SMART/IOPS, service monitoring, notification delivery, and central multi-server management remain future work.