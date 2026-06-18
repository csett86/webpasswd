# webpasswd
A simple web app to change your own local password, just like passwd on the cli

## Features

- Change a local Unix user password through a browser form
- Authentication and password change enforced by PAM (`/etc/pam.d/passwd`)
- Per-IP rate limiting (configurable, default: 5 attempts / 15 minutes)
- No JavaScript — pure HTML + CSS
- Single static Go binary (CGO required for libpam)
- Security headers: CSP, X-Frame-Options, X-Content-Type-Options

## Requirements

- Linux with PAM (`libpam0g`)
- Build: `libpam0g-dev`
- Go 1.22+

## Build

```sh
sudo apt-get install libpam0g-dev   # Debian/Ubuntu
go build -o webpasswd .
```

## Run

```sh
# Must run as root (or with sufficient PAM privileges) to read/write /etc/shadow
sudo ./webpasswd -addr :8080
```

### Flags

| Flag | Default | Description |
|------|---------|-------------|
| `-addr` | `:8080` | TCP address to listen on |
| `-rate-limit` | `5` | Max password-change attempts per IP per window |
| `-rate-window` | `15m` | Sliding window duration for rate limiting |
| `-x-forwarded-for` | `false` | Trust `X-Forwarded-For` / `X-Real-IP` headers (enable when behind a reverse proxy) |

## systemd

Install the unit file and web assets:

```sh
sudo cp webpasswd /usr/local/bin/
sudo mkdir -p /etc/webpasswd
sudo cp -r templates static /etc/webpasswd/
sudo cp webpasswd.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now webpasswd
```

## Reverse proxy

webpasswd does **not** terminate TLS. Put it behind nginx, Caddy, or a similar
reverse proxy that handles HTTPS. Enable `-x-forwarded-for` so rate limiting
uses the real client IP:

```
# nginx example
location / {
    proxy_pass http://127.0.0.1:8080;
    proxy_set_header X-Real-IP $remote_addr;
}
```

## Security notes

- The process **must run as root** (or have `CAP_SETUID`/`CAP_SETGID`) so PAM
  can authenticate users and update `/etc/shadow`.
- Rate limiting is per-IP and in-memory; it resets on restart.
- Passwords are never logged.
- `html/template` is used to auto-escape all output (XSS protection).

## Testing

```sh
go test ./...
```

Integration testing against real PAM requires a system with a known user
account and shadow entry.
