# syntax=docker/dockerfile:1

# ── Build stage ──────────────────────────────────────────────────────────────
FROM golang:1.22-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpam0g-dev \
 && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=1 go build -trimpath -ldflags="-s -w" -o /webpasswd .

# ── Runtime stage ─────────────────────────────────────────────────────────────
FROM debian:bookworm-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    libpam-runtime \
    libpam0g \
 && rm -rf /var/lib/apt/lists/*

# Copy the binary and web assets.
COPY --from=builder /webpasswd /usr/local/bin/webpasswd
COPY templates/ /etc/webpasswd/templates/
COPY static/   /etc/webpasswd/static/

WORKDIR /etc/webpasswd
EXPOSE 8080

# The container must run as root (or a user with CAP_SETUID/CAP_SETGID) so
# that PAM can authenticate and change shadow passwords. Restrict this in your
# orchestration layer (e.g. grant only the required Linux capabilities).
ENTRYPOINT ["/usr/local/bin/webpasswd"]
CMD ["-addr", ":8080"]
