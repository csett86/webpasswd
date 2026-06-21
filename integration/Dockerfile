# -----------------------------------------------------------------------
# Stage 1 – build the webpasswd binary inside a Go toolchain image so
# that the correct glibc version and CGO PAM bindings are guaranteed.
# -----------------------------------------------------------------------
FROM golang:1.25-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
        libpam0g-dev \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=1 go build -o /webpasswd .

# -----------------------------------------------------------------------
# Stage 2 – minimal Debian image with systemd so the binary can be run
# under the provided webpasswd.service unit exactly as in production.
# -----------------------------------------------------------------------
FROM debian:trixie

ENV container=docker \
    DEBIAN_FRONTEND=noninteractive

RUN apt-get update && apt-get install -y --no-install-recommends \
        systemd \
        systemd-sysv \
        libpam0g \
        libpam-pwquality \
        cracklib-runtime \
        passwd \
    && rm -rf /var/lib/apt/lists/*

# Remove unused systemd units to speed up container boot.
RUN rm -f \
        /lib/systemd/system/multi-user.target.wants/* \
        /etc/systemd/system/*.wants/* \
        /lib/systemd/system/local-fs.target.wants/* \
        /lib/systemd/system/sockets.target.wants/*udev* \
        /lib/systemd/system/sockets.target.wants/*initctl* \
        /lib/systemd/system/basic.target.wants/* \
        /lib/systemd/system/systemd-update-utmp* \
    2>/dev/null; true

# Create the integration-test user before systemd starts the service so the
# service's filesystem view includes the account database entry.
RUN useradd -m webtest && echo 'webtest:OldPass1234!' | chpasswd

# Install the webpasswd binary.
COPY --from=builder /webpasswd /usr/local/bin/webpasswd
COPY pam.d/webpasswd /etc/pam.d/webpasswd

# Populate the working directory required by the systemd unit.
RUN mkdir -p /etc/webpasswd
COPY templates/ /etc/webpasswd/templates/
COPY static/    /etc/webpasswd/static/

# Install and enable the systemd unit exactly as shipped in the repository.
COPY webpasswd.service /etc/systemd/system/webpasswd.service
RUN mkdir -p /etc/systemd/system/multi-user.target.wants \
    && ln -sf /etc/systemd/system/webpasswd.service \
              /etc/systemd/system/multi-user.target.wants/webpasswd.service

STOPSIGNAL SIGRTMIN+3
CMD ["/lib/systemd/systemd"]
