# Standalone diagnostic image -- deliberately NOT based on or sharing
# layers with the main NetLanvas Dockerfile. This never runs real
# NetLanvas code; keeping it fully separate means it can't accidentally
# pick up main-app behavior/dependencies that would muddy what it's
# actually testing.

# Builder stage -- cross-compiles the WIN-9 proof-of-concept SNMP helper
# (netlanvas_snmp_helper) for Windows and Mac. Pure-Go (gosnmp has no C
# dependency), so this cross-compiles cleanly with just GOOS/GOARCH --
# no Windows build machine or C toolchain needed. Built fresh every
# image build, not vendored as a binary in the repo, so the source is
# always what's actually running.
FROM golang:1.24-bookworm AS snmp-helper-builder
WORKDIR /build
COPY snmp_helper/go.mod ./
COPY snmp_helper/main.go .
RUN go mod tidy
RUN CGO_ENABLED=0 GOOS=windows GOARCH=amd64 go build -o netlanvas_snmp_helper.exe main.go
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -o netlanvas_snmp_helper_mac_arm64 main.go
RUN CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -o netlanvas_snmp_helper_mac_amd64 main.go

FROM python:3.12-slim

RUN apt-get update && apt-get install -y --no-install-recommends openssh-client \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY readiness_check.py .
COPY --from=snmp-helper-builder /build/netlanvas_snmp_helper.exe /app/bin/netlanvas_snmp_helper.exe
COPY --from=snmp-helper-builder /build/netlanvas_snmp_helper_mac_arm64 /app/bin/netlanvas_snmp_helper_mac_arm64
COPY --from=snmp-helper-builder /build/netlanvas_snmp_helper_mac_amd64 /app/bin/netlanvas_snmp_helper_mac_amd64

ENTRYPOINT ["python3", "readiness_check.py"]
