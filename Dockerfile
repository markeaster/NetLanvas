FROM python:3.12-slim
# Baked in at build time by build_multiarch.sh (--build-arg), so the
# running image is always the single source of truth for its own
# version -- no per-host docker-compose.yaml env var to keep in sync.
# See punch list: version string went stale on field deployments
# because Watchtower updates the image but never touches a host's
# local compose file.
ARG NETLANVAS_VERSION=unknown
ENV NETLANVAS_VERSION=$NETLANVAS_VERSION
RUN apt-get update && apt-get install -y fping iproute2 snmp nmap curl libffi-dev && rm -rf /var/lib/apt/lists/*
WORKDIR /app
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt
COPY src/ /app/src/
COPY defaults.json /app/static_defaults/defaults.json
COPY entrypoint.sh /app/entrypoint.sh
ENTRYPOINT ["/app/entrypoint.sh"]
