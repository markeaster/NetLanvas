# NetLanvas build image for Anthropic's OSS Scanner.
#
# tools/ping_sweep_helper and tools/snmp_helper are Windows-only and
# macOS-only replacements respectively (see their own //go:build tags) for
# functionality that on Linux just shells out to the system fping/net-snmp
# CLI tools instead -- they are NOT part of the Linux/Docker build at all,
# so they are deliberately not built here. The real network-input-parsing
# surface on this platform is Python: src/engine/snmp_adapter.py and
# src/pollers/ping_sweeper.py parse the text output of those system tools.
FROM python:3.12-slim
ENV DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -y --no-install-recommends \
      fping iproute2 snmp nmap curl libffi-dev \
    && rm -rf /var/lib/apt/lists/*

# scanner contract: the checkout lives inside the image, at /src
COPY . /src
WORKDIR /src

RUN pip install --no-cache-dir -r requirements.txt

# Cheap build-sanity check: every Python source file at least parses. There is
# no automated test suite in this repository yet (see threat_model.md) so this
# is the extent of "run the cheap tests" available right now. A failure here
# fails the build, same as the README's contract.
RUN python -m compileall -q src
