FROM python:3.12-slim@sha256:f77ac9e44ae96ef2c90b8053ea08c31f8be030f824196b0ae4db6d462c84e51f

WORKDIR /app

# System tools.
# - tshark: PCAP analysis
# - binutils: strings(1) for ASCII/Unicode extraction
# - libimage-exiftool-perl: metadata extraction for all file types
# - libmagic1: MIME detection (python-magic)
# - libyara-dev: YARA rule engine headers for yara-python
# `apt-get upgrade`: the base digest is pinned and upstream image rebuilds lag
# Debian security fixes (PCRE2), so a --no-cache rebuild takes them.
RUN apt-get update && apt-get upgrade -y \
    && apt-get install -y --no-install-recommends \
    binutils \
    libimage-exiftool-perl \
    libmagic1 \
    libyara-dev \
    tshark \
    && rm -rf /var/lib/apt/lists/*

# Hash-locked install (requirements.txt → requirements.lock via scripts/lock-python.sh).
COPY requirements.lock ./
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY worker.py .

# Non-root, no capabilities — same uid as v1 so the air-gapped network
# /tmp:noexec mount and quarantine read-only volume keep the same posture.
# The code stays root-owned: the process that parses hostile files must not be
# able to rewrite worker.py (the rootfs is read-only in compose as well).
RUN useradd -m -u 1002 analyst \
    && mkdir -p /quarantine /yara-rules \
    && chown analyst:analyst /quarantine /yara-rules
USER 1002:1002

EXPOSE 8001
CMD ["uvicorn", "worker:app", "--host", "0.0.0.0", "--port", "8001"]
