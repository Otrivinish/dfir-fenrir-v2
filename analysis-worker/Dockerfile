FROM python:3.12-slim

WORKDIR /app

# System tools.
# - tshark: PCAP analysis
# - binutils: strings(1) for ASCII/Unicode extraction
# - libimage-exiftool-perl: metadata extraction for all file types
# - libmagic1: MIME detection (python-magic)
# - libyara-dev: YARA rule engine headers for yara-python
RUN apt-get update && apt-get install -y --no-install-recommends \
    binutils \
    file \
    libimage-exiftool-perl \
    libmagic1 \
    libyara-dev \
    tshark \
    && rm -rf /var/lib/apt/lists/*

RUN pip install --no-cache-dir \
    fastapi==0.115.6 \
    "uvicorn[standard]==0.34.0" \
    python-magic==0.4.27 \
    python-multipart==0.0.20 \
    pefile==2023.2.7 \
    oletools==0.60.2 \
    pdfminer.six==20231228 \
    yara-python==4.5.1 \
    exifread==3.0.0

COPY worker.py .

# Non-root, no capabilities — same uid as v1 so the air-gapped network
# /tmp:noexec mount and quarantine read-only volume keep the same posture.
RUN useradd -m -u 1002 analyst \
    && chown -R analyst:analyst /app \
    && mkdir -p /quarantine /yara-rules \
    && chown analyst:analyst /quarantine /yara-rules
USER analyst

EXPOSE 8001
CMD ["uvicorn", "worker:app", "--host", "0.0.0.0", "--port", "8001"]
