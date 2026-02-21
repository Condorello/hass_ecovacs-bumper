#!/usr/bin/env bash
set -euo pipefail

echo "[bumper] starting"

# =========================
# PATH FISSI
# =========================
CERTS_DIR="/addon_configs/ecovacs_bumper/certs"
DATA_DIR="/addon_configs/ecovacs_bumper/data"

# =========================
# DATA DIRECTORY
# =========================
mkdir -p "${DATA_DIR}"

mkdir -p /bumper
rm -rf /bumper/data
ln -s "${DATA_DIR}" /bumper/data

export BUMPER_DATA="/bumper/data"

echo "[bumper] BUMPER_DATA=${BUMPER_DATA}"
ls -la /bumper || true
ls -la /bumper/data || true

# =========================
# CERTIFICATES
# =========================
echo "[bumper] certs dir: ${CERTS_DIR}"
ls -la "${CERTS_DIR}" || true

export BUMPER_CERTS="${CERTS_DIR}"
export BUMPER_CA="${CERTS_DIR}/ca.crt"
export BUMPER_CERT="${CERTS_DIR}/bumper.crt"
export BUMPER_KEY="${CERTS_DIR}/bumper.key"

# Fail-fast
test -f "${BUMPER_CA}"   || { echo "[bumper] Missing ${BUMPER_CA}"; exit 1; }
test -f "${BUMPER_CERT}" || { echo "[bumper] Missing ${BUMPER_CERT}"; exit 1; }
test -f "${BUMPER_KEY}"  || { echo "[bumper] Missing ${BUMPER_KEY}"; exit 1; }

# =========================
# AVVIO
# =========================
cd /opt/bumper
exec /opt/venv/bin/python -m bumper