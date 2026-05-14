#!/usr/bin/env bash
# scripts/install_voice.sh
# =========================
# One-shot voice-stack installer for Z620 (or any Linux deployment).
#
# Usage:
#     cd /opt/super-tanks
#     git pull
#     sudo bash scripts/install_voice.sh
#
# Idempotent — safe to re-run after a fresh git pull.
#
# What it does:
#   1. apt-get install runtime audio dependencies
#   2. pip install faster-whisper into the project venv
#   3. download Piper TTS binary + Norwegian voice models
#   4. write a systemd unit for the voice runner
#   5. print the env vars the operator must set in their
#      /etc/super-tanks/env file
#
# What it does NOT do:
#   - mint a Home Assistant token (operator action; HA UI)
#   - place Wyoming satellites in rooms (physical install)
#   - configure config/voice_rooms.json — run
#     `python -m scripts.voice_discover --scan-ha` for that and edit
#     the JSON to taste

set -euo pipefail

readonly PROJECT_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
readonly PIPER_DIR="${PROJECT_ROOT}/vendor/piper"
readonly PIPER_VERSION="1.2.0"
readonly PIPER_PLATFORM="linux_x86_64"
readonly PIPER_URL="https://github.com/rhasspy/piper/releases/download/v${PIPER_VERSION}/piper_${PIPER_PLATFORM}.tar.gz"
readonly MODEL_DIR="${PROJECT_ROOT}/vendor/piper-models"
# Adjust the model names if your distro of choice differs.
readonly NB_MODEL_URL="https://huggingface.co/rhasspy/piper-voices/resolve/main/no/no_NO/talesyntese/medium/no_NO-talesyntese-medium.onnx"
readonly NB_CONFIG_URL="https://huggingface.co/rhasspy/piper-voices/resolve/main/no/no_NO/talesyntese/medium/no_NO-talesyntese-medium.onnx.json"

readonly SYSTEMD_UNIT="/etc/systemd/system/super-tanks-voice.service"
readonly ENV_FILE="/etc/super-tanks/env"

log() { printf "[install_voice] %s\n" "$*"; }
warn() { printf "[install_voice] WARN: %s\n" "$*" >&2; }
die() { printf "[install_voice] FAIL: %s\n" "$*" >&2; exit 1; }

require_root() {
  [[ ${EUID} -eq 0 ]] || die "must run as root (use sudo)"
}

apt_deps() {
  log "Installing apt dependencies"
  apt-get update
  apt-get install -y --no-install-recommends \
    python3-venv \
    python3-pip \
    ffmpeg \
    alsa-utils \
    pulseaudio-utils \
    ca-certificates \
    curl
}

ensure_venv() {
  local venv="${PROJECT_ROOT}/.venv"
  if [[ ! -d "${venv}" ]]; then
    log "Creating venv at ${venv}"
    python3 -m venv "${venv}"
  fi
  log "Upgrading pip + installing faster-whisper"
  "${venv}/bin/pip" install --upgrade pip setuptools wheel
  "${venv}/bin/pip" install --upgrade faster-whisper
}

download_piper() {
  mkdir -p "${PIPER_DIR}"
  if [[ -x "${PIPER_DIR}/piper/piper" ]]; then
    log "Piper already installed at ${PIPER_DIR}/piper/piper"
    return
  fi
  log "Downloading Piper ${PIPER_VERSION}"
  curl -fsSL "${PIPER_URL}" -o "${PIPER_DIR}/piper.tar.gz"
  tar -xzf "${PIPER_DIR}/piper.tar.gz" -C "${PIPER_DIR}"
  rm "${PIPER_DIR}/piper.tar.gz"
}

download_models() {
  mkdir -p "${MODEL_DIR}"
  if [[ ! -f "${MODEL_DIR}/no_NO-talesyntese-medium.onnx" ]]; then
    log "Downloading Norwegian Piper model"
    curl -fsSL "${NB_MODEL_URL}" -o "${MODEL_DIR}/no_NO-talesyntese-medium.onnx"
    curl -fsSL "${NB_CONFIG_URL}" -o "${MODEL_DIR}/no_NO-talesyntese-medium.onnx.json"
  else
    log "Norwegian Piper model already present"
  fi
}

write_systemd_unit() {
  log "Writing ${SYSTEMD_UNIT}"
  cat >"${SYSTEMD_UNIT}" <<UNIT
[Unit]
Description=Super Tanks Voice Runner
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${PROJECT_ROOT}
ExecStart=${PROJECT_ROOT}/.venv/bin/python -m scripts.voice_runner
Restart=on-failure
RestartSec=5

# Confining the daemon — its only job is to bridge audio in/out.
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=true
ProtectSystem=full
ReadWritePaths=${PROJECT_ROOT}/data ${PROJECT_ROOT}/config

[Install]
WantedBy=multi-user.target
UNIT
  systemctl daemon-reload
}

ensure_env_template() {
  mkdir -p "$(dirname "${ENV_FILE}")"
  if [[ -f "${ENV_FILE}" ]]; then
    log "Env file already exists at ${ENV_FILE}; not overwriting"
    return
  fi
  log "Writing template ${ENV_FILE}"
  cat >"${ENV_FILE}" <<ENV
# Super Tanks voice runner env. Edit before starting the service.

# Required: Piper TTS
ST_PIPER_BIN=${PIPER_DIR}/piper/piper
ST_PIPER_MODEL_DIR=${MODEL_DIR}

# Required: Whisper STT (download a faster-whisper model to this path)
# e.g. https://huggingface.co/Systran/faster-whisper-large-v3
ST_WHISPER_MODEL=/opt/super-tanks/vendor/whisper-large-v3
ST_WHISPER_DEVICE=cpu
ST_WHISPER_LANG=no

# Required: Home Assistant for media_player routing
HOMEASSISTANT_URL=http://hass.local:8123
HOMEASSISTANT_TOKEN=REPLACE_WITH_LONG_LIVED_TOKEN

# Optional: override the default voice ids
# ST_VOICE_AERIS=nb_NO-talesyntese-medium
# ST_VOICE_ZEPH=nb_NO-talesyntese-medium#1
# ST_VOICE_LANG=nb_NO

# Upstream model fingerprint (drives the tier-rebaseline gate)
# ST_UPSTREAM_MODEL=claude-opus-4-7

# Self-heal: opt-in for automatic dep upgrades. Default OFF.
# ST_ZEPH_AUTO_APPLY_DEPS=0
ENV
  chmod 0640 "${ENV_FILE}"
}

print_next_steps() {
  cat <<NEXT

Voice install complete. Next steps:

  1. Edit ${ENV_FILE} and replace REPLACE_WITH_LONG_LIVED_TOKEN with
     a Home Assistant long-lived access token.

  2. Download a faster-whisper model:
       mkdir -p /opt/super-tanks/vendor/whisper-large-v3
       # See https://huggingface.co/Systran/faster-whisper-large-v3
     (or use a smaller variant; update ST_WHISPER_MODEL in ${ENV_FILE})

  3. Generate the room map:
       cd ${PROJECT_ROOT}
       ./.venv/bin/python -m scripts.voice_discover --scan-ha \\
           > config/voice_rooms.json
       \$EDITOR config/voice_rooms.json   # review + clean up hints

  4. Verify the setup:
       ./.venv/bin/python -m scripts.voice_discover --check

  5. Start the service:
       systemctl enable --now super-tanks-voice.service
       journalctl -u super-tanks-voice -f

NEXT
}

main() {
  require_root
  apt_deps
  ensure_venv
  download_piper
  download_models
  write_systemd_unit
  ensure_env_template
  print_next_steps
}

main "$@"
