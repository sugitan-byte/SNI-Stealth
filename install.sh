#!/usr/bin/env bash
#
# SNI-Stealth — one-click VPS installer.
#
#   curl -fsSL https://raw.githubusercontent.com/sugitan-byte/SNI-Stealth/main/install.sh | sudo bash
#
# or, from a checkout:  sudo ./install.sh
#
# Installs a JDK, builds the server, generates a self-signed cert, writes the config,
# installs a systemd service, opens the firewall, and prints the client settings.
#
# Non-interactive overrides (env vars):
#   PORT=443 TOKEN=... SNI=m.google.com FALLBACK=forward FORWARD_HOST=mpu-ecommerce.com \
#   FORWARD_PORT=443 FORWARD_TLS=auto BRIDGE=socks5 REPO_URL=... INSTALL_DIR=/opt/sni-stealth
#
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/sugitan-byte/SNI-Stealth.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sni-stealth}"
SERVICE="sni-stealth"

log()  { printf '\033[1;36m[sni-stealth]\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[sni-stealth]\033[0m %s\n' "$*"; }
die()  { printf '\033[1;31m[sni-stealth]\033[0m %s\n' "$*" >&2; exit 1; }

[ "$(id -u)" -eq 0 ] || die "Run as root (use sudo)."

# ---------------------------------------------------------------- package manager
if   command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf     >/dev/null 2>&1; then PM=dnf
elif command -v yum     >/dev/null 2>&1; then PM=yum
else die "No supported package manager (apt/dnf/yum) found."; fi

install_pkgs() {
  case "$PM" in
    apt) apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@";;
    dnf) dnf install -y "$@";;
    yum) yum install -y "$@";;
  esac
}

# ---------------------------------------------------------------- dependencies (JDK, git, curl)
log "Installing dependencies (JDK 17, git, curl)…"
if [ "$PM" = "apt" ]; then
  install_pkgs openjdk-17-jdk-headless git curl ca-certificates
else
  install_pkgs java-17-openjdk-devel git curl ca-certificates
fi
command -v javac  >/dev/null 2>&1 || die "javac not found after install."
command -v keytool>/dev/null 2>&1 || die "keytool not found after install."
JAVA_BIN="$(readlink -f "$(command -v java)")"
log "Java: $JAVA_BIN"

# ---------------------------------------------------------------- get the source
SELF_SRC=""
# When run from a checkout, use it. $0 resolution is best-effort (won't exist under curl|bash).
if [ -f "src/com/kokovpn/stealth/server/StealthServer.java" ]; then
  SELF_SRC="$(pwd)"
elif [ -n "${BASH_SOURCE:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/src/com/kokovpn/stealth/server/StealthServer.java" ]; then
  SELF_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

mkdir -p "$INSTALL_DIR"
if [ -n "$SELF_SRC" ] && [ "$SELF_SRC" != "$INSTALL_DIR" ]; then
  log "Copying source from $SELF_SRC to $INSTALL_DIR…"
  cp -R "$SELF_SRC"/. "$INSTALL_DIR"/
elif [ ! -f "$INSTALL_DIR/src/com/kokovpn/stealth/server/StealthServer.java" ]; then
  log "Cloning $REPO_URL…"
  tmp="$(mktemp -d)"
  git clone --depth 1 "$REPO_URL" "$tmp"
  cp -R "$tmp"/. "$INSTALL_DIR"/
  rm -rf "$tmp"
fi
cd "$INSTALL_DIR"

# ---------------------------------------------------------------- build
log "Building…"
rm -rf out
mkdir -p out
find src -name '*.java' > /tmp/sni_sources.txt
javac -source 8 -target 8 -Xlint:none -d out @/tmp/sni_sources.txt
rm -f /tmp/sni_sources.txt
log "Built to $INSTALL_DIR/out"

# ---------------------------------------------------------------- settings (env or prompt)
prompt() { # prompt VAR "question" "default"
  local __var="$1" __q="$2" __def="$3" __ans
  if [ -n "${!__var:-}" ]; then return; fi
  if [ -t 0 ]; then
    read -r -p "$__q [$__def]: " __ans || true
    printf -v "$__var" '%s' "${__ans:-$__def}"
  else
    printf -v "$__var" '%s' "$__def"
  fi
}

PUBIP="$(curl -fsS4 https://api.ipify.org 2>/dev/null || echo YOUR_VPS_IP)"
prompt PORT         "Listen port"                 "443"
prompt SNI          "Front / SNI domain"          "m.google.com"
prompt FALLBACK     "Fallback (http200|forward)"  "forward"
prompt FORWARD_HOST "Decoy origin host"           "mpu-ecommerce.com"
prompt FORWARD_PORT "Decoy origin port"           "443"
prompt FORWARD_TLS  "Forward TLS to decoy (auto|true|false)" "auto"
prompt BRIDGE       "Bridge (socks5|websocket)"   "socks5"
if [ -z "${TOKEN:-}" ]; then
  TOKEN="$(head -c32 /dev/urandom | od -An -tx1 | tr -d ' \n')"
  log "Generated auth token."
fi

# ---------------------------------------------------------------- keystore
if [ ! -f "$INSTALL_DIR/server.p12" ]; then
  log "Generating self-signed certificate…"
  keytool -genkeypair -alias stealth -keyalg RSA -keysize 2048 -validity 3650 \
          -storetype PKCS12 -keystore "$INSTALL_DIR/server.p12" -storepass changeit \
          -dname "CN=${SNI}" >/dev/null 2>&1
fi

# ---------------------------------------------------------------- config
log "Writing server.properties…"
cat > "$INSTALL_DIR/server.properties" <<CFG
listenPort=${PORT}
useTls=true
keystorePath=${INSTALL_DIR}/server.p12
keystorePass=changeit
token=${TOKEN}
bridge=${BRIDGE}
fallback=${FALLBACK}
forwardHost=${FORWARD_HOST}
forwardPort=${FORWARD_PORT}
forwardTls=${FORWARD_TLS}
workerThreads=512
CFG
chmod 600 "$INSTALL_DIR/server.properties"

# ---------------------------------------------------------------- bind privileged ports w/o root
if [ "$PORT" -lt 1024 ]; then
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' "$JAVA_BIN" 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------- systemd service
log "Installing systemd service…"
cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=SNI-Stealth tunnel server
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${JAVA_BIN} -cp ${INSTALL_DIR}/out com.kokovpn.stealth.server.StealthServer --config ${INSTALL_DIR}/server.properties
Restart=always
RestartSec=3
User=root
NoNewPrivileges=true

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"

# ---------------------------------------------------------------- firewall
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

sleep 1
# ---------------------------------------------------------------- summary
STATE="$(systemctl is-active "$SERVICE" 2>/dev/null || echo unknown)"
cat <<SUMMARY

============================================================
  SNI-Stealth server is installed.  Service: ${STATE}
============================================================
  Server IP        : ${PUBIP}
  Port             : ${PORT}
  Token            : ${TOKEN}
  Bridge           : ${BRIDGE}
  Fallback         : ${FALLBACK}  (${FORWARD_HOST}:${FORWARD_PORT}, tls=${FORWARD_TLS})

  --- Enter these in the KoKo VPN admin (Stealth network + server) ---
  Server ServerIP      : ${PUBIP}
  Server TcpPort       : ${PORT}
  Network StealthSni   : ${SNI}
  Network StealthToken : ${TOKEN}
  Network StealthBridge: ${BRIDGE}
  Network StealthUseTls: true

  Logs   : journalctl -u ${SERVICE} -f
  Restart: systemctl restart ${SERVICE}
  Probe  : curl -k https://${PUBIP}:${PORT}/   (should show the decoy site, no token)
============================================================
SUMMARY
