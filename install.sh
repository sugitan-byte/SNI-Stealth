#!/usr/bin/env bash
#
# SNI-Stealth — One-Click Interactive VPS Installer & Manager
#
# Usage (One-Liner on any fresh Ubuntu/Debian/CentOS VPS):
#   bash <(curl -fsSL https://raw.githubusercontent.com/sugitan-byte/SNI-Stealth/main/install.sh)
#
# Or from cloned directory:
#   sudo ./install.sh
#
set -euo pipefail

REPO_URL="${REPO_URL:-https://github.com/sugitan-byte/SNI-Stealth.git}"
INSTALL_DIR="${INSTALL_DIR:-/opt/sni-stealth}"
SERVICE="sni-stealth"

# Color formatting
C_RESET='\033[0m'
C_CYAN='\033[1;36m'
C_GREEN='\033[1;32m'
C_YELLOW='\033[1;33m'
C_RED='\033[1;31m'
C_BOLD='\033[1m'

log()  { printf "${C_CYAN}[sni-stealth]${C_RESET} %s\n" "$*"; }
info() { printf "${C_GREEN}[✓]${C_RESET} %s\n" "$*"; }
warn() { printf "${C_YELLOW}[!]${C_RESET} %s\n" "$*"; }
die()  { printf "${C_RED}[✗] ERROR:${C_RESET} %s\n" "$*" >&2; exit 1; }

# Helper to read from /dev/tty even when running via `curl ... | bash`
read_input() {
  local prompt_text="$1"
  local default_val="$2"
  local user_val=""

  if [ -c /dev/tty ]; then
    printf "${C_BOLD}%s${C_RESET} [%s]: " "$prompt_text" "$default_val" > /dev/tty
    read -r user_val < /dev/tty || true
  else
    read -r -p "$prompt_text [$default_val]: " user_val || true
  fi

  echo "${user_val:-$default_val}"
}

# ---------------------------------------------------------------- Management Menu
setprop() {
  local cfg="$INSTALL_DIR/server.properties" k="$1" v="$2"
  if grep -qE "^${k}=" "$cfg"; then
    sed -i -E "s#^${k}=.*#${k}=${v}#" "$cfg"
  else
    echo "${k}=${v}" >> "$cfg"
  fi
}

getprop() {
  grep -E "^$1=" "$INSTALL_DIR/server.properties" 2>/dev/null | head -1 | cut -d= -f2-
}

regen_cert() {
  local cn="$1"
  keytool -delete -alias stealth -keystore "$INSTALL_DIR/server.p12" -storepass changeit >/dev/null 2>&1 || true
  keytool -genkeypair -alias stealth -keyalg RSA -keysize 2048 -validity 3650 \
          -storetype PKCS12 -keystore "$INSTALL_DIR/server.p12" -storepass changeit \
          -dname "CN=${cn}, OU=IT, O=Google LLC, L=Mountain View, ST=CA, C=US" >/dev/null 2>&1 && info "Certificate regenerated (CN=${cn})."
}

manage() {
  local cfg="$INSTALL_DIR/server.properties"
  [ -f "$cfg" ] || die "No server.properties at $INSTALL_DIR — run installer first."
  
  while true; do
    local tok; tok="$(getprop token)"
    local cn; cn="$(keytool -list -v -keystore "$INSTALL_DIR/server.p12" -storepass changeit 2>/dev/null | grep -m1 'Owner:' | sed -E 's/.*CN=([^,]*).*/\1/' || echo 'unknown')"
    local active; active="$(systemctl is-active $SERVICE 2>/dev/null || echo inactive)"
    
    printf "\n${C_CYAN}============================================================${C_RESET}\n"
    printf "          ${C_BOLD}SNI-Stealth Server Management Menu${C_RESET}\n"
    printf "${C_CYAN}============================================================${C_RESET}\n"
    printf "  Service Status   : %b\n" "$([ "$active" = "active" ] && printf "${C_GREEN}RUNNING (active)${C_RESET}" || printf "${C_RED}%s${C_RESET}" "$active")"
    printf "  Listen Port      : %s\n" "$(getprop listenPort)"
    printf "  Auth Token       : %s\n" "${tok:-<none>}"
    printf "  Cert SNI / CN    : %s\n" "$cn"
    printf "  Bridge           : %s\n" "$(getprop bridge)"
    printf "  Decoy Fallback   : %s (%s:%s)\n" "$(getprop fallback)" "$(getprop forwardHost)" "$(getprop forwardPort)"
    printf "${C_CYAN}------------------------------------------------------------${C_RESET}\n"
    printf "  1) Change Listen Port          6) Change Decoy Host & Port\n"
    printf "  2) Change Auth Token           7) Change Fallback Mode (forward|http200)\n"
    printf "  3) Change Cert SNI / Domain    8) Restart Stealth Service\n"
    printf "  4) Change Bridge (socks5/ws)   9) View Realtime Live Logs\n"
    printf "  5) Check Service Status        0) Exit Menu\n"
    printf "${C_CYAN}------------------------------------------------------------${C_RESET}\n"
    
    local choice
    choice="$(read_input "Choose an option" "0")"
    case "$choice" in
      1)
        local np; np="$(read_input "Enter new listen port" "443")"
        setprop listenPort "$np"
        command -v ufw >/dev/null 2>&1 && ufw allow "$np/tcp" >/dev/null 2>&1 || true
        ;;
      2)
        local nt; nt="$(read_input "Enter new auth token" "koko-secret-token")"
        setprop token "$nt"
        ;;
      3)
        local ns; ns="$(read_input "Enter new SNI front domain" "m.google.com")"
        regen_cert "$ns"
        ;;
      4)
        local nb; nb="$(read_input "Enter bridge (socks5|websocket)" "socks5")"
        setprop bridge "$nb"
        ;;
      5)
        systemctl status $SERVICE --no-pager || true
        ;;
      6)
        local nh; nh="$(read_input "Enter new decoy host" "www.google.com")"
        local nhp; nhp="$(read_input "Enter decoy port" "443")"
        setprop forwardHost "$nh"
        setprop forwardPort "$nhp"
        ;;
      7)
        local nf; nf="$(read_input "Enter fallback (forward|http200)" "forward")"
        setprop fallback "$nf"
        ;;
      8)
        systemctl restart $SERVICE && info "Service restarted successfully!"
        ;;
      9)
        printf "${C_YELLOW}Press Ctrl+C to exit logs...${C_RESET}\n"
        journalctl -u $SERVICE -f -n 50 || true
        ;;
      0|q|exit)
        printf "Goodbye!\n"
        exit 0
        ;;
      *)
        warn "Invalid choice: $choice"
        ;;
    esac

    if [[ "$choice" =~ ^[1-4|6-7]$ ]]; then
      local apply; apply="$(read_input "Apply changes and restart service now? (y/n)" "y")"
      if [ "$apply" = "y" ] || [ "$apply" = "Y" ]; then
        systemctl restart $SERVICE && info "Applied & restarted: $(systemctl is-active $SERVICE)"
      fi
    fi
  done
}

# Check root permissions
[ "$(id -u)" -eq 0 ] || die "This script must be run as root (use sudo or login as root)."

if [ "${1:-}" = "menu" ] || [ "${1:-}" = "--menu" ]; then
  manage
  exit 0
fi

# ---------------------------------------------------------------- Banner
clear 2>/dev/null || true
printf "\n${C_CYAN}============================================================${C_RESET}\n"
printf "    ${C_BOLD}SNI-STEALTH DUAL-MODE SERVER INSTALLER (MYANMAR DPI BYPASS)${C_RESET}\n"
printf "    ${C_YELLOW}TLS 0x16 Sniffing + Plain HTTP Fallback + CloudFront Ready${C_RESET}\n"
printf "${C_CYAN}============================================================${C_RESET}\n\n"

# ---------------------------------------------------------------- Package Manager
if   command -v apt-get >/dev/null 2>&1; then PM=apt
elif command -v dnf     >/dev/null 2>&1; then PM=dnf
elif command -v yum     >/dev/null 2>&1; then PM=yum
else die "No supported package manager (apt/dnf/yum) found on this Linux system."; fi

install_pkgs() {
  case "$PM" in
    apt) apt-get update -y && DEBIAN_FRONTEND=noninteractive apt-get install -y "$@";;
    dnf) dnf install -y "$@";;
    yum) yum install -y "$@";;
  esac
}

# ---------------------------------------------------------------- Interactive Questions
log "Configuring installation options..."
PUBIP="$(curl -fsS4 https://api.ipify.org 2>/dev/null || curl -fsS4 https://icanhazip.com 2>/dev/null || echo "YOUR_VPS_IP")"

# 1. Listen Port
PORT="$(read_input "1) Enter Stealth Server Listen Port" "443")"

# 2. Secret Auth Token
DEFAULT_TOKEN="$(head -c16 /dev/urandom | od -An -tx1 | tr -d ' \n')"
TOKEN="$(read_input "2) Enter Auth Secret Token (X-Stealth-Auth)" "$DEFAULT_TOKEN")"

# 3. Fake SNI Domain
SNI="$(read_input "3) Enter Front SNI / Certificate Domain (eg: m.google.com)" "m.google.com")"

# 4. Bridge Selection
BRIDGE="$(read_input "4) Enter Bridge Backend (socks5 or websocket)" "socks5")"

# 5. Local SOCKS5 Dante Auto-Setup
SETUP_DANTE="n"
if [ "$BRIDGE" = "socks5" ]; then
  if ! ss -tulpn | grep -q ':1080 '; then
    SETUP_DANTE="$(read_input "5) No SOCKS5 on port 1080 detected. Auto-install local Dante SOCKS5 server? (y/n)" "y")"
  fi
fi

# 6. Decoy Host
FORWARD_HOST="$(read_input "6) Enter Decoy Fallback Host (for unauthorized probes)" "www.google.com")"
FORWARD_PORT="$(read_input "7) Enter Decoy Fallback Port" "443")"
FORWARD_TLS="auto"

printf "\n${C_GREEN}Configuration set. Starting installation...${C_RESET}\n\n"

# ---------------------------------------------------------------- Install Dependencies
log "Installing dependencies (JDK 17, Git, Curl, OpenSSL)..."
if [ "$PM" = "apt" ]; then
  install_pkgs openjdk-17-jdk-headless git curl ca-certificates openssl ufw
  if [ "$SETUP_DANTE" = "y" ] || [ "$SETUP_DANTE" = "Y" ]; then
    install_pkgs dante-server
  fi
else
  install_pkgs java-17-openjdk-devel git curl ca-certificates openssl
fi

JAVA_BIN="$(readlink -f "$(command -v java)" 2>/dev/null || command -v java)"
command -v javac  >/dev/null 2>&1 || die "javac compiler not found."
command -v keytool>/dev/null 2>&1 || die "keytool not found."
info "Java runtime ready: $JAVA_BIN"

# ---------------------------------------------------------------- Configure Dante SOCKS5 if requested
if [ "$SETUP_DANTE" = "y" ] || [ "$SETUP_DANTE" = "Y" ]; then
  log "Setting up local Dante SOCKS5 proxy on 127.0.0.1:1080..."
  cat > /etc/danted.conf << 'EOF'
logoutput: /var/log/danted.log
internal: 127.0.0.1 port = 1080
external: eth0
# Auto-detect default interface if eth0 not present
clientmethod: none
socksmethod: none
user.privileged: root
user.unprivileged: nobody

client pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}

socks pass {
    from: 127.0.0.0/8 to: 0.0.0.0/0
    log: error
}
EOF
  # Auto-adjust external network interface in danted.conf
  DEF_IF="$(ip route show default 2>/dev/null | awk '{print $5}' | head -1 || echo eth0)"
  if [ -n "$DEF_IF" ]; then
    sed -i "s/external: eth0/external: $DEF_IF/" /etc/danted.conf
  fi

  systemctl enable danted >/dev/null 2>&1 || true
  systemctl restart danted >/dev/null 2>&1 || true
  info "Dante SOCKS5 server running on 127.0.0.1:1080"
fi

# ---------------------------------------------------------------- Get / Clone Source
mkdir -p "$INSTALL_DIR"
SELF_SRC=""
if [ -f "src/com/kokovpn/stealth/server/StealthServer.java" ]; then
  SELF_SRC="$(pwd)"
elif [ -n "${BASH_SOURCE:-}" ] && [ -f "$(dirname "${BASH_SOURCE[0]}")/src/com/kokovpn/stealth/server/StealthServer.java" ]; then
  SELF_SRC="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
fi

if [ -n "$SELF_SRC" ] && [ "$SELF_SRC" != "$INSTALL_DIR" ]; then
  log "Copying source from $SELF_SRC to $INSTALL_DIR..."
  cp -R "$SELF_SRC"/. "$INSTALL_DIR"/
elif [ ! -f "$INSTALL_DIR/src/com/kokovpn/stealth/server/StealthServer.java" ]; then
  log "Cloning repository from $REPO_URL..."
  tmp="$(mktemp -d)"
  git clone --depth 1 "$REPO_URL" "$tmp"
  cp -R "$tmp"/. "$INSTALL_DIR"/
  rm -rf "$tmp"
fi

cd "$INSTALL_DIR"

# ---------------------------------------------------------------- Compile & Build JAR
log "Compiling Java Dual-Mode Stealth Server..."
rm -rf out build/classes
mkdir -p build/classes
find src -name "*.java" > /tmp/stealth_sources.txt
javac -d build/classes @/tmp/stealth_sources.txt
rm -f /tmp/stealth_sources.txt

jar cfe "$INSTALL_DIR/stealth-server.jar" com.kokovpn.stealth.server.StealthServer -C build/classes .
info "Compiled stealth-server.jar successfully."

# ---------------------------------------------------------------- Generate SSL Certificate KeyStore
log "Generating PKCS12 Certificate for SNI ($SNI)..."
rm -f "$INSTALL_DIR/server.p12"
keytool -genkeypair -alias stealth -keyalg RSA -keysize 2048 -validity 3650 \
        -storetype PKCS12 -keystore "$INSTALL_DIR/server.p12" -storepass changeit -keypass changeit \
        -dname "CN=${SNI}, OU=IT, O=Google LLC, L=Mountain View, ST=CA, C=US" >/dev/null 2>&1
info "Generated certificate keystore at $INSTALL_DIR/server.p12"

# ---------------------------------------------------------------- Write server.properties
log "Writing server.properties..."
cat > "$INSTALL_DIR/server.properties" <<CFG
listenPort=${PORT}
useTls=true
keystorePath=${INSTALL_DIR}/server.p12
keystorePass=changeit
token=${TOKEN}
bridge=${BRIDGE}
fallback=forward
forwardHost=${FORWARD_HOST}
forwardPort=${FORWARD_PORT}
forwardTls=${FORWARD_TLS}
workerThreads=512
CFG
chmod 600 "$INSTALL_DIR/server.properties"
info "Config saved to $INSTALL_DIR/server.properties"

# ---------------------------------------------------------------- Capability for low ports
if [ "$PORT" -lt 1024 ]; then
  if command -v setcap >/dev/null 2>&1; then
    setcap 'cap_net_bind_service=+ep' "$JAVA_BIN" 2>/dev/null || true
  fi
fi

# ---------------------------------------------------------------- Install systemd service
log "Configuring systemd service ($SERVICE)..."
cat > "/etc/systemd/system/${SERVICE}.service" <<UNIT
[Unit]
Description=SNI-Stealth Dual-Mode Tunnel Server
After=network.target

[Service]
Type=simple
WorkingDirectory=${INSTALL_DIR}
ExecStart=${JAVA_BIN} -jar ${INSTALL_DIR}/stealth-server.jar --config ${INSTALL_DIR}/server.properties
Restart=always
RestartSec=3
User=root
LimitNOFILE=65535

[Install]
WantedBy=multi-user.target
UNIT

systemctl daemon-reload
systemctl enable "$SERVICE" >/dev/null 2>&1 || true
systemctl restart "$SERVICE"
sleep 1

# Create shortcut command `sni-stealth` to access menu anytime
cat > /usr/local/bin/sni-stealth << 'EOF'
#!/usr/bin/env bash
if [ -f /opt/sni-stealth/install.sh ]; then
  sudo /opt/sni-stealth/install.sh menu
elif [ -f "$(dirname "$0")/install.sh" ]; then
  sudo "$(dirname "$0")/install.sh" menu
else
  echo "SNI-Stealth installation directory not found."
fi
EOF
chmod +x /usr/local/bin/sni-stealth 2>/dev/null || true

# ---------------------------------------------------------------- Firewall
if command -v ufw >/dev/null 2>&1; then
  ufw allow "${PORT}/tcp" >/dev/null 2>&1 || true
elif command -v firewall-cmd >/dev/null 2>&1; then
  firewall-cmd --permanent --add-port="${PORT}/tcp" >/dev/null 2>&1 || true
  firewall-cmd --reload >/dev/null 2>&1 || true
fi

# ---------------------------------------------------------------- Final Summary Banner
STATE="$(systemctl is-active "$SERVICE" 2>/dev/null || echo "unknown")"

printf "\n${C_GREEN}====================================================================${C_RESET}\n"
printf "  🎉 ${C_BOLD}SNI-STEALTH DUAL-MODE SERVER INSTALLED SUCCESSFULLY!${C_RESET}\n"
printf "     Service Status: %b\n" "$([ "$STATE" = "active" ] && printf "${C_GREEN}RUNNING (Active)${C_RESET}" || printf "${C_RED}%s${C_RESET}" "$STATE")"
printf "${C_GREEN}====================================================================${C_RESET}\n"
printf "  📍 ${C_BOLD}VPS Public IP${C_RESET}       : ${C_CYAN}%s${C_RESET}\n" "$PUBIP"
printf "  🔌 ${C_BOLD}Stealth Port${C_RESET}        : ${C_CYAN}%s${C_RESET}\n" "$PORT"
printf "  🔑 ${C_BOLD}Auth Secret Token${C_RESET}   : ${C_YELLOW}%s${C_RESET}\n" "$TOKEN"
printf "  🌐 ${C_BOLD}Front SNI Domain${C_RESET}    : ${C_CYAN}%s${C_RESET}\n" "$SNI"
printf "  🌉 ${C_BOLD}Internal Bridge${C_RESET}     : %s\n" "$BRIDGE"
printf "  🛡️ ${C_BOLD}Decoy Fallback${C_RESET}      : %s:%s\n" "$FORWARD_HOST" "$FORWARD_PORT"
printf "${C_CYAN}--------------------------------------------------------------------${C_RESET}\n"
printf "  📋 ${C_BOLD}FLUTTER ADMIN APP CONFIGURATION FIELDS:${C_RESET}\n"
printf "     - Method / Protocol : ${C_BOLD}STEALTH${C_RESET}\n"
printf "     - Server IP / Host  : ${C_CYAN}%s${C_RESET}\n" "$PUBIP"
printf "     - Port              : ${C_CYAN}%s${C_RESET}\n" "$PORT"
printf "     - Forced SNI        : ${C_CYAN}%s${C_RESET}\n" "$SNI"
printf "     - Wrap in TLS       : ${C_GREEN}ON (true)${C_RESET}\n"
printf "     - Auth Token        : ${C_YELLOW}%s${C_RESET}\n" "$TOKEN"
printf "     - Bridge Mode       : %s\n" "$BRIDGE"
printf "     - Stream Mux        : ${C_GREEN}ON (true)${C_RESET}\n"
printf "     - CloudFront CDN    : ${C_BOLD}(Optional toggle if using AWS CDN)${C_RESET}\n"
printf "${C_CYAN}--------------------------------------------------------------------${C_RESET}\n"
printf "  🛠️  ${C_BOLD}Useful Server Commands:${C_RESET}\n"
printf "     - Open Management Menu : ${C_CYAN}sni-stealth${C_RESET}  (or ${C_CYAN}/opt/sni-stealth/install.sh menu${C_RESET})\n"
printf "     - View Live Realtime Logs: ${C_CYAN}journalctl -u %s -f${C_RESET}\n" "$SERVICE"
printf "     - Restart Service      : ${C_CYAN}systemctl restart %s${C_RESET}\n" "$SERVICE"
printf "${C_GREEN}====================================================================${C_RESET}\n\n"
