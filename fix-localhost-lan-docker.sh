#!/usr/bin/env bash
# Hybrid fix: stable subnet detection + smart cleanup of VPN-pushed routes
# Also enforces NO_PROXY settings and proxy bypass for localhost.

set -euo pipefail

LAN_IF="${LAN_IF:-wlp0s20f3}"   # your LAN/Wi-Fi iface
LAN_GW="${LAN_GW:-192.168.8.1}" # your LAN router/gateway
RESTORE_DEFAULT=0
[[ "${1:-}" == "--restore-default" ]] && RESTORE_DEFAULT=1

log(){ printf "%s %s\n" "$(date +'%H:%M:%S')" "$*"; }

# --- 0) Sanity ---
if ! ip link show "$LAN_IF" >/dev/null 2>&1; then
  log "[!] LAN_IF '$LAN_IF' not found. Override with LAN_IF=…"
  exit 1
fi

# --- 1) Ensure /etc/hosts has both IPv4 + IPv6 localhost ---
log "[*] Checking /etc/hosts for localhost entries..."
if ! grep -qE '^127\.0\.0\.1[[:space:]]+localhost' /etc/hosts; then
  echo "127.0.0.1   localhost" | sudo tee -a /etc/hosts >/dev/null
  log "[!] Added missing IPv4 localhost to /etc/hosts"
fi
if ! grep -qE '^::1[[:space:]]+localhost' /etc/hosts; then
  echo "::1   localhost" | sudo tee -a /etc/hosts >/dev/null
  log "[!] Added missing IPv6 localhost to /etc/hosts"
fi

# --- 2) Ensure NO_PROXY env vars include localhost ---
log "[*] Enforcing NO_PROXY environment variables..."
for VAR in NO_PROXY no_proxy; do
  if ! grep -q "$VAR=localhost,127.0.0.1,::1" "$HOME/.bashrc" "$HOME/.zshrc" 2>/dev/null; then
    echo "export $VAR=localhost,127.0.0.1,::1" >> "$HOME/.bashrc"
    echo "export $VAR=localhost,127.0.0.1,::1" >> "$HOME/.zshrc"
    log "[!] Added $VAR to ~/.bashrc and ~/.zshrc"
  fi
done

# --- 3) Enforce GNOME proxy ignore-hosts ---
if command -v gsettings >/dev/null 2>&1; then
  log "[*] Updating GNOME proxy ignore-hosts..."
  gsettings set org.gnome.system.proxy ignore-hosts "['localhost','127.0.0.1','::1']" || true
fi

# --- 4) Pin localhost route ---
sudo ip route replace 127.0.0.0/8 dev lo metric 0

# --- 5) Protect LAN ---
for CIDR in $(ip -o -4 addr show dev "$LAN_IF" | awk '{print $4}'); do
  [[ -z "$CIDR" ]] && continue
  log "[*] Protecting LAN $CIDR via $LAN_IF"
  sudo ip route replace "$CIDR" dev "$LAN_IF" scope link metric 0 || true
done

# Remove VPN-pushed LAN routes
ip route | awk '$1 ~ /^192\.168\./ && / dev gpd[0-9]+/ {print $1}' \
| while read -r NET; do
  log "[!] Removing VPN LAN $NET via gpd"
  sudo ip route del "$NET" dev gpd0 2>/dev/null || true
done

# Ensure LAN supernet wins
sudo ip route replace 192.168.0.0/16 via "$LAN_GW" dev "$LAN_IF" metric 0 || true

# --- 6) Restore default route if requested ---
DEF_DEV=$(ip route show default | awk '/default/ {print $5; exit}')
if [[ $RESTORE_DEFAULT -eq 1 && "$DEF_DEV" =~ ^gpd[0-9]+$ ]]; then
  sudo ip route del default || true
  sudo ip route add default via "$LAN_GW" dev "$LAN_IF" metric 100 || true
  log "[!] Restored default route to LAN"
else
  log "[i] Not touching default route"
fi

# --- 7) Protect Docker ---
mapfile -t DOCKER_IFS < <(ip -o link | awk -F': ' '{print $2}' | grep -E '^(docker[0-9]*|br-.+)$' || true)
if [[ ${#DOCKER_IFS[@]} -gt 0 ]]; then
  log "[*] Protecting Docker networks..."
  for IF in "${DOCKER_IFS[@]}"; do
    for CIDR in $(ip -o -4 addr show dev "$IF" | awk '{print $4}'); do
      [[ -z "$CIDR" ]] && continue
      NET=$(echo "$CIDR" | cut -d/ -f1 | awk -F. '{printf "%s.%s.%s.0/%s\n",$1,$2,$3,substr("'"$CIDR"'", index("'"$CIDR"'", "/")+1)}')
      [[ -z "$NET" ]] && NET="$CIDR"
      log "    - Pin $NET via $IF"
      sudo ip route replace "$NET" dev "$IF" metric 0 || true
      sudo ip route del "$NET" dev gpd0 2>/dev/null || true
    done
  done
fi

log "[✓] Done. Current key routes:"
ip route | grep -E '(^default| gpd0| lo |docker0|br-|'"$LAN_IF"')'
