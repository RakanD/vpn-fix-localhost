#!/usr/bin/env bash
# Fix localhost, LAN, and Docker routing when GlobalProtect is connected.
# Ubuntu 24.04 tested. Safe to run repeatedly.

set -euo pipefail

# ====== CONFIG (override via env or edit below) ======
LAN_IF="${LAN_IF:-wlp0s20f3}"        # your Wi-Fi/Ethernet iface (ip -br link)
LAN_GW="${LAN_GW:-192.168.8.1}"      # your LAN router/gateway
# Pass --restore-default to switch default route from VPN back to LAN
RESTORE_DEFAULT=0
[[ "${1:-}" == "--restore-default" ]] && RESTORE_DEFAULT=1
# =====================================================

log(){ printf "%s %s\n" "$(date +'%H:%M:%S')" "$*"; }

need_iface() {
  if ! ip link show "$1" >/dev/null 2>&1; then
    log "[!] Interface '$1' not found. Set LAN_IF/LAN_GW (e.g. LAN_IF=enp5s0 LAN_GW=192.168.1.1)."
    exit 1
  fi
}

# Return one or more network CIDRs for an interface (e.g., "172.18.0.0/16")
# Strategy:
#   1) Prefer kernel routes bound to that iface (proto kernel scope link)
#   2) If missing, derive from the iface IP(s) using Python ipaddress
cidrs_for_iface() {
  local IF="$1"
  local found=0

  # From kernel routes
  while read -r CIDR; do
    [[ -n "$CIDR" ]] || continue
    echo "$CIDR"
    found=1
  done < <(ip route | awk -v IF="$IF" '$0 ~ (" dev "IF" ") && /proto kernel/ && /scope link/ {print $1}')

  # Derive from IPs if none found
  if [[ $found -eq 0 ]]; then
    while read -r ADDR; do
      [[ -n "$ADDR" ]] || continue
      # Convert host/prefix to network/prefix using Python (no external deps)
      python3 - <<PY
import ipaddress, sys
cidr = sys.argv[1]
net = ipaddress.ip_network(cidr, strict=False)
print(f"{net.network_address}/{net.prefixlen}")
PY
      "$ADDR"
    done < <(ip -o -4 addr show dev "$IF" | awk '{print $4}')
  fi
}

# --- 0) Sanity ---
need_iface "$LAN_IF"

# --- 1) Ensure /etc/hosts maps localhost correctly ---
log "[*] Checking /etc/hosts for localhost..."
if ! getent hosts localhost | grep -qE '(^|[[:space:]])127\.0\.0\.1([[:space:]]|$)'; then
  log "[!] Fixing localhost entry in /etc/hosts"
  sudo sed -i '/[[:space:]]localhost$/d' /etc/hosts
  echo "127.0.0.1   localhost" | sudo tee -a /etc/hosts >/dev/null
  grep -q '^::1[[:space:]]\+localhost' /etc/hosts || echo "::1   localhost" | sudo tee -a /etc/hosts >/dev/null
else
  log "[✓] /etc/hosts has correct localhost mapping"
fi

# --- 2) Pin 127.0.0.0/8 to loopback with top priority ---
log "[*] Ensuring 127.0.0.0/8 via lo..."
sudo ip route replace 127.0.0.0/8 dev lo metric 0 || true

# --- 3) Protect your LAN from being hijacked by VPN ---
# Detect LAN subnet for $LAN_IF
LAN_SUBNETS=$(cidrs_for_iface "$LAN_IF")
if [[ -n "${LAN_SUBNETS:-}" ]]; then
  while read -r CIDR; do
    [[ -z "$CIDR" ]] && continue
    log "[*] Protecting LAN subnet $CIDR via $LAN_IF"
    sudo ip route replace "$CIDR" dev "$LAN_IF" scope link metric 5 || true
  done <<< "$LAN_SUBNETS"
else
  log "[!] Could not detect LAN subnet on $LAN_IF"
fi

# Optionally restore default route to LAN if VPN took it
CURRENT_DEF_DEV=$(ip route show default | awk '/default/ {print $5; exit}')
if [[ $RESTORE_DEFAULT -eq 1 && "$CURRENT_DEF_DEV" =~ ^gpd[0-9]+$ ]]; then
  log "[!] Restoring default route to LAN via $LAN_GW dev $LAN_IF"
  sudo ip route del default || true
  sudo ip route add default via "$LAN_GW" dev "$LAN_IF" metric 100 || true
else
  log "[i] Not touching default route (pass --restore-default to switch from VPN to LAN)."
fi

# --- 4) Protect Docker bridges (docker0 and br-*) ---
log "[*] Protecting Docker bridges…"
mapfile -t DOCKER_IFS < <(ip -o link | awk -F': ' '{print $2}' | grep -E '^(docker[0-9]*|br-.+)$' || true)
if [[ ${#DOCKER_IFS[@]} -eq 0 ]]; then
  log "[i] No Docker bridges detected (ok if Docker not running)."
else
  for IF in "${DOCKER_IFS[@]}"; do
    for CIDR in $(cidrs_for_iface "$IF"); do
      [[ -z "$CIDR" ]] && continue
      log "    - Pin $CIDR via $IF"
      sudo ip route replace "$CIDR" dev "$IF" proto kernel scope link metric 0 || true
    done
  done
fi

# --- 5) Summary ---
log "[*] Summary:"
echo "localhost -> $(getent hosts localhost | awk '{print $1,$2}' | paste -sd '; ' -)"
ip route get 127.0.0.1 | sed 's/^/   /'
ip route | grep -E '(^default| docker0| br-| lo |'"$LAN_IF"'| gpd[0-9])' | sed 's/^/   /' || true

log "[✓] Done."
