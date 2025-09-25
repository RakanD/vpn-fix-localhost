#!/usr/bin/env bash
# Fix localhost, LAN, and Docker routing when GlobalProtect is connected.
# Ubuntu 24.04 tested. Safe to run repeatedly.

set -euo pipefail

# ====== CONFIG (override via env or edit below) ======
LAN_IF="${LAN_IF:-wlp0s20f3}"        # your LAN/Wi-Fi iface (ip -br link)
LAN_GW="${LAN_GW:-192.168.8.1}"      # your LAN router/gateway
RESTORE_DEFAULT=0                    # set via --restore-default flag
[[ "${1:-}" == "--restore-default" ]] && RESTORE_DEFAULT=1
# =====================================================

log(){ printf "%s %s\n" "$(date +'%H:%M:%S')" "$*"; }

need_iface() {
  if ! ip link show "$1" >/dev/null 2>&1; then
    log "[!] Interface '$1' not found. Override LAN_IF/LAN_GW as env vars."
    exit 1
  fi
}

# Return subnets for an interface
cidrs_for_iface() {
  local IF="$1"
  local found=0
  # Prefer kernel routes
  while read -r CIDR; do
    [[ -n "$CIDR" ]] || continue
    echo "$CIDR"; found=1
  done < <(ip route | awk -v IF="$IF" '$0 ~ (" dev "IF" ") && /proto kernel/ && /scope link/ {print $1}')
  # Fallback to derive from iface IP(s)
  if [[ $found -eq 0 ]]; then
    while read -r ADDR; do
      [[ -z "$ADDR" ]] && continue
      python3 - <<PY
import ipaddress, sys
cidr=sys.argv[1]
net=ipaddress.ip_network(cidr, strict=False)
print(f"{net.network_address}/{net.prefixlen}")
PY
      "$ADDR"
    done < <(ip -o -4 addr show dev "$IF" | awk '{print $4}')
  fi
}

# --- 0) Sanity ---
need_iface "$LAN_IF"

# --- 1) Ensure /etc/hosts has localhost ---
log "[*] Checking /etc/hosts for localhost..."
if ! getent hosts localhost | grep -q "127.0.0.1"; then
  log "[!] Fixing /etc/hosts localhost entry"
  sudo sed -i '/[[:space:]]localhost$/d' /etc/hosts
  echo "127.0.0.1   localhost" | sudo tee -a /etc/hosts >/dev/null
  grep -q '^::1[[:space:]]\+localhost' /etc/hosts || echo "::1   localhost" | sudo tee -a /etc/hosts >/dev/null
else
  log "[✓] /etc/hosts is fine"
fi

# --- 2) Pin 127.0.0.0/8 to lo ---
log "[*] Ensuring 127.0.0.0/8 via lo..."
sudo ip route replace 127.0.0.0/8 dev lo metric 0 || true

# --- 3) Protect LAN ---
for CIDR in $(cidrs_for_iface "$LAN_IF"); do
  [[ -z "$CIDR" ]] && continue
  log "[*] Protecting LAN subnet $CIDR via $LAN_IF"
  sudo ip route replace "$CIDR" dev "$LAN_IF" scope link metric 0 || true
done

# Remove VPN-pushed LAN routes
ip route | awk '$1 ~ /^192\.168\./ && $0 ~ / dev gpd[0-9]+/ {print $1}' \
| while read -r NET; do
  log "[!] Removing VPN LAN route $NET via gpd"
  sudo ip route del "$NET" dev gpd0 2>/dev/null || true
done

# Ensure LAN supernet always wins
sudo ip route replace 192.168.0.0/16 via "$LAN_GW" dev "$LAN_IF" metric 0 || true

# Optionally restore default
DEF_DEV=$(ip route show default | awk '/default/ {print $5; exit}')
if [[ $RESTORE_DEFAULT -eq 1 && "$DEF_DEV" =~ ^gpd[0-9]+$ ]]; then
  log "[!] Restoring default route to LAN via $LAN_GW"
  sudo ip route del default || true
  sudo ip route add default via "$LAN_GW" dev "$LAN_IF" metric 100 || true
else
  log "[i] Not touching default route."
fi

# --- 4) Protect Docker ---
mapfile -t DOCKER_IFS < <(ip -o link | awk -F': ' '{print $2}' | grep -E '^(docker[0-9]*|br-.+)$' || true)
if [[ ${#DOCKER_IFS[@]} -gt 0 ]]; then
  log "[*] Protecting Docker networks..."
  for IF in "${DOCKER_IFS[@]}"; do
    for CIDR in $(cidrs_for_iface "$IF"); do
      [[ -z "$CIDR" ]] && continue
      log "    - Pin $CIDR via $IF"
      sudo ip route replace "$CIDR" dev "$IF" metric 0 || true
      # Remove VPN duplicates
      sudo ip route del "$CIDR" dev gpd0 2>/dev/null || true
    done
  done
fi

# --- 5) Summary ---
log "[*] Summary:"
ip route get 127.0.0.1 | sed 's/^/   /'
ip route | grep -E '(^default| docker0| br-| lo |'"$LAN_IF"'| gpd[0-9])' | sed 's/^/   /' || true
log "[✓] Done."
