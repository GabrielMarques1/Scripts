#!/bin/bash
# ═══════════════════════════════════════════════════════
#  MÓDULO 02 — Port Scan & Serviços
#  Uso standalone: ./02_ports.sh <alvo> <output_dir>
# ═══════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; RST='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${BLU}[*]${RST} $1"; }
ok()    { echo -e "${GRN}[+]${RST} $1"; }
warn()  { echo -e "${YLW}[!]${RST} $1"; }
fail()  { echo -e "${RED}[-]${RST} $1"; }
has()   { command -v "$1" &>/dev/null; }

TARGET="${1:?Uso: $0 <alvo> <output_dir>}"
OUTDIR="${2:?Uso: $0 <alvo> <output_dir>}/ports"
mkdir -p "$OUTDIR"
CLEAN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|:.*||')

echo -e "\n${CYN}━━━ 🔌 MÓDULO 02 — Port Scan & Serviços ━━━${RST}\n"

if ! has nmap; then fail "nmap não instalado!"; exit 1; fi

# Quick scan — top 1000
info "Quick scan — top 1000 portas..."
nmap -T4 --open -oN "${OUTDIR}/quick_scan.txt" -oG "${OUTDIR}/quick_scan.gnmap" "$CLEAN" 2>/dev/null

open_ports=$(grep -oP '\d+/open' "${OUTDIR}/quick_scan.gnmap" 2>/dev/null | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')

# Se nada, scan completo
if [[ -z "$open_ports" ]]; then
    warn "Nada no top 1000. Scan completo (-p-)..."
    nmap -T4 -p- --open -oN "${OUTDIR}/full_scan.txt" -oG "${OUTDIR}/full_scan.gnmap" "$CLEAN" 2>/dev/null
    open_ports=$(grep -oP '\d+/open' "${OUTDIR}/full_scan.gnmap" 2>/dev/null | cut -d/ -f1 | tr '\n' ',' | sed 's/,$//')
fi

if [[ -z "$open_ports" ]]; then fail "Nenhuma porta aberta."; exit 0; fi

ok "Portas abertas: ${open_ports}"
echo "$open_ports" > "${OUTDIR}/open_ports.txt"

# Service & Version
info "Detectando serviços (-sV -sC)..."
nmap -sV -sC -T4 -p "$open_ports" -oN "${OUTDIR}/services.txt" -oX "${OUTDIR}/services.xml" "$CLEAN" 2>/dev/null
ok "→ services.txt"

echo -e "\n${BOLD}  Serviços:${RST}"
grep -E '^[0-9]+/' "${OUTDIR}/services.txt" 2>/dev/null | while read -r line; do
    echo -e "    ${GRN}→${RST} $line"
done

# OS Detection (root only)
if [[ $EUID -eq 0 ]]; then
    info "OS Detection..."
    nmap -O -p "$open_ports" -oN "${OUTDIR}/os_detect.txt" "$CLEAN" 2>/dev/null
    ok "→ os_detect.txt"

    info "UDP top 20..."
    nmap -sU --top-ports 20 -T4 --open -oN "${OUTDIR}/udp_scan.txt" "$CLEAN" 2>/dev/null
    ok "→ udp_scan.txt"
else
    warn "Rode como root para OS detection e UDP scan."
fi

# Nmap vuln scripts
info "Nmap vuln scripts..."
nmap --script vuln -p "$open_ports" -oN "${OUTDIR}/nmap_vulns.txt" "$CLEAN" 2>/dev/null || true
ok "→ nmap_vulns.txt"

echo -e "\n${GRN}━━━ Módulo 02 concluído ━━━${RST}"
