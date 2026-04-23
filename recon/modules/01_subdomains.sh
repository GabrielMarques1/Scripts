#!/bin/bash
# ═══════════════════════════════════════════════════════
#  MÓDULO 01 — Subdomínios & DNS
#  Uso standalone: ./01_subdomains.sh <alvo> <output_dir>
# ═══════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; RST='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${BLU}[*]${RST} $1"; }
ok()    { echo -e "${GRN}[+]${RST} $1"; }
warn()  { echo -e "${YLW}[!]${RST} $1"; }
has()   { command -v "$1" &>/dev/null; }

TARGET="${1:?Uso: $0 <alvo> <output_dir>}"
OUTDIR="${2:?Uso: $0 <alvo> <output_dir>}/subdomains"
mkdir -p "$OUTDIR"
CLEAN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|:.*||')
is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

echo -e "\n${CYN}━━━ 📡 MÓDULO 01 — Subdomínios & DNS ━━━${RST}\n"

# WHOIS
if has whois; then
    info "WHOIS..."; whois "$CLEAN" > "${OUTDIR}/whois.txt" 2>/dev/null; ok "→ whois.txt"
fi

# DNS Records
if has dig; then
    info "DNS Records..."
    { for t in A AAAA MX NS TXT SOA CNAME; do echo "═══ $t ═══"; dig +short "$CLEAN" "$t" 2>/dev/null; echo; done } > "${OUTDIR}/dns_records.txt"
    ok "→ dns_records.txt"
    echo "    A:  $(dig +short "$CLEAN" A 2>/dev/null | head -3 | tr '\n' ' ')"
fi

# Se IP, pular subdomínios
if is_ip "$CLEAN"; then
    info "Alvo é IP, pulando subdomínios."
    has dig && dig +short -x "$CLEAN" > "${OUTDIR}/reverse_dns.txt" 2>/dev/null
    exit 0
fi

# crt.sh
info "crt.sh..."
curl -s "https://crt.sh/?q=%25.${CLEAN}&output=json" 2>/dev/null \
    | grep -oP '"name_value"\s*:\s*"\K[^"]+' | sort -u | grep -v '^\*' > "${OUTDIR}/crtsh.txt" 2>/dev/null || true
ok "crt.sh → $(wc -l < "${OUTDIR}/crtsh.txt" 2>/dev/null || echo 0) subdomínios"

# subfinder
has subfinder && { info "subfinder..."; subfinder -d "$CLEAN" -silent -o "${OUTDIR}/subfinder.txt" 2>/dev/null; ok "→ subfinder.txt"; }

# amass
has amass && { info "amass (passive, timeout 5min)..."; timeout 300 amass enum -passive -d "$CLEAN" -o "${OUTDIR}/amass.txt" 2>/dev/null || true; ok "→ amass.txt"; }

# dnsrecon
has dnsrecon && { info "dnsrecon..."; dnsrecon -d "$CLEAN" -t std > "${OUTDIR}/dnsrecon.txt" 2>/dev/null || true; ok "→ dnsrecon.txt"; }

# theHarvester
has theHarvester && { info "theHarvester..."; theHarvester -d "$CLEAN" -b all -f "${OUTDIR}/theharvester" >/dev/null 2>&1 || true; ok "→ theharvester"; }

# Consolidar
info "Consolidando..."
cat "${OUTDIR}"/*.txt 2>/dev/null | grep -oP '[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+' \
    | grep -i "${CLEAN}$" | sort -u > "${OUTDIR}/all_subdomains.txt"
ok "Total: $(wc -l < "${OUTDIR}/all_subdomains.txt") subdomínios → all_subdomains.txt"

# Alive check
info "Alive check..."
> "${OUTDIR}/alive.txt"
while IFS= read -r sub; do
    for proto in https http; do
        code=$(curl -s -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 5 "${proto}://${sub}" 2>/dev/null || echo "000")
        if [[ "$code" != "000" ]]; then
            echo "${proto}://${sub} [${code}]" >> "${OUTDIR}/alive.txt"
            echo -e "  ${GRN}✔${RST} ${proto}://${sub} [${code}]"
            break
        fi
    done
done < "${OUTDIR}/all_subdomains.txt"
ok "Vivos: $(wc -l < "${OUTDIR}/alive.txt") → alive.txt"
echo -e "\n${GRN}━━━ Módulo 01 concluído ━━━${RST}"
