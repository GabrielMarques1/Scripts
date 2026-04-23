#!/bin/bash
# ═══════════════════════════════════════════════════════
#  MÓDULO 05 — Vulnerability Scan
#  Uso standalone: ./05_vulns.sh <alvo> <output_dir>
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
OUTDIR="${2:?Uso: $0 <alvo> <output_dir>}/vulns"
mkdir -p "$OUTDIR"
CLEAN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|:.*||')

if curl -sk --connect-timeout 3 "https://${CLEAN}" -o /dev/null 2>/dev/null; then
    BASE_URL="https://${CLEAN}"
else
    BASE_URL="http://${CLEAN}"
fi

echo -e "\n${CYN}━━━ 🛡️  MÓDULO 05 — Vulnerability Scan ━━━${RST}"
echo -e "${BLU}    URL: ${BASE_URL}${RST}\n"

# ── Nikto ──
if has nikto; then
    info "nikto (web vuln scan — pode demorar)..."
    nikto -h "$BASE_URL" -o "${OUTDIR}/nikto.txt" -Format txt 2>/dev/null || true
    ok "→ nikto.txt"

    # Mostrar findings
    vulns=$(grep -c "+" "${OUTDIR}/nikto.txt" 2>/dev/null || echo 0)
    echo -e "    ${YLW}Findings: ${vulns}${RST}"
else
    warn "nikto não instalado."
fi

# ── Nuclei ──
if has nuclei; then
    info "nuclei (template scan)..."
    nuclei -u "$BASE_URL" \
        -severity low,medium,high,critical \
        -o "${OUTDIR}/nuclei.txt" \
        -silent 2>/dev/null || true
    ok "→ nuclei.txt"

    if [[ -s "${OUTDIR}/nuclei.txt" ]]; then
        echo -e "\n${BOLD}  Nuclei findings:${RST}"
        cat "${OUTDIR}/nuclei.txt" | while read -r line; do
            if echo "$line" | grep -qi "critical"; then
                echo -e "    ${RED}🔴 $line${RST}"
            elif echo "$line" | grep -qi "high"; then
                echo -e "    ${RED}🟠 $line${RST}"
            elif echo "$line" | grep -qi "medium"; then
                echo -e "    ${YLW}🟡 $line${RST}"
            else
                echo -e "    ${BLU}🔵 $line${RST}"
            fi
        done
    fi
else
    warn "nuclei não instalado. Instale: go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
fi

# ── Searchsploit (se tiver services.txt do módulo 02) ──
PORTS_DIR="$(dirname "$OUTDIR")/ports"
if has searchsploit && [[ -f "${PORTS_DIR}/services.txt" ]]; then
    info "searchsploit (busca exploits para serviços encontrados)..."
    {
        echo "═══ Exploits para serviços detectados ═══"
        echo ""
        # Extrair nomes de serviço do nmap output
        grep -oP '\d+/tcp\s+open\s+\S+\s+\K.*' "${PORTS_DIR}/services.txt" 2>/dev/null \
            | sort -u | while read -r svc; do
            # Pegar só o nome/versão principal
            svc_clean=$(echo "$svc" | awk '{print $1, $2}' | head -1)
            if [[ -n "$svc_clean" ]]; then
                echo "── ${svc_clean} ──"
                searchsploit "$svc_clean" 2>/dev/null | head -15
                echo ""
            fi
        done
    } > "${OUTDIR}/searchsploit.txt"
    ok "→ searchsploit.txt"
elif has searchsploit; then
    info "searchsploit disponível mas sem services.txt. Rode o módulo 02 primeiro."
fi

# ── SSL/TLS check ──
if [[ "$BASE_URL" == https* ]]; then
    info "SSL/TLS check..."
    {
        echo "═══ Certificado SSL ═══"
        echo | openssl s_client -connect "${CLEAN}:443" -servername "$CLEAN" 2>/dev/null \
            | openssl x509 -noout -text 2>/dev/null | head -30
        echo ""
        echo "═══ Cifras fracas ═══"
        nmap --script ssl-enum-ciphers -p 443 "$CLEAN" 2>/dev/null | grep -A2 "TLSv\|SSLv" || echo "Nenhuma fraca encontrada."
    } > "${OUTDIR}/ssl_check.txt"
    ok "→ ssl_check.txt"
fi

# ── CORS check ──
info "CORS misconfiguration check..."
{
    echo "═══ CORS Test ═══"
    for origin in "https://evil.com" "null" "https://${CLEAN}.evil.com"; do
        echo "Origin: ${origin}"
        resp=$(curl -sk -H "Origin: ${origin}" -I "$BASE_URL" 2>/dev/null)
        acao=$(echo "$resp" | grep -i "access-control-allow-origin" || echo "  Não refletido")
        echo "  $acao"
        echo ""
    done
} > "${OUTDIR}/cors_check.txt"
ok "→ cors_check.txt"

# Verificar se CORS está vulnerável (só nas linhas de ACAO, não no arquivo todo)
if grep -i "access-control-allow-origin" "${OUTDIR}/cors_check.txt" 2>/dev/null | grep -qi "evil.com\|\bnull\b"; then
    echo -e "    ${RED}⚠️  Possível CORS misconfiguration!${RST}"
fi

# ── Resumo ──
echo ""
info "Resumo de vulnerabilidades:"
for f in "${OUTDIR}"/*.txt; do
    if [[ -f "$f" ]] && [[ -s "$f" ]]; then
        echo -e "    ${GRN}→${RST} $(basename "$f")"
    fi
done

echo -e "\n${GRN}━━━ Módulo 05 concluído ━━━${RST}"
