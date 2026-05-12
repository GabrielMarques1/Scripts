#!/bin/bash
# ═══════════════════════════════════════════════════════
#  MÓDULO 01 — Subdomínios & DNS (Pipeline Integrado)
#  Uso standalone: ./01_subdomains.sh <alvo> <output_dir>
#
#  Fluxo: Descobrir → Probar → Inteligência → Relatório
# ═══════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; MAG='\033[0;35m'
RST='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${BLU}[*]${RST} $1"; }
ok()    { echo -e "${GRN}[+]${RST} $1"; }
warn()  { echo -e "${YLW}[!]${RST} $1"; }
fail()  { echo -e "${RED}[-]${RST} $1"; }
has()   { command -v "$1" &>/dev/null; }
is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

# Detectar binários em ~/go/bin ou ~/.local/bin
find_bin() {
    command -v "$1" 2>/dev/null && return
    [[ -x "$HOME/go/bin/$1" ]] && echo "$HOME/go/bin/$1" && return
    [[ -x "$HOME/.local/bin/$1" ]] && echo "$HOME/.local/bin/$1" && return
    echo ""
}

TARGET="${1:?Uso: $0 <alvo> <output_dir>}"
OUTDIR="${2:?Uso: $0 <alvo> <output_dir>}/subdomains"
mkdir -p "$OUTDIR"
CLEAN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|:.*||')

echo -e "\n${CYN}━━━ 📡 MÓDULO 01 — Subdomínios & DNS ━━━${RST}"
echo -e "${BLU}    Alvo: ${BOLD}${CLEAN}${RST}\n"

# ═══════════════════════════════════════════
#  FASE 0 — DNS Básico
# ═══════════════════════════════════════════
echo -e "${BOLD}▸ FASE 0 — DNS${RST}"

if has whois; then
    info "WHOIS..."
    whois "$CLEAN" > "${OUTDIR}/whois.txt" 2>/dev/null
    ok "→ whois.txt"
fi

if has dig; then
    info "DNS Records..."
    { for t in A AAAA MX NS TXT SOA CNAME; do
        echo "═══ $t ═══"
        dig +short "$CLEAN" "$t" 2>/dev/null
        echo
    done } > "${OUTDIR}/dns_records.txt"
    ok "→ dns_records.txt"
    echo -e "    A: $(dig +short "$CLEAN" A 2>/dev/null | head -3 | tr '\n' ' ')"
fi

# Se IP, pular subdomínios
if is_ip "$CLEAN"; then
    info "Alvo é IP — pulando subdomínios."
    has dig && dig +short -x "$CLEAN" > "${OUTDIR}/reverse_dns.txt" 2>/dev/null
    echo -e "\n${GRN}━━━ Módulo 01 concluído ━━━${RST}"
    exit 0
fi

# ═══════════════════════════════════════════
#  FASE 1 — DESCOBERTA (todas as fontes → 1 lista)
# ═══════════════════════════════════════════
echo -e "\n${BOLD}▸ FASE 1 — Descoberta de subdomínios${RST}"

DISCOVERY="${OUTDIR}/.discovery_raw.txt"
> "$DISCOVERY"
tools_used=""

# crt.sh (certificados SSL)
info "crt.sh (certificados)..."
curl -s "https://crt.sh/?q=%25.${CLEAN}&output=json" 2>/dev/null \
    | grep -oP '"name_value"\s*:\s*"\K[^"]+' | sort -u | grep -v '^\*' >> "$DISCOVERY" 2>/dev/null || true
crt_count=$(wc -l < "$DISCOVERY" 2>/dev/null || echo 0)
ok "crt.sh: ${crt_count}"

# subfinder
if has subfinder; then
    info "subfinder..."
    subfinder -d "$CLEAN" -silent 2>/dev/null >> "$DISCOVERY"
    tools_used="${tools_used:+$tools_used, }subfinder"
fi

# amass (passive, timeout 3min)
if has amass; then
    info "amass (passive, max 3min)..."
    timeout 180 amass enum -passive -d "$CLEAN" 2>/dev/null >> "$DISCOVERY" || true
    tools_used="${tools_used:+$tools_used, }amass"
fi

# dnsrecon
if has dnsrecon; then
    info "dnsrecon..."
    dnsrecon -d "$CLEAN" -t std 2>/dev/null \
        | grep -oP '[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+' >> "$DISCOVERY" 2>/dev/null || true
    tools_used="${tools_used:+$tools_used, }dnsrecon"
fi

# theHarvester
if has theHarvester; then
    info "theHarvester..."
    theHarvester -d "$CLEAN" -b all 2>/dev/null \
        | grep -oP '[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+' >> "$DISCOVERY" 2>/dev/null || true
    tools_used="${tools_used:+$tools_used, }theHarvester"
fi

# Consolidar e deduplicar
grep -oP '[a-zA-Z0-9][-a-zA-Z0-9]*(\.[a-zA-Z0-9][-a-zA-Z0-9]*)+' "$DISCOVERY" 2>/dev/null \
    | grep -i "${CLEAN}$" | sort -u > "${OUTDIR}/all_subdomains.txt"
rm -f "$DISCOVERY"

total_subs=$(wc -l < "${OUTDIR}/all_subdomains.txt" 2>/dev/null || echo 0)
echo ""
ok "Total descobertos: ${total_subs} subdomínios únicos"
ok "Fontes: crt.sh${tools_used:+, $tools_used}"
ok "→ all_subdomains.txt"

if [[ "$total_subs" -eq 0 ]]; then
    warn "Nenhum subdomínio encontrado."
    echo -e "\n${GRN}━━━ Módulo 01 concluído ━━━${RST}"
    exit 0
fi

# ═══════════════════════════════════════════
#  FASE 2 — PROBE (httpx nos subdomínios)
# ═══════════════════════════════════════════
echo -e "\n${BOLD}▸ FASE 2 — Probe (quais estão vivos?)${RST}"

HTTPX_BIN=$(find_bin httpx)

if [[ -n "$HTTPX_BIN" ]]; then
    info "httpx (50 threads) — status, título, tech, servidor..."

    $HTTPX_BIN -l "${OUTDIR}/all_subdomains.txt" \
        -sc -title -cl -server -td -ip \
        -threads 50 \
        -timeout 5 \
        -no-color \
        -o "${OUTDIR}/alive_detailed.txt" \
        2>/dev/null

    # alive.txt limpo (só URLs)
    awk '{print $1}' "${OUTDIR}/alive_detailed.txt" 2>/dev/null | sort -u > "${OUTDIR}/alive.txt"
else
    # Fallback: curl paralelo
    info "httpx indisponível — usando curl (20 threads)..."
    > "${OUTDIR}/alive.txt"
    > "${OUTDIR}/alive_detailed.txt"

    _check_alive() {
        local sub="$1" outfile="$2" detail_file="$3"
        for proto in https http; do
            local code
            code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 3 --max-time 5 "${proto}://${sub}" 2>/dev/null || echo "000")
            if [[ "$code" != "000" ]]; then
                local title
                title=$(curl -sk --connect-timeout 3 --max-time 5 "${proto}://${sub}" 2>/dev/null \
                    | grep -oP '<title>\K[^<]+' | head -1 | cut -c1-50)
                echo "${proto}://${sub} [${code}]" >> "$outfile"
                echo "${proto}://${sub} [${code}] [${title:-sem título}]" >> "$detail_file"
                break
            fi
        done
    }
    export -f _check_alive

    xargs -a "${OUTDIR}/all_subdomains.txt" -I{} -P 20 \
        bash -c '_check_alive "$@"' _ {} "${OUTDIR}/alive.txt" "${OUTDIR}/alive_detailed.txt"
fi

alive_count=$(wc -l < "${OUTDIR}/alive.txt" 2>/dev/null || echo 0)
dead_count=$((total_subs - alive_count))

echo ""
echo -e "${BOLD}  ┌────────────────────────────────────────────────────┐${RST}"
echo -e "${BOLD}  │  RESULTADOS DO PROBE                              │${RST}"
echo -e "${BOLD}  ├────────────────────────────────────────────────────┤${RST}"
echo -e "  │  ${GRN}● Vivos:${RST}  ${alive_count}/${total_subs}                                  │"
echo -e "  │  ${RED}● Mortos:${RST} ${dead_count}/${total_subs}                                  │"
echo -e "${BOLD}  ├────────────────────────────────────────────────────┤${RST}"

if [[ -s "${OUTDIR}/alive_detailed.txt" ]]; then
    while IFS= read -r line; do
        local url status
        url=$(echo "$line" | awk '{print $1}')
        status=$(echo "$line" | grep -oP '\[\d+\]' | head -1)
        code=$(echo "$status" | tr -d '[]')

        local color="$RST"
        case "${code:-0}" in
            200|201|204) color="$GRN" ;;
            301|302|307|308) color="$CYN" ;;
            401|403) color="$YLW" ;;
            500|502|503) color="$RED" ;;
        esac

        printf "  │  ${color}%-45s %s${RST}\n" "$url" "$status"
    done < "${OUTDIR}/alive_detailed.txt"
fi
echo -e "${BOLD}  └────────────────────────────────────────────────────┘${RST}"

# Contadores por status
if [[ -s "${OUTDIR}/alive_detailed.txt" ]]; then
    echo ""
    for code_group in "200" "301 302 307" "401 403" "500 502 503"; do
        local count=0 label="" color=""
        case "$code_group" in
            "200") label="2xx OK" ; color="$GRN" ;;
            "301 302 307") label="3xx Redirect" ; color="$CYN" ;;
            "401 403") label="4xx Restrito" ; color="$YLW" ;;
            "500 502 503") label="5xx Erro" ; color="$RED" ;;
        esac
        for c in $code_group; do
            local n
            n=$(grep -c "\[${c}\]" "${OUTDIR}/alive_detailed.txt" 2>/dev/null || echo 0)
            count=$((count + n))
        done
        [[ $count -gt 0 ]] && echo -e "    ${color}●${RST} ${label}: ${count}"
    done
fi

ok "→ alive.txt, alive_detailed.txt"

# ═══════════════════════════════════════════
#  FASE 3 — INTELIGÊNCIA (gau + uro nos vivos)
# ═══════════════════════════════════════════
echo -e "\n${BOLD}▸ FASE 3 — Inteligência (URLs históricas dos vivos)${RST}"

GAU_BIN=$(find_bin gau)
URO_BIN=$(find_bin uro)

if [[ -n "$GAU_BIN" && "$alive_count" -gt 0 ]]; then
    info "gau — buscando URLs históricas dos ${alive_count} subdomínios vivos..."

    # Extrair domínios dos alive (sem protocolo)
    sed 's|https\?://||;s|/.*||' "${OUTDIR}/alive.txt" 2>/dev/null \
        | sort -u > "${OUTDIR}/.alive_domains.txt"

    > "${OUTDIR}/gau_raw.txt"

    # gau em cada domínio vivo (com timeout global)
    while IFS= read -r domain; do
        echo -e "    ${BLU}→${RST} ${domain}"
        timeout 60 $GAU_BIN --threads 3 "$domain" 2>/dev/null >> "${OUTDIR}/gau_raw.txt" || true
    done < "${OUTDIR}/.alive_domains.txt"

    rm -f "${OUTDIR}/.alive_domains.txt"

    raw_count=$(wc -l < "${OUTDIR}/gau_raw.txt" 2>/dev/null || echo 0)

    if [[ $raw_count -gt 0 ]]; then
        ok "gau: ${raw_count} URLs brutas"

        # Filtrar assets estáticos
        grep -viE '\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|tar|gz)(\?|$)' \
            "${OUTDIR}/gau_raw.txt" | sort -u > "${OUTDIR}/gau_filtered.txt"

        # uro — limpar URLs redundantes
        if [[ -n "$URO_BIN" ]]; then
            local before=$(wc -l < "${OUTDIR}/gau_filtered.txt")
            $URO_BIN < "${OUTDIR}/gau_filtered.txt" > "${OUTDIR}/gau_urls.txt" 2>/dev/null
            local after=$(wc -l < "${OUTDIR}/gau_urls.txt")
            ok "uro: ${before} → ${after} (removeu $((before - after)) redundantes)"
        else
            cp "${OUTDIR}/gau_filtered.txt" "${OUTDIR}/gau_urls.txt"
        fi
        rm -f "${OUTDIR}/gau_filtered.txt"

        # Extrair por tipo
        grep '?' "${OUTDIR}/gau_urls.txt" 2>/dev/null | sort -u > "${OUTDIR}/gau_params.txt"
        grep -iE '\.js(\?|$)' "${OUTDIR}/gau_raw.txt" 2>/dev/null | sort -u > "${OUTDIR}/gau_js.txt"
        sed 's/?.*//' "${OUTDIR}/gau_urls.txt" 2>/dev/null | sort -u > "${OUTDIR}/gau_paths.txt"

        local url_count=$(wc -l < "${OUTDIR}/gau_urls.txt" 2>/dev/null || echo 0)
        local param_count=$(wc -l < "${OUTDIR}/gau_params.txt" 2>/dev/null || echo 0)
        local js_count=$(wc -l < "${OUTDIR}/gau_js.txt" 2>/dev/null || echo 0)
        local path_count=$(wc -l < "${OUTDIR}/gau_paths.txt" 2>/dev/null || echo 0)

        echo ""
        echo -e "    ${GRN}URLs limpas:${RST}      ${url_count}"
        echo -e "    ${RED}Com parâmetros:${RST}   ${param_count}"
        echo -e "    ${YLW}Arquivos JS:${RST}      ${js_count}"
        echo -e "    ${CYN}Paths únicos:${RST}     ${path_count}"

        if [[ $param_count -gt 0 ]]; then
            echo -e "\n    ${BOLD}Top URLs com parâmetros:${RST}"
            head -8 "${OUTDIR}/gau_params.txt" | while IFS= read -r u; do
                echo -e "    ${RED}⚡${RST} $u"
            done
            [[ $param_count -gt 8 ]] && echo -e "    ${YLW}... +$((param_count - 8)) mais${RST}"
        fi

        ok "→ gau_urls.txt, gau_params.txt, gau_js.txt, gau_paths.txt"
    else
        warn "gau não retornou URLs."
    fi
elif [[ -z "$GAU_BIN" ]]; then
    warn "gau não instalado — pulando fase de inteligência."
fi

# ═══════════════════════════════════════════
#  FASE 4 — RELATÓRIO CONSOLIDADO
# ═══════════════════════════════════════════
echo -e "\n${BOLD}▸ FASE 4 — Relatório${RST}"

{
    echo "════════════════════════════════════════════"
    echo "  RECON SUBDOMÍNIOS — ${CLEAN}"
    echo "  Data: $(date '+%Y-%m-%d %H:%M:%S')"
    echo "════════════════════════════════════════════"
    echo ""
    echo "DESCOBERTOS: ${total_subs}"
    echo "VIVOS:       ${alive_count}"
    echo "MORTOS:      ${dead_count}"
    echo ""
    echo "── SUBDOMÍNIOS VIVOS ──"
    [[ -s "${OUTDIR}/alive_detailed.txt" ]] && cat "${OUTDIR}/alive_detailed.txt"
    echo ""
    if [[ -s "${OUTDIR}/gau_params.txt" ]]; then
        echo "── URLs COM PARÂMETROS (potenciais alvos) ──"
        cat "${OUTDIR}/gau_params.txt"
        echo ""
    fi
    if [[ -s "${OUTDIR}/gau_js.txt" ]]; then
        echo "── ENDPOINTS JS ──"
        cat "${OUTDIR}/gau_js.txt"
        echo ""
    fi
} > "${OUTDIR}/summary.txt"

ok "→ summary.txt (relatório consolidado)"

echo ""
echo -e "${BOLD}  ┌────────────────────────────────────────────────────┐${RST}"
echo -e "${BOLD}  │  📊 RESUMO FINAL                                  │${RST}"
echo -e "${BOLD}  ├────────────────────────────────────────────────────┤${RST}"
echo -e "  │  Subdomínios:  ${BOLD}${total_subs}${RST} descobertos → ${GRN}${alive_count} vivos${RST}"
[[ -s "${OUTDIR}/gau_urls.txt" ]] && echo -e "  │  URLs (gau):    ${BOLD}$(wc -l < "${OUTDIR}/gau_urls.txt")${RST} limpas (uro)"
[[ -s "${OUTDIR}/gau_params.txt" ]] && echo -e "  │  Com params:    ${RED}$(wc -l < "${OUTDIR}/gau_params.txt")${RST} prontas pra fuzzing"
[[ -s "${OUTDIR}/gau_js.txt" ]] && echo -e "  │  Arquivos JS:   ${YLW}$(wc -l < "${OUTDIR}/gau_js.txt")${RST}"
echo -e "${BOLD}  └────────────────────────────────────────────────────┘${RST}"

echo -e "\n${GRN}━━━ Módulo 01 concluído ━━━${RST}"
