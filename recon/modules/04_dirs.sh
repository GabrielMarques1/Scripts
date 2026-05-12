#!/bin/bash
# ═══════════════════════════════════════════════════════
#  MÓDULO 04 — Fuzzing (Dirs, Vhosts, Subdomínios, Extensões)
#  Uso: ./04_dirs.sh <alvo> <output_dir> [auto]
#  Se passar "auto" como 3º arg, roda tudo sem menu (FULL RECON)
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

# Limpar códigos ANSI de arquivo
strip_ansi() { sed -i 's/\x1b\[[0-9;]*[a-zA-Z]//g' "$1" 2>/dev/null; }

TARGET="${1:?Uso: $0 <alvo> <output_dir> [auto]}"
OUTDIR="${2:?Uso: $0 <alvo> <output_dir>}/dirs"
AUTO_MODE="${3:-}"
mkdir -p "$OUTDIR"
CLEAN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|:.*||')

# Detectar URL
if curl -sk --connect-timeout 3 "https://${CLEAN}" -o /dev/null 2>/dev/null; then
    BASE_URL="https://${CLEAN}"
else
    BASE_URL="http://${CLEAN}"
fi

# ── Wordlists disponíveis ──
declare -A WL_MAP
wl_idx=0

add_wl() {
    local label="$1" path="$2" type="$3"
    if [[ -f "$path" ]]; then
        wl_idx=$((wl_idx + 1))
        WL_MAP["${wl_idx}_path"]="$path"
        WL_MAP["${wl_idx}_label"]="$label"
        WL_MAP["${wl_idx}_type"]="$type"
        WL_MAP["${wl_idx}_size"]="$(wc -l < "$path" 2>/dev/null)"
    fi
}

# Custom do user
add_wl "raft-large-dirs"       "$HOME/Aulas/txts_uteis/raft-large-directories-lowercase.txt" "dirs"
add_wl "big"                   "$HOME/Aulas/txts_uteis/big.txt"                              "dirs"
add_wl "common"                "$HOME/Aulas/txts_uteis/common.txt"                           "dirs"
add_wl "raft-large-files"      "$HOME/Aulas/txts_uteis/raft-large-files-lowercase.txt"       "files"
add_wl "raft-small-extensions" "$HOME/Aulas/txts_uteis/raft-small-extensions.txt"             "ext"
add_wl "subdomains-5k"         "$HOME/Aulas/txts_uteis/subdomains-top1million-5000.txt"      "subs"

# Kali defaults
add_wl "dirbuster-medium"      "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt" "dirs"
add_wl "dirb-common"           "/usr/share/wordlists/dirb/common.txt"                         "dirs"
add_wl "seclists-raft-medium"  "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt" "dirs"
add_wl "seclists-common"       "/usr/share/seclists/Discovery/Web-Content/common.txt"         "dirs"
add_wl "seclists-subs-5k"      "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" "subs"
add_wl "burp-params"           "/usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt" "params"
add_wl "top-app-params"        "/usr/share/seclists/Discovery/Web-Content/url-params_from-top-55-most-popular-apps.txt" "params"

WL_TOTAL=$wl_idx

# ═══════════════════════════════════════════
#  CALIBRAÇÃO
# ═══════════════════════════════════════════
calibrate() {
    info "Calibrando..."
    CALIBRATION_SIZES=()
    for i in 1 2 3; do
        rand_path=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)
        resp=$(curl -sk --connect-timeout 5 -w '\n__HTTP_CODE__%{http_code}' "${BASE_URL}/${rand_path}" 2>/dev/null)
        code=$(echo "$resp" | grep '__HTTP_CODE__' | sed 's/__HTTP_CODE__//')
        resp=$(echo "$resp" | grep -v '__HTTP_CODE__')
        sz=${#resp}
        wc_w=$(echo "$resp" | wc -w | tr -d ' ')
        CALIBRATION_SIZES+=("$sz")
        echo -e "    teste ${i}: code=${code} size=${sz} words=${wc_w}"
    done

    FILTER_ARGS=""
    if [[ "${CALIBRATION_SIZES[0]}" == "${CALIBRATION_SIZES[1]}" && "${CALIBRATION_SIZES[1]}" == "${CALIBRATION_SIZES[2]}" ]]; then
        FILTER_ARGS="-fs ${CALIBRATION_SIZES[0]}"
        ok "404 customizado (size=${CALIBRATION_SIZES[0]}). Filtrando."
    else
        FILTER_ARGS="-ac"
        ok "Usando auto-calibrate."
    fi
}

# ═══════════════════════════════════════════
#  CRAWLER — katana + gau + fallback curl
# ═══════════════════════════════════════════

# Detectar binários (podem estar em ~/go/bin)
_find_bin() {
    command -v "$1" 2>/dev/null && return
    [[ -x "$HOME/go/bin/$1" ]] && echo "$HOME/go/bin/$1" && return
    echo ""
}

scan_crawl() {
    local max_depth="${1:-3}"

    echo -e "\n${BOLD}══ CRAWLER ══${RST}"
    info "Alvo: ${BASE_URL}"

    local urls_file="${OUTDIR}/crawl_urls.txt"
    local params_file="${OUTDIR}/crawl_params.txt"
    local endpoints_file="${OUTDIR}/crawl_endpoints.txt"
    local js_file="${OUTDIR}/crawl_js.txt"

    > "$urls_file"
    > "$params_file"
    > "$endpoints_file"
    > "$js_file"

    local katana_bin=$(_find_bin katana)
    local gau_bin=$(_find_bin gau)
    local used_tools=""

    # ── KATANA — Crawler ativo ──
    if [[ -n "$katana_bin" ]]; then
        info "katana — crawling ativo (profundidade: ${max_depth}, 20 threads)..."
        used_tools="katana"

        $katana_bin -u "$BASE_URL" \
            -d "$max_depth" \
            -jc \
            -kf all \
            -ef css,png,jpg,jpeg,gif,svg,ico,woff,woff2,ttf,eot,mp4,mp3 \
            -c 20 \
            -timeout 10 \
            -silent \
            -no-color \
            -o "${OUTDIR}/katana_raw.txt" \
            2>/dev/null || true

        if [[ -s "${OUTDIR}/katana_raw.txt" ]]; then
            local kt_count=$(wc -l < "${OUTDIR}/katana_raw.txt")
            ok "katana: ${kt_count} URLs"
            cat "${OUTDIR}/katana_raw.txt" >> "$urls_file"
        else
            warn "katana não retornou resultados."
        fi
    fi

    # ── GAU — URLs históricas ──
    if [[ -n "$gau_bin" ]]; then
        info "gau — buscando URLs históricas (Wayback, CommonCrawl)..."
        used_tools="${used_tools:+$used_tools + }gau"

        timeout 90 $gau_bin --threads 5 "$CLEAN" 2>/dev/null \
            | grep -viE '\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot|mp4|mp3|pdf|zip|tar|gz)(\?|$)' \
            | sort -u > "${OUTDIR}/gau_crawl.txt" || true

        if [[ -s "${OUTDIR}/gau_crawl.txt" ]]; then
            local gau_count=$(wc -l < "${OUTDIR}/gau_crawl.txt")
            ok "gau: ${gau_count} URLs históricas"
            cat "${OUTDIR}/gau_crawl.txt" >> "$urls_file"
        else
            warn "gau não retornou resultados."
        fi
    fi

    # ── FALLBACK: curl crawl ──
    if [[ -z "$katana_bin" && -z "$gau_bin" ]]; then
        warn "Nem katana nem gau disponíveis. Usando crawler básico (curl)..."
        used_tools="curl"

        local visited="${OUTDIR}/.crawl_visited"
        local queue="${OUTDIR}/.crawl_queue"
        > "$visited"
        echo "${BASE_URL}/" > "$queue"

        local d=0
        while [[ $d -lt $max_depth ]] && [[ -s "$queue" ]]; do
            d=$((d + 1))
            info "Profundidade ${d}/${max_depth}..."
            local next_q="${OUTDIR}/.crawl_next"
            > "$next_q"

            while IFS= read -r url; do
                grep -qxF "$url" "$visited" 2>/dev/null && continue
                echo "$url" >> "$visited"
                body=$(curl -sk --connect-timeout 5 --max-time 10 -L "$url" 2>/dev/null) || continue
                echo "$body" | grep -oP '(href|src|action)\s*=\s*["'"'"']\K[^"'"'"'#]+' 2>/dev/null | while IFS= read -r link; do
                    case "$link" in
                        http://*|https://*) echo "$link" | grep -qi "$CLEAN" && echo "$link" >> "$urls_file" ;;
                        /*) echo "${BASE_URL}${link}" >> "$urls_file" ;;
                    esac
                done
            done < "$queue"
            sort -u "$next_q" -o "$queue" 2>/dev/null
        done
        rm -f "$visited" "$queue" "${OUTDIR}/.crawl_next"
    fi

    # ── PÓS-PROCESSAMENTO unificado ──
    local raw_count=$(wc -l < "$urls_file" 2>/dev/null || echo 0)

    # Deduplicar
    sort -u "$urls_file" -o "$urls_file" 2>/dev/null

    # Filtrar assets que passaram
    grep -viE '\.(css|png|jpg|jpeg|gif|svg|ico|woff|woff2|ttf|eot)(\?|$)' \
        "$urls_file" > "${urls_file}.tmp" 2>/dev/null
    mv "${urls_file}.tmp" "$urls_file" 2>/dev/null

    # uro — remover URLs redundantes (mesma page, params diferentes)
    local uro_bin=$(_find_bin uro)
    if [[ -n "$uro_bin" ]]; then
        local before_uro=$(wc -l < "$urls_file" 2>/dev/null || echo 0)
        $uro_bin < "$urls_file" > "${urls_file}.uro" 2>/dev/null
        mv "${urls_file}.uro" "$urls_file" 2>/dev/null
        local after_uro=$(wc -l < "$urls_file" 2>/dev/null || echo 0)
        local removed=$((before_uro - after_uro))
        [[ $removed -gt 0 ]] && ok "uro: removeu ${removed} URLs redundantes (${before_uro} → ${after_uro})"
        used_tools="${used_tools:+$used_tools + }uro"
    fi

    # Extrair URLs com parâmetros
    grep '?' "$urls_file" 2>/dev/null | sort -u > "$params_file"

    # Extrair nomes de parâmetros únicos
    grep -oP '[?&]\K[^=]+' "$params_file" 2>/dev/null | sort -u > "$endpoints_file"

    # Extrair JS files
    grep -iE '\.js(\?|$)' "$urls_file" 2>/dev/null | sort -u > "$js_file"

    local url_count=$(wc -l < "$urls_file" 2>/dev/null || echo 0)
    local param_count=$(wc -l < "$params_file" 2>/dev/null || echo 0)
    local endpoint_count=$(wc -l < "$endpoints_file" 2>/dev/null || echo 0)
    local js_count=$(wc -l < "$js_file" 2>/dev/null || echo 0)

    echo ""
    echo -e "    ${BOLD}Ferramentas: ${used_tools}${RST}"
    echo -e "    ${GRN}URLs totais:${RST}        ${url_count}"
    echo -e "    ${RED}Com parâmetros:${RST}     ${param_count}"
    echo -e "    ${CYN}Parâmetros únicos:${RST} ${endpoint_count}"
    echo -e "    ${YLW}Arquivos JS:${RST}        ${js_count}"

    if [[ $url_count -gt 0 ]]; then
        echo -e "\n    ${BOLD}Top URLs:${RST}"
        head -15 "$urls_file" | while IFS= read -r u; do
            echo -e "    ${GRN}→${RST} $u"
        done
        [[ $url_count -gt 15 ]] && echo -e "    ${YLW}... +$((url_count - 15)) mais${RST}"
    fi

    if [[ $param_count -gt 0 ]]; then
        echo -e "\n    ${BOLD}URLs com parâmetros (prontas pra fuzzing):${RST}"
        head -10 "$params_file" | while IFS= read -r u; do
            echo -e "    ${RED}⚡${RST} $u"
        done
    fi

    ok "→ crawl_urls.txt, crawl_params.txt, crawl_endpoints.txt, crawl_js.txt"
    ok "Concluído."
}

# ═══════════════════════════════════════════
#  FUNÇÕES DE SCAN
# ═══════════════════════════════════════════
scan_dirs() {
    local wl="$1"
    echo -e "\n${BOLD}══ DIRETÓRIOS ══${RST}"
    info "Wordlist: $(basename "$wl") ($(wc -l < "$wl") entradas)"

    if has ffuf; then
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" -w "$wl" \
            -mc 200,204,301,302,307,401,405 -fc 404 \
            -ac ${FILTER_ARGS} -t 50 -c \
            -o "${OUTDIR}/ffuf_dirs.json" -of json \
            | tee "${OUTDIR}/ffuf_dirs.txt" 2>/dev/null
    elif has gobuster; then
        gobuster dir -u "$BASE_URL" -w "$wl" \
            -s "200,204,301,302,307,401,405" -b "404,403" \
            -t 50 -o "${OUTDIR}/gobuster_dirs.txt" \
            --no-error 2>/dev/null || true
    fi
    ok "Concluído."
}

scan_vhosts() {
    local wl="$1"
    if is_ip "$CLEAN"; then warn "Alvo é IP, vhosts não se aplica."; return; fi

    echo -e "\n${BOLD}══ VHOSTS ══${RST}"
    info "Wordlist: $(basename "$wl") ($(wc -l < "$wl") entradas)"

    if has ffuf; then
        rand_vhost=$(tr -dc 'a-z' < /dev/urandom | head -c 12)
        vhost_size=$(curl -sk -o /dev/null -w "%{size_download}" -H "Host: ${rand_vhost}.${CLEAN}" "$BASE_URL" 2>/dev/null)
        info "Filtro: size=${vhost_size}"

        ffuf -u "$BASE_URL" -H "Host: FUZZ.${CLEAN}" -w "$wl" \
            -mc 200,301,302,307 -fs "$vhost_size" \
            -ac -t 50 -c \
            -o "${OUTDIR}/ffuf_vhosts.json" \
            -of json 2>/dev/null | tee "${OUTDIR}/ffuf_vhosts.txt" 2>/dev/null || true
    else
        warn "ffuf necessário para vhosts."
    fi
    ok "Concluído."
}

scan_subdomains() {
    local wl="$1"
    if is_ip "$CLEAN"; then warn "Alvo é IP, subdomínios não se aplica."; return; fi

    echo -e "\n${BOLD}══ SUBDOMÍNIOS DNS ══${RST}"
    info "Wordlist: $(basename "$wl") ($(wc -l < "$wl") entradas)"

    # Wildcard check
    rand_sub=$(tr -dc 'a-z' < /dev/urandom | head -c 14)
    wildcard_ip=$(dig +short "${rand_sub}.${CLEAN}" A 2>/dev/null | head -1)
    [[ -n "$wildcard_ip" ]] && warn "Wildcard: *.${CLEAN} → ${wildcard_ip}"

    if has gobuster; then
        local wild_arg=""
        [[ -n "$wildcard_ip" ]] && wild_arg="--wildcard"
        # shellcheck disable=SC2086
        timeout 120 gobuster dns -d "$CLEAN" -w "$wl" \
            -t 50 ${wild_arg} \
            -o "${OUTDIR}/dns_brute.txt" \
            --no-error 2>/dev/null || true
    else
        info "dig fallback (max 500)..."
        > "${OUTDIR}/dns_brute.txt"
        local c=0
        while IFS= read -r sub && [[ $c -lt 500 ]]; do
            [[ -z "$sub" || "$sub" == \#* ]] && continue
            ip=$(dig +short +time=1 +tries=1 "${sub}.${CLEAN}" A 2>/dev/null | head -1)
            if [[ -n "$ip" && "$ip" != "$wildcard_ip" ]]; then
                echo "${sub}.${CLEAN} → ${ip}" >> "${OUTDIR}/dns_brute.txt"
                echo -e "    ${GRN}✔${RST} ${sub}.${CLEAN} → ${ip}"
            fi
            c=$((c + 1))
        done < "$wl"
    fi

    if [[ -s "${OUTDIR}/dns_brute.txt" ]]; then
        found=$(wc -l < "${OUTDIR}/dns_brute.txt")
        echo -e "    ${GRN}Encontrados: ${found}${RST}"
        head -15 "${OUTDIR}/dns_brute.txt" | while read -r l; do echo -e "    ${GRN}→${RST} $l"; done
    fi
    ok "Concluído."
}

scan_extensions() {
    local wl="$1"
    local exts="${2:-.php,.html,.txt,.bak,.old,.conf,.xml,.json,.sql,.zip,.tar.gz,.log}"

    echo -e "\n${BOLD}══ ARQUIVOS COM EXTENSÕES ══${RST}"
    info "Wordlist: $(basename "$wl")"
    info "Extensões: ${exts:0:60}..."

    if has ffuf; then
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" -w "$wl" \
            -e "$exts" \
            -mc 200,204,301,302,307,401 -fc 404 \
            -ac ${FILTER_ARGS} -t 50 -c \
            -o "${OUTDIR}/ffuf_files.json" -of json \
            | tee "${OUTDIR}/ffuf_files.txt" 2>/dev/null
    elif has gobuster; then
        gobuster dir -u "$BASE_URL" -w "$wl" \
            -x "${exts//./}" \
            -s "200,204,301,302,307,401" -b "404,403" \
            -t 50 -o "${OUTDIR}/gobuster_files.txt" \
            --no-error 2>/dev/null || true
    fi
    ok "Concluído."
}

scan_files_only() {
    local wl="$1"
    echo -e "\n${BOLD}══ WORDLIST DE ARQUIVOS ══${RST}"
    info "Wordlist: $(basename "$wl") ($(wc -l < "$wl") entradas)"

    if has ffuf; then
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" -w "$wl" \
            -mc 200,204,301,302,307,401 -fc 404 \
            -ac ${FILTER_ARGS} -t 50 -c \
            -o "${OUTDIR}/ffuf_files_raft.json" -of json \
            | tee "${OUTDIR}/ffuf_files_raft.txt" 2>/dev/null
    fi
    ok "Concluído."
}

scan_params() {
    local target_url="$1"
    local wl="$2"

    if ! has ffuf; then
        fail "ffuf necessário para parameter fuzzing."
        return 1
    fi

    local threads="${THREADS_FFUF:-50}"

    echo -e "\n${BOLD}══ PARAMETER FUZZING ══${RST}"
    info "URL: ${target_url}"
    info "Wordlist: $(basename "$wl") ($(wc -l < "$wl") entradas)"
    info "Threads: ${threads}"

    # ── FASE A: Descobrir parâmetros GET ──
    info "Fase A — Descobrindo parâmetros GET ocultos..."

    baseline_size=$(curl -sk -o /dev/null -w "%{size_download}" --connect-timeout "${TIMEOUT_CURL:-5}" "$target_url" 2>/dev/null)
    info "Baseline size: ${baseline_size} bytes"

    # Rate limiting adaptativo
    local ffuf_rate_args=""
    if [[ "${RATE_LIMIT:-0}" -gt 0 ]]; then
        ffuf_rate_args="-rate ${RATE_LIMIT}"
    fi

    ffuf -u "${target_url}?FUZZ=test123" \
        -w "$wl" \
        -mc all \
        -fs "$baseline_size" \
        -ac \
        -t "$threads" -c $ffuf_rate_args \
        -timeout "${TIMEOUT_FFUF:-10}" \
        -o "${OUTDIR}/ffuf_params_discovery.json" \
        -of json 2>/dev/null | tee "${OUTDIR}/ffuf_params_discovery.txt" 2>/dev/null || true

    # Verificar se WAF bloqueou (muitos 429/403)
    if [[ "${RATE_LIMIT_ADAPTIVE:-true}" == "true" && -s "${OUTDIR}/ffuf_params_discovery.txt" ]]; then
        local waf_hits
        waf_hits=$(grep -c '\[429\]\|\[403\]' "${OUTDIR}/ffuf_params_discovery.txt" 2>/dev/null || echo 0)
        if [[ $waf_hits -gt 10 ]]; then
            local new_threads="${RATE_LIMIT_MIN_THREADS:-5}"
            warn "WAF detectado (${waf_hits}x 429/403) — reduzindo threads: ${threads} → ${new_threads}"
            threads=$new_threads
            # Re-rodar com menos threads
            ffuf -u "${target_url}?FUZZ=test123" \
                -w "$wl" -mc all -fs "$baseline_size" -ac \
                -t "$new_threads" -c -rate 10 \
                -timeout "${TIMEOUT_FFUF:-10}" \
                -o "${OUTDIR}/ffuf_params_discovery.json" \
                -of json 2>/dev/null | tee "${OUTDIR}/ffuf_params_discovery.txt" 2>/dev/null || true
            ok "Re-scan com ${new_threads} threads concluído."
        fi
    fi

    # Extrair parâmetros encontrados
    local params_found=()
    local params_file="${OUTDIR}/params_found_raw.txt"
    > "$params_file"

    # Texto do ffuf (mais confiável)
    if [[ -s "${OUTDIR}/ffuf_params_discovery.txt" ]]; then
        sed 's/\x1b\[[0-9;]*[a-zA-Z]//g' "${OUTDIR}/ffuf_params_discovery.txt" 2>/dev/null \
            | grep '\[Status:' | awk '{print $1}' | sort -u >> "$params_file"
    fi
    # JSON fallback
    if [[ -s "${OUTDIR}/ffuf_params_discovery.json" ]]; then
        grep -oP '"FUZZ"\s*:\s*"\K[^"]+' "${OUTDIR}/ffuf_params_discovery.json" 2>/dev/null \
            | sort -u >> "$params_file"
    fi

    sort -u "$params_file" -o "$params_file"
    while IFS= read -r p; do
        [[ -n "$p" && "$p" != "FUZZ" ]] && params_found+=("$p")
    done < "$params_file"

    if [[ ${#params_found[@]} -eq 0 ]]; then
        warn "Nenhum parâmetro oculto encontrado na fase A."
        echo -e "    ${BLU}Dica: tente em páginas específicas (.php, /api/, /search)${RST}"
        ok "Concluído."
        return 0
    fi

    ok "Parâmetros encontrados: ${#params_found[@]}"
    printf '%s\n' "${params_found[@]}" > "${OUTDIR}/params_found.txt"
    for p in "${params_found[@]}"; do
        echo -e "    ${GRN}→${RST} ${p}"
    done

    # ── FASE B: Testar injeções GET ──
    echo ""
    info "Fase B — Testando injeções GET nos ${#params_found[@]} parâmetros..."

    declare -A PAYLOADS
    PAYLOADS[LFI]="../../../../etc/passwd"
    PAYLOADS[LFI2]="....//....//....//etc/passwd"
    PAYLOADS[XSS]="<script>alert(1)</script>"
    PAYLOADS[XSS2]="'\"><img src=x onerror=alert(1)>"
    PAYLOADS[SQLi]="' OR '1'='1"
    PAYLOADS[SQLi2]="1' AND SLEEP(2)-- -"
    PAYLOADS[SQLi3]="\" OR \"\"=\""
    PAYLOADS[SSRF]="http://127.0.0.1:80"
    PAYLOADS[SSRF2]="http://169.254.169.254/latest/meta-data/"
    PAYLOADS[SSTI]="{{7*7}}"
    PAYLOADS[CMDI]=";id"
    PAYLOADS[IDOR]="1"
    PAYLOADS[REDIRECT]="https://evil.com"

    > "${OUTDIR}/params_vulns.txt"

    _test_payload() {
        local param="$1" vuln_type="$2" payload="$3" method="$4" resp="$5"
        local is_vuln=false vuln_evidence=""

        case "$vuln_type" in
            LFI|LFI2)
                echo "$resp" | grep -q "root:x:0:0\|root:.*:/bin/" && { is_vuln=true; vuln_evidence="/etc/passwd no response!"; } ;;
            XSS|XSS2)
                echo "$resp" | grep -q "<script>alert(1)</script>\|onerror=alert" && { is_vuln=true; vuln_evidence="payload refletido sem sanitização"; } ;;
            SQLi|SQLi2|SQLi3)
                if echo "$resp" | grep -qi "sql syntax\|mysql\|sqlite\|postgresql\|ORA-\|unterminated\|ODBC"; then
                    is_vuln=true; vuln_evidence="erro SQL no response"
                fi ;;
            SSTI)
                echo "$resp" | grep -q "49" && { is_vuln=true; vuln_evidence="{{7*7}}=49 refletido!"; } ;;
            CMDI)
                echo "$resp" | grep -q "uid=\|gid=" && { is_vuln=true; vuln_evidence="output de comando detectado!"; } ;;
            SSRF|SSRF2)
                ;; # Precisa de out-of-band
        esac

        if $is_vuln; then
            echo -e "      ${RED}🔴 ${method} ${vuln_type}: POSSÍVEL VULN! ${vuln_evidence}${RST}"
            echo "[VULN] method=${method} param=${param} type=${vuln_type} evidence=${vuln_evidence}" >> "${OUTDIR}/params_vulns.txt"
        fi
    }

    for param in "${params_found[@]}"; do
        echo -e "\n    ${CYN}── ${param} ──${RST}"

        normal_resp=$(curl -sk --connect-timeout "${TIMEOUT_CURL:-5}" "${target_url}?${param}=normaltest123" 2>/dev/null)
        normal_size=${#normal_resp}

        for vuln_type in "${!PAYLOADS[@]}"; do
            payload="${PAYLOADS[$vuln_type]}"
            encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")

            test_resp=$(curl -sk --connect-timeout "${TIMEOUT_CURL:-5}" "${target_url}?${param}=${encoded}" 2>/dev/null)
            test_size=${#test_resp}

            _test_payload "$param" "$vuln_type" "$payload" "GET" "$test_resp"

            # Size diff check (genérico)
            if [[ $((test_size - normal_size)) -gt 500 || $((test_size - normal_size)) -lt -500 ]]; then
                echo -e "      ${YLW}🟡 GET ${vuln_type}: size diff (${normal_size}→${test_size})${RST}"
                echo "[INTERESTING] method=GET param=${param} type=${vuln_type} evidence=size_diff(${normal_size}→${test_size})" >> "${OUTDIR}/params_vulns.txt"
            fi
        done
    done

    # ── FASE C: Testar injeções POST ──
    echo ""
    info "Fase C — Testando injeções POST..."

    for param in "${params_found[@]}"; do
        echo -e "\n    ${MAG}── POST: ${param} ──${RST}"

        # Baseline POST
        post_normal=$(curl -sk --connect-timeout "${TIMEOUT_CURL:-5}" \
            -X POST -d "${param}=normaltest123" "$target_url" 2>/dev/null)
        post_normal_size=${#post_normal}

        for vuln_type in "${!PAYLOADS[@]}"; do
            payload="${PAYLOADS[$vuln_type]}"
            encoded=$(python3 -c "import urllib.parse; print(urllib.parse.quote('${payload}'))" 2>/dev/null || echo "$payload")

            # POST urlencoded
            post_resp=$(curl -sk --connect-timeout "${TIMEOUT_CURL:-5}" \
                -X POST -d "${param}=${encoded}" "$target_url" 2>/dev/null)

            _test_payload "$param" "$vuln_type" "$payload" "POST" "$post_resp"

            # POST JSON
            json_resp=$(curl -sk --connect-timeout "${TIMEOUT_CURL:-5}" \
                -X POST -H "Content-Type: application/json" \
                -d "{\"${param}\": \"${payload}\"}" "$target_url" 2>/dev/null)

            _test_payload "$param" "$vuln_type" "$payload" "POST-JSON" "$json_resp"
        done
    done

    # ── Resumo ──
    echo ""
    if [[ -s "${OUTDIR}/params_vulns.txt" ]]; then
        local get_vulns=$(grep -c "method=GET.*\[VULN\]" "${OUTDIR}/params_vulns.txt" 2>/dev/null || echo 0)
        local post_vulns=$(grep -c "method=POST" "${OUTDIR}/params_vulns.txt" 2>/dev/null || echo 0)
        local total_vulns=$(grep -c "\[VULN\]" "${OUTDIR}/params_vulns.txt" 2>/dev/null || echo 0)
        local interesting=$(grep -c "\[INTERESTING\]" "${OUTDIR}/params_vulns.txt" 2>/dev/null || echo 0)
        echo -e "    ${RED}🔴 Vulneráveis: ${total_vulns}${RST} (GET: ${get_vulns}, POST: ${post_vulns})"
        echo -e "    ${YLW}🟡 Interessantes: ${interesting}${RST}"
        ok "→ params_vulns.txt"
    else
        ok "Nenhuma injeção detectada."
    fi
    ok "→ params_found.txt"
    ok "Concluído."
}



# ═══════════════════════════════════════════
#  MENU — Listar wordlists
# ═══════════════════════════════════════════
show_wordlists() {
    echo ""
    echo -e "${BOLD}  Wordlists disponíveis:${RST}"
    for i in $(seq 1 "$WL_TOTAL"); do
        local label="${WL_MAP["${i}_label"]}"
        local sz="${WL_MAP["${i}_size"]}"
        local tp="${WL_MAP["${i}_type"]}"
        local color="$RST"
        case "$tp" in
            dirs)   color="$GRN" ;;
            subs)   color="$CYN" ;;
            files)  color="$MAG" ;;
            ext)    color="$YLW" ;;
            params) color="$RED" ;;
        esac
        printf "    ${color}%2d${RST}) %-25s %6s linhas  [%s]\n" "$i" "$label" "$sz" "$tp"
    done
    echo ""
}

show_menu() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════${RST}"
    echo -e "${CYN} FUZZING — ${YLW}${BASE_URL}${RST}"
    echo -e "${BOLD}═══════════════════════════════════════${RST}"
    echo ""
    echo -e "  ${GRN}1${RST}) Diretórios"
    echo -e "  ${GRN}2${RST}) Vhosts"
    echo -e "  ${GRN}3${RST}) Subdomínios DNS"
    echo -e "  ${GRN}4${RST}) Extensões (dirs + extensões)"
    echo -e "  ${GRN}5${RST}) Arquivos (wordlist de filenames)"
    echo -e "  ${GRN}6${RST}) ${RED}Parâmetros${RST} (GET param fuzzing + injeções)"
    echo -e "  ${GRN}7${RST}) ${CYN}Crawler${RST} (descobrir endpoints automaticamente)"
    echo -e "  ${GRN}8${RST}) ${MAG}FULL${RST} (tudo sequencial)"
    echo ""
    echo -e "  ${GRN}w${RST}) Ver wordlists disponíveis"
    echo -e "  ${GRN}q${RST}) Voltar"
    echo ""
}

pick_wordlist() {
    local default_type="$1"
    show_wordlists

    # Sugerir wordlist default baseado no tipo
    local suggested=""
    for i in $(seq 1 "$WL_TOTAL"); do
        if [[ "${WL_MAP["${i}_type"]}" == "$default_type" ]]; then
            suggested="$i"
            break
        fi
    done

    read -rp "$(echo -e "${YLW}[?]${RST} Wordlist [Enter=${suggested:-1}]: ")" choice
    choice="${choice:-$suggested}"
    choice="${choice:-1}"

    if [[ -n "${WL_MAP["${choice}_path"]+x}" ]]; then
        PICKED_WL="${WL_MAP["${choice}_path"]}"
        ok "Usando: $(basename "$PICKED_WL")"
    else
        fail "Opção inválida, usando default."
        PICKED_WL="${WL_MAP["1_path"]}"
    fi
}

# ═══════════════════════════════════════════
#  MODO AUTO (chamado pelo FULL RECON)
# ═══════════════════════════════════════════
run_auto() {
    echo -e "\n${CYN}━━━ 📂 MÓDULO 04 — Fuzzing (AUTO) ━━━${RST}\n"
    calibrate
    echo ""

    # Pegar primeiro wordlist de cada tipo
    local dir_wl="" sub_wl="" ext_wl="" files_wl=""
    for i in $(seq 1 "$WL_TOTAL"); do
        case "${WL_MAP["${i}_type"]}" in
            dirs)  [[ -z "$dir_wl" ]]   && dir_wl="${WL_MAP["${i}_path"]}" ;;
            subs)  [[ -z "$sub_wl" ]]   && sub_wl="${WL_MAP["${i}_path"]}" ;;
            ext)   [[ -z "$ext_wl" ]]   && ext_wl="${WL_MAP["${i}_path"]}" ;;
            files) [[ -z "$files_wl" ]] && files_wl="${WL_MAP["${i}_path"]}" ;;
        esac
    done

    [[ -n "$dir_wl" ]]   && scan_dirs "$dir_wl"
    [[ -n "$sub_wl" ]]   && scan_vhosts "$sub_wl"
    [[ -n "$sub_wl" ]]   && scan_subdomains "$sub_wl"

    if [[ -n "$ext_wl" && -n "$dir_wl" ]]; then
        local exts
        exts=$(head -50 "$ext_wl" | tr '\n' ',' | sed 's/,$//')
        scan_extensions "$dir_wl" "$exts"
    elif [[ -n "$dir_wl" ]]; then
        scan_extensions "$dir_wl"
    fi

    [[ -n "$files_wl" ]] && scan_files_only "$files_wl"

    # Crawler
    scan_crawl 2

    # Parameter fuzzing automático (usar URLs crawleadas se existirem)
    local param_wl=""
    for i in $(seq 1 "$WL_TOTAL"); do
        [[ "${WL_MAP["${i}_type"]}" == "params" ]] && { param_wl="${WL_MAP["${i}_path"]}"; break; }
    done
    if [[ -n "$param_wl" ]]; then
        # Se crawler encontrou URLs com parâmetros, testar cada uma
        if [[ -s "${OUTDIR}/crawl_params.txt" ]]; then
            info "Testando parâmetros nas URLs crawleadas..."
            while IFS= read -r crawled_url; do
                # Extrair base URL (sem parâmetros)
                local base
                base=$(echo "$crawled_url" | sed 's|?.*||')
                scan_params "$base" "$param_wl"
            done < <(head -5 "${OUTDIR}/crawl_params.txt")
        else
            scan_params "${BASE_URL}/" "$param_wl"
        fi
    fi
}

# ═══════════════════════════════════════════
#  MODO INTERATIVO
# ═══════════════════════════════════════════
run_interactive() {
    echo -e "\n${CYN}━━━ 📂 MÓDULO 04 — Fuzzing ━━━${RST}"
    echo -e "${BLU}    Alvo: ${BASE_URL}${RST}"
    calibrate

    while true; do
        show_menu
        read -rp "$(echo -e "${BLU}[fuzzing]${RST} Opção: ")" opt

        case "$opt" in
            1)
                pick_wordlist "dirs"
                scan_dirs "$PICKED_WL"
                ;;
            2)
                pick_wordlist "subs"
                scan_vhosts "$PICKED_WL"
                ;;
            3)
                pick_wordlist "subs"
                scan_subdomains "$PICKED_WL"
                ;;
            4)
                pick_wordlist "dirs"
                local dir_picked="$PICKED_WL"
                # Perguntar extensões
                local ext_wl_found=""
                for i in $(seq 1 "$WL_TOTAL"); do
                    [[ "${WL_MAP["${i}_type"]}" == "ext" ]] && ext_wl_found="${WL_MAP["${i}_path"]}"
                done

                echo -e "\n${YLW}[?]${RST} Como quer buscar extensões?"
                echo -e "  ${GRN}1${RST}) Usar wordlist ($(basename "${ext_wl_found:-nenhuma}"))"
                echo -e "  ${GRN}2${RST}) Digitar extensões manualmente"
                echo -e "  ${GRN}3${RST}) Sem extensões (só diretórios)"
                read -rp "$(echo -e "${YLW}[?]${RST} Opção [1]: ")" ext_choice
                ext_choice="${ext_choice:-1}"

                case "$ext_choice" in
                    1)
                        if [[ -n "$ext_wl_found" ]]; then
                            local exts
                            exts=$(head -50 "$ext_wl_found" | tr '\n' ',' | sed 's/,$//')
                            scan_extensions "$dir_picked" "$exts"
                        else
                            warn "Nenhuma wordlist de extensões encontrada."
                            scan_dirs "$dir_picked"
                        fi
                        ;;
                    2)
                        read -rp "$(echo -e "${YLW}[?]${RST} Extensões (ex: .php,.html,.txt): ")" custom_ext
                        if [[ -n "$custom_ext" ]]; then
                            scan_extensions "$dir_picked" "$custom_ext"
                        else
                            warn "Nenhuma extensão digitada. Rodando só diretórios."
                            scan_dirs "$dir_picked"
                        fi
                        ;;
                    3)
                        info "Sem extensões — rodando só diretórios."
                        scan_dirs "$dir_picked"
                        ;;
                    *)
                        warn "Opção inválida. Rodando só diretórios."
                        scan_dirs "$dir_picked"
                        ;;
                esac
                ;;
            5)
                pick_wordlist "files"
                scan_files_only "$PICKED_WL"
                ;;
            6)
                echo -e "\n${YLW}[?]${RST} URL alvo para param fuzzing (ex: ${BASE_URL}/index.php)"
                echo -e "    ${BLU}Dica: use uma página que aceite parâmetros${RST}"
                read -rp "$(echo -e "${YLW}[?]${RST} URL [Enter=${BASE_URL}/]: ")" param_url
                param_url="${param_url:-${BASE_URL}/}"
                pick_wordlist "params"
                scan_params "$param_url" "$PICKED_WL"
                ;;
            7)
                echo -e "\n${YLW}[?]${RST} Profundidade do crawl (1-5) [2]: "
                read -rp "    > " crawl_depth
                crawl_depth="${crawl_depth:-2}"
                scan_crawl "$crawl_depth"
                ;;
            8)
                run_auto
                ;;
            w)
                show_wordlists
                ;;
            q)
                break
                ;;
            *)
                warn "Opção inválida."
                ;;
        esac
    done
}

# ═══════════════════════════════════════════
#  RESUMO
# ═══════════════════════════════════════════
show_summary() {
    echo ""
    echo -e "${BOLD}══ RESUMO ══${RST}"
    local total=0
    for f in "${OUTDIR}"/*.txt "${OUTDIR}"/*.json; do
        if [[ -f "$f" ]] && [[ -s "$f" ]]; then
            local count
            count=$(wc -l < "$f")
            total=$((total + count))
            echo -e "    ${GRN}→${RST} $(basename "$f"): ${count} linhas"
        fi
    done
    ok "Total: ${total} resultados"
    echo -e "\n${GRN}━━━ Módulo 04 concluído ━━━${RST}"
}

# ── Main ──
if [[ "$AUTO_MODE" == "auto" ]]; then
    run_auto
else
    run_interactive
fi

# Limpar ANSI de TODOS os arquivos de output
info "Limpando output files..."
for f in "${OUTDIR}"/*.txt; do
    [[ -f "$f" ]] && strip_ansi "$f"
done

show_summary
