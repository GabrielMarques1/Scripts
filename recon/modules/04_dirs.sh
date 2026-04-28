#!/bin/bash
# ═══════════════════════════════════════════════════════
#  MÓDULO 04 — Directory & Subdomain Bruteforce
#  Uso standalone: ./04_dirs.sh <alvo> <output_dir>
#
#  ORDEM: 1) Diretórios  2) Subdomínios DNS  3) Extensões/Arquivos  4) Vhosts
# ═══════════════════════════════════════════════════════

set -uo pipefail

RED='\033[0;31m'; GRN='\033[0;32m'; YLW='\033[1;33m'
BLU='\033[0;34m'; CYN='\033[0;36m'; RST='\033[0m'; BOLD='\033[1m'

info()  { echo -e "${BLU}[*]${RST} $1"; }
ok()    { echo -e "${GRN}[+]${RST} $1"; }
warn()  { echo -e "${YLW}[!]${RST} $1"; }
fail()  { echo -e "${RED}[-]${RST} $1"; }
has()   { command -v "$1" &>/dev/null; }
is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

TARGET="${1:?Uso: $0 <alvo> <output_dir>}"
OUTDIR="${2:?Uso: $0 <alvo> <output_dir>}/dirs"
mkdir -p "$OUTDIR"
CLEAN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|:.*||')

# Detectar URL
if curl -sk --connect-timeout 3 "https://${CLEAN}" -o /dev/null 2>/dev/null; then
    BASE_URL="https://${CLEAN}"
else
    BASE_URL="http://${CLEAN}"
fi

# ── Wordlists ──
WORDLISTS=(
    "$HOME/Aulas/txts_uteis/raft-large-directories-lowercase.txt"
    "$HOME/Aulas/txts_uteis/big.txt"
    "$HOME/Aulas/txts_uteis/common.txt"
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "/usr/share/wordlists/dirb/common.txt"
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/wordlists/dirb/big.txt"
)

EXT_WL="$HOME/Aulas/txts_uteis/raft-small-extensions.txt"
FILES_WL="$HOME/Aulas/txts_uteis/raft-large-files-lowercase.txt"

WORDLIST=""
for wl in "${WORDLISTS[@]}"; do
    [[ -f "$wl" ]] && { WORDLIST="$wl"; break; }
done

if [[ -z "$WORDLIST" ]]; then
    fail "Nenhuma wordlist encontrada!"
    exit 1
fi

echo -e "\n${CYN}━━━ 📂 MÓDULO 04 — Bruteforce ━━━${RST}"
echo -e "${BLU}    URL: ${BASE_URL}${RST}"
echo -e "${BLU}    Wordlist: $(basename "$WORDLIST")${RST}\n"

# ═══════════════════════════════════════════
#  CALIBRAÇÃO — Anti falso positivo
# ═══════════════════════════════════════════
info "Calibrando..."
CALIBRATION_SIZES=()
CALIBRATION_WORDS=()
CALIBRATION_LINES=()

for i in 1 2 3; do
    rand_path=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)
    resp=$(curl -sk --connect-timeout 5 -w '\n__HTTP_CODE__%{http_code}' "${BASE_URL}/${rand_path}" 2>/dev/null)
    code=$(echo "$resp" | grep '__HTTP_CODE__' | sed 's/__HTTP_CODE__//')
    resp=$(echo "$resp" | grep -v '__HTTP_CODE__')
    sz=${#resp}
    wc_w=$(echo "$resp" | wc -w | tr -d ' ')
    wc_l=$(echo "$resp" | wc -l | tr -d ' ')
    CALIBRATION_SIZES+=("$sz")
    CALIBRATION_WORDS+=("$wc_w")
    CALIBRATION_LINES+=("$wc_l")
    echo -e "    teste ${i}: code=${code} size=${sz} words=${wc_w} lines=${wc_l}"
done

FILTER_ARGS=""
if [[ "${CALIBRATION_SIZES[0]}" == "${CALIBRATION_SIZES[1]}" && "${CALIBRATION_SIZES[1]}" == "${CALIBRATION_SIZES[2]}" ]]; then
    FILTER_ARGS="-fs ${CALIBRATION_SIZES[0]}"
    ok "404 customizado detectado (size=${CALIBRATION_SIZES[0]}). Filtrando."
elif [[ "${CALIBRATION_WORDS[0]}" == "${CALIBRATION_WORDS[1]}" && "${CALIBRATION_WORDS[1]}" == "${CALIBRATION_WORDS[2]}" ]]; then
    FILTER_ARGS="-fw ${CALIBRATION_WORDS[0]}"
    ok "Filtro por word count (${CALIBRATION_WORDS[0]})."
elif [[ "${CALIBRATION_LINES[0]}" == "${CALIBRATION_LINES[1]}" && "${CALIBRATION_LINES[1]}" == "${CALIBRATION_LINES[2]}" ]]; then
    FILTER_ARGS="-fl ${CALIBRATION_LINES[0]}"
    ok "Filtro por line count (${CALIBRATION_LINES[0]})."
else
    warn "Respostas variam — usando -ac."
    FILTER_ARGS="-ac"
fi

echo ""

# ═══════════════════════════════════════════
#  FASE 1 — DIRETÓRIOS
# ═══════════════════════════════════════════
echo -e "${BOLD}══ FASE 1: Diretórios ══${RST}"

if has ffuf; then
    info "ffuf — diretórios ($(basename "$WORDLIST"))..."
    # shellcheck disable=SC2086
    ffuf -u "${BASE_URL}/FUZZ" \
        -w "$WORDLIST" \
        -mc 200,204,301,302,307,401,405 \
        -fc 404 \
        -ac \
        ${FILTER_ARGS} \
        -t 50 -c \
        -o "${OUTDIR}/ffuf_dirs.json" -of json \
        | tee "${OUTDIR}/ffuf_dirs.txt" 2>/dev/null
    ok "→ ffuf_dirs.txt"

elif has gobuster; then
    info "gobuster — diretórios..."
    gobuster dir -u "$BASE_URL" \
        -w "$WORDLIST" \
        -s "200,204,301,302,307,401,405" \
        -b "404,403" \
        -t 50 \
        -o "${OUTDIR}/gobuster_dirs.txt" \
        --no-error 2>/dev/null || true
    ok "→ gobuster_dirs.txt"
else
    fail "Nenhum fuzzer disponível (ffuf/gobuster)."
    exit 1
fi

echo ""

# ═══════════════════════════════════════════
#  FASE 2 — VHOSTS
# ═══════════════════════════════════════════
if has ffuf && ! is_ip "$CLEAN"; then
    echo -e "${BOLD}══ FASE 2: Vhosts ══${RST}"
    VHOST_WL=""
    for wl in "$HOME/Aulas/txts_uteis/subdomains-top1million-5000.txt" \
              "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"; do
        [[ -f "$wl" ]] && { VHOST_WL="$wl"; break; }
    done

    if [[ -n "$VHOST_WL" ]]; then
        rand_vhost=$(tr -dc 'a-z' < /dev/urandom | head -c 12)
        vhost_size=$(curl -sk -o /dev/null -w "%{size_download}" -H "Host: ${rand_vhost}.${CLEAN}" "$BASE_URL" 2>/dev/null)

        info "ffuf — vhosts (filtro: size=${vhost_size})..."
        ffuf -u "$BASE_URL" \
            -H "Host: FUZZ.${CLEAN}" \
            -w "$VHOST_WL" \
            -mc 200,301,302,307 \
            -fs "$vhost_size" \
            -ac -t 50 -c \
            -o "${OUTDIR}/ffuf_vhosts.json" \
            -of json 2>/dev/null | tee "${OUTDIR}/ffuf_vhosts.txt" 2>/dev/null || true
        ok "→ ffuf_vhosts.txt"
    else
        warn "Nenhuma wordlist para vhosts."
    fi
    echo ""
fi

# ═══════════════════════════════════════════
#  FASE 3 — SUBDOMÍNIOS DNS
# ═══════════════════════════════════════════
if ! is_ip "$CLEAN"; then
    echo -e "${BOLD}══ FASE 3: Subdomínios DNS ══${RST}"

    DNS_WL=""
    for wl in "$HOME/Aulas/txts_uteis/subdomains-top1million-5000.txt" \
              "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
              "/usr/share/wordlists/dirb/common.txt"; do
        [[ -f "$wl" ]] && { DNS_WL="$wl"; break; }
    done

    if [[ -n "$DNS_WL" ]]; then
        info "Wordlist: $(basename "$DNS_WL") ($(wc -l < "$DNS_WL") entradas)"

        # Wildcard detection
        rand_sub=$(tr -dc 'a-z' < /dev/urandom | head -c 14)
        wildcard_ip=$(dig +short "${rand_sub}.${CLEAN}" A 2>/dev/null | head -1)

        if [[ -n "$wildcard_ip" ]]; then
            warn "Wildcard DNS (*.${CLEAN} → ${wildcard_ip}). Filtrando."
            WILD_FILTER="--wildcard"
        else
            ok "Sem wildcard DNS."
            WILD_FILTER=""
        fi

        if has gobuster; then
            info "gobuster dns — subdomínios..."
            # shellcheck disable=SC2086
            timeout 120 gobuster dns -d "$CLEAN" \
                -w "$DNS_WL" \
                -t 50 \
                ${WILD_FILTER} \
                -o "${OUTDIR}/dns_brute.txt" \
                --no-error 2>/dev/null || true
            ok "→ dns_brute.txt"

            if [[ -s "${OUTDIR}/dns_brute.txt" ]]; then
                found=$(wc -l < "${OUTDIR}/dns_brute.txt")
                echo -e "    ${GRN}Encontrados: ${found} subdomínios${RST}"
                head -15 "${OUTDIR}/dns_brute.txt" | while read -r line; do
                    echo -e "    ${GRN}→${RST} $line"
                done
                [[ "$found" -gt 15 ]] && echo -e "    ${YLW}... +$((found - 15)) mais${RST}"
            fi
        else
            info "dig — subdomínios (max 500 entradas)..."
            > "${OUTDIR}/dns_brute.txt"
            count=0
            while IFS= read -r sub && [[ $count -lt 500 ]]; do
                [[ -z "$sub" || "$sub" == \#* ]] && continue
                ip=$(dig +short +time=1 +tries=1 "${sub}.${CLEAN}" A 2>/dev/null | head -1)
                if [[ -n "$ip" && "$ip" != "$wildcard_ip" ]]; then
                    echo "${sub}.${CLEAN} → ${ip}" >> "${OUTDIR}/dns_brute.txt"
                    echo -e "    ${GRN}✔${RST} ${sub}.${CLEAN} → ${ip}"
                fi
                count=$((count + 1))
            done < "$DNS_WL"
            ok "→ dns_brute.txt"
        fi
    else
        warn "Nenhuma wordlist DNS encontrada."
    fi
    echo ""
fi

# ═══════════════════════════════════════════
#  FASE 4 — ARQUIVOS COM EXTENSÕES
# ═══════════════════════════════════════════
echo -e "${BOLD}══ FASE 4: Arquivos com extensões ══${RST}"

if has ffuf; then
    if [[ -f "$EXT_WL" ]]; then
        info "ffuf — extensões de: $(basename "$EXT_WL")..."
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" \
            -w "$WORDLIST" \
            -e "$(head -50 "$EXT_WL" | tr '\n' ',' | sed 's/,$//')" \
            -mc 200,204,301,302,307,401 \
            -fc 404 -ac ${FILTER_ARGS} \
            -t 50 -c \
            -o "${OUTDIR}/ffuf_files.json" -of json \
            | tee "${OUTDIR}/ffuf_files.txt" 2>/dev/null
    else
        info "ffuf — extensões padrão..."
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" \
            -w "$WORDLIST" \
            -e .php,.html,.txt,.bak,.old,.conf,.xml,.json,.sql,.zip,.tar.gz,.log \
            -mc 200,204,301,302,307,401 \
            -fc 404 -ac ${FILTER_ARGS} \
            -t 50 -c \
            -o "${OUTDIR}/ffuf_files.json" -of json \
            | tee "${OUTDIR}/ffuf_files.txt" 2>/dev/null
    fi
    ok "→ ffuf_files.txt"

    if [[ -f "$FILES_WL" ]]; then
        info "ffuf — raft files: $(basename "$FILES_WL")..."
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" \
            -w "$FILES_WL" \
            -mc 200,204,301,302,307,401 \
            -fc 404 -ac ${FILTER_ARGS} \
            -t 50 -c \
            -o "${OUTDIR}/ffuf_files_raft.json" -of json \
            | tee "${OUTDIR}/ffuf_files_raft.txt" 2>/dev/null
        ok "→ ffuf_files_raft.txt"
    fi

elif has gobuster; then
    info "gobuster — arquivos com extensões..."
    gobuster dir -u "$BASE_URL" \
        -w "$WORDLIST" \
        -x "php,html,txt,bak,old,conf,xml,json,sql,zip,log" \
        -s "200,204,301,302,307,401" \
        -b "404,403" \
        -t 50 \
        -o "${OUTDIR}/gobuster_files.txt" \
        --no-error 2>/dev/null || true
    ok "→ gobuster_files.txt"
fi

# ── Resumo ──
echo -e "${BOLD}══ RESUMO ══${RST}"
total=0
for f in "${OUTDIR}"/*.txt; do
    if [[ -f "$f" ]] && [[ -s "$f" ]]; then
        count=$(wc -l < "$f")
        total=$((total + count))
        echo -e "    ${GRN}→${RST} $(basename "$f"): ${count} linhas"
    fi
done
ok "Total: ${total} resultados"

echo -e "\n${GRN}━━━ Módulo 04 concluído ━━━${RST}"
