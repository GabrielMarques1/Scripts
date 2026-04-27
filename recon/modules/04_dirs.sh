#!/bin/bash
# ═══════════════════════════════════════════════════════
#  MÓDULO 04 — Directory Bruteforce
#  Uso standalone: ./04_dirs.sh <alvo> <output_dir>
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
OUTDIR="${2:?Uso: $0 <alvo> <output_dir>}/dirs"
mkdir -p "$OUTDIR"
CLEAN=$(echo "$TARGET" | sed 's|https\?://||;s|/.*||;s|:.*||')

# Detectar URL
if curl -sk --connect-timeout 3 "https://${CLEAN}" -o /dev/null 2>/dev/null; then
    BASE_URL="https://${CLEAN}"
else
    BASE_URL="http://${CLEAN}"
fi

# Wordlists (custom do user + Kali paths)
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

# Wordlist de extensões (para scan de arquivos)
EXT_WL="$HOME/Aulas/txts_uteis/raft-small-extensions.txt"

# Wordlist de arquivos
FILES_WL="$HOME/Aulas/txts_uteis/raft-large-files-lowercase.txt"

# Encontrar wordlist disponível
WORDLIST=""
for wl in "${WORDLISTS[@]}"; do
    if [[ -f "$wl" ]]; then
        WORDLIST="$wl"
        break
    fi
done

if [[ -z "$WORDLIST" ]]; then
    fail "Nenhuma wordlist encontrada!"
    echo "    Instale: sudo apt install seclists wordlists"
    exit 1
fi

echo -e "\n${CYN}━━━ 📂 MÓDULO 04 — Directory Bruteforce ━━━${RST}"
echo -e "${BLU}    URL: ${BASE_URL}${RST}"
echo -e "${BLU}    Wordlist: $(basename "$WORDLIST")${RST}\n"

# ═══════════════════════════════════════════
#  CALIBRAÇÃO — Anti falso positivo
#  Faz requests para paths aleatórios que NÃO existem,
#  captura size/words/lines da resposta padrão do servidor.
#  Usa esses valores para filtrar respostas iguais no ffuf.
# ═══════════════════════════════════════════
info "Calibrando (detectando resposta padrão do servidor)..."

# Gerar 3 paths aleatórios garantidamente inexistentes
CALIBRATION_SIZES=()
CALIBRATION_WORDS=()
CALIBRATION_LINES=()

for i in 1 2 3; do
    rand_path=$(tr -dc 'a-z0-9' < /dev/urandom | head -c 16)
    cal_url="${BASE_URL}/${rand_path}"
    # Uma única request — captura body + status code juntos
    resp=$(curl -sk --connect-timeout 5 -w '\n__HTTP_CODE__%{http_code}' "$cal_url" 2>/dev/null)
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

# Se os 3 tiverem o mesmo size → é a página "not found" do servidor
FILTER_ARGS=""
if [[ "${CALIBRATION_SIZES[0]}" == "${CALIBRATION_SIZES[1]}" && "${CALIBRATION_SIZES[1]}" == "${CALIBRATION_SIZES[2]}" ]]; then
    FILTER_SIZE="${CALIBRATION_SIZES[0]}"
    FILTER_ARGS="-fs ${FILTER_SIZE}"
    ok "Página 404 customizada detectada (size=${FILTER_SIZE}). Filtrando."
elif [[ "${CALIBRATION_WORDS[0]}" == "${CALIBRATION_WORDS[1]}" && "${CALIBRATION_WORDS[1]}" == "${CALIBRATION_WORDS[2]}" ]]; then
    # Size varia (ex: path refletido no body) mas word count é igual
    FILTER_WORDS="${CALIBRATION_WORDS[0]}"
    FILTER_ARGS="-fw ${FILTER_WORDS}"
    ok "Filtro por word count (words=${FILTER_WORDS})."
elif [[ "${CALIBRATION_LINES[0]}" == "${CALIBRATION_LINES[1]}" && "${CALIBRATION_LINES[1]}" == "${CALIBRATION_LINES[2]}" ]]; then
    FILTER_LINES="${CALIBRATION_LINES[0]}"
    FILTER_ARGS="-fl ${FILTER_LINES}"
    ok "Filtro por line count (lines=${FILTER_LINES})."
else
    warn "Respostas variam — usando auto-calibrate (-ac) do ffuf."
    FILTER_ARGS="-ac"
fi

echo ""

# ── ffuf (preferido) ──
if has ffuf; then
    info "ffuf — diretórios..."
    info "Filtros: ${FILTER_ARGS:-nenhum} + -ac"
    # shellcheck disable=SC2086
    ffuf -u "${BASE_URL}/FUZZ" \
        -w "$WORDLIST" \
        -mc 200,204,301,302,307,401,405 \
        -fc 404 \
        -ac \
        ${FILTER_ARGS} \
        -t 50 \
        -c \
        -o "${OUTDIR}/ffuf_dirs.json" \
        -of json \
        | tee "${OUTDIR}/ffuf_dirs.txt" 2>/dev/null
    ok "→ ffuf_dirs.txt"

    # Extensões: usar wordlist custom se existir, senão hardcoded
    info "ffuf — arquivos com extensões..."
    if [[ -f "$EXT_WL" ]]; then
        info "Usando extensões de: $(basename "$EXT_WL")"
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" \
            -w "$WORDLIST" \
            -e "$(head -50 "$EXT_WL" | tr '\n' ',' | sed 's/,$//')" \
            -mc 200,204,301,302,307,401 \
            -fc 404 \
            -ac \
            ${FILTER_ARGS} \
            -t 50 \
            -c \
            -o "${OUTDIR}/ffuf_files.json" \
            -of json \
            | tee "${OUTDIR}/ffuf_files.txt" 2>/dev/null
    else
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" \
            -w "$WORDLIST" \
            -e .php,.html,.txt,.bak,.old,.conf,.xml,.json,.sql,.zip,.tar.gz,.log \
            -mc 200,204,301,302,307,401 \
            -fc 404 \
            -ac \
            ${FILTER_ARGS} \
            -t 50 \
            -c \
            -o "${OUTDIR}/ffuf_files.json" \
            -of json \
            | tee "${OUTDIR}/ffuf_files.txt" 2>/dev/null
    fi
    ok "→ ffuf_files.txt"

    # Se tiver wordlist de arquivos dedicada, rodar também
    if [[ -f "$FILES_WL" ]]; then
        info "ffuf — wordlist de arquivos: $(basename "$FILES_WL")..."
        # shellcheck disable=SC2086
        ffuf -u "${BASE_URL}/FUZZ" \
            -w "$FILES_WL" \
            -mc 200,204,301,302,307,401 \
            -fc 404 \
            -ac \
            ${FILTER_ARGS} \
            -t 50 \
            -c \
            -o "${OUTDIR}/ffuf_files_raft.json" \
            -of json \
            | tee "${OUTDIR}/ffuf_files_raft.txt" 2>/dev/null
        ok "→ ffuf_files_raft.txt"
    fi

# ── gobuster fallback ──
elif has gobuster; then
    # gobuster não tem auto-calibrate, mas filtra por status code
    # Remover 403 que gera muito falso positivo
    info "gobuster — diretórios..."
    gobuster dir -u "$BASE_URL" \
        -w "$WORDLIST" \
        -s "200,204,301,302,307,401,405" \
        -b "404,403" \
        -t 50 \
        -o "${OUTDIR}/gobuster_dirs.txt" \
        --no-error 2>/dev/null || true
    ok "→ gobuster_dirs.txt"

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

else
    fail "Nenhum fuzzer disponível (ffuf/gobuster)."
    exit 1
fi

# ── Bruteforce de subdomínios (DNS) ──
is_ip() { [[ "$1" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; }

if ! is_ip "$CLEAN"; then
    DNS_WL=""
    for wl in "$HOME/Aulas/txts_uteis/subdomains-top1million-5000.txt" \
              "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
              "/usr/share/seclists/Discovery/DNS/subdomains-top1million-20000.txt" \
              "/usr/share/wordlists/amass/subdomains-top1mil-5000.txt" \
              "/usr/share/wordlists/dirb/common.txt"; do
        [[ -f "$wl" ]] && { DNS_WL="$wl"; break; }
    done

    if [[ -n "$DNS_WL" ]]; then
        # Detectar wildcard DNS (domínio resolve qualquer sub)
        rand_sub=$(tr -dc 'a-z' < /dev/urandom | head -c 14)
        wildcard_ip=$(dig +short "${rand_sub}.${CLEAN}" A 2>/dev/null | head -1)

        if [[ -n "$wildcard_ip" ]]; then
            warn "Wildcard DNS detectado (*.${CLEAN} → ${wildcard_ip}). Filtrando."
            WILD_FILTER="--wildcard"  # gobuster
        else
            ok "Sem wildcard DNS."
            WILD_FILTER=""
        fi

        if has gobuster; then
            info "gobuster dns — subdomínios de ${CLEAN}..."
            # shellcheck disable=SC2086
            gobuster dns -d "$CLEAN" \
                -w "$DNS_WL" \
                -t 50 \
                ${WILD_FILTER} \
                -o "${OUTDIR}/dns_brute.txt" \
                --no-error 2>/dev/null || true
            ok "→ dns_brute.txt"

            if [[ -s "${OUTDIR}/dns_brute.txt" ]]; then
                found=$(wc -l < "${OUTDIR}/dns_brute.txt")
                echo -e "\n${BOLD}  Subdomínios encontrados (DNS brute): ${found}${RST}"
                head -20 "${OUTDIR}/dns_brute.txt" | while read -r line; do
                    echo -e "    ${GRN}→${RST} $line"
                done
                [[ "$found" -gt 20 ]] && echo -e "    ${YLW}... +$((found - 20)) mais${RST}"
            fi

        elif has ffuf; then
            info "ffuf dns — subdomínios de ${CLEAN}..."
            # ffuf não tem modo DNS nativo, usar resolução via curl
            > "${OUTDIR}/dns_brute.txt"
            while IFS= read -r sub; do
                ip=$(dig +short "${sub}.${CLEAN}" A 2>/dev/null | head -1)
                if [[ -n "$ip" && "$ip" != "$wildcard_ip" ]]; then
                    echo "${sub}.${CLEAN} → ${ip}" >> "${OUTDIR}/dns_brute.txt"
                    echo -e "    ${GRN}✔${RST} ${sub}.${CLEAN} → ${ip}"
                fi
            done < "$DNS_WL"
            ok "→ dns_brute.txt"
        fi
    else
        warn "Nenhuma wordlist DNS encontrada para bruteforce de subdomínios."
    fi
else
    info "Alvo é IP, pulando bruteforce de subdomínios DNS."
fi

echo ""

# ── Buscar vhosts ──
if has ffuf && ! is_ip "$CLEAN"; then
    info "ffuf — vhost bruteforce..."
    VHOST_WL="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ -f "$VHOST_WL" ]]; then
        # Calibrar: pegar size de um vhost aleatório inexistente
        rand_vhost=$(tr -dc 'a-z' < /dev/urandom | head -c 12)
        vhost_size=$(curl -sk -o /dev/null -w "%{size_download}" -H "Host: ${rand_vhost}.${CLEAN}" "$BASE_URL" 2>/dev/null)

        ffuf -u "$BASE_URL" \
            -H "Host: FUZZ.${CLEAN}" \
            -w "$VHOST_WL" \
            -mc 200,301,302,307 \
            -fs "$vhost_size" \
            -ac \
            -t 50 \
            -c \
            -o "${OUTDIR}/ffuf_vhosts.json" \
            -of json 2>/dev/null | tee "${OUTDIR}/ffuf_vhosts.txt" 2>/dev/null || true
        ok "→ ffuf_vhosts.txt"
    else
        warn "Wordlist vhost não encontrada: ${VHOST_WL}"
    fi
fi

# ── Resumo ──
echo ""
info "Resumo dos achados:"
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

