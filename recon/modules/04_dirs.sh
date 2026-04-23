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

# Wordlists (Kali paths)
WORDLISTS=(
    "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt"
    "/usr/share/wordlists/dirb/common.txt"
    "/usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt"
    "/usr/share/seclists/Discovery/Web-Content/common.txt"
    "/usr/share/wordlists/dirb/big.txt"
)

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
    rand_path=$(cat /dev/urandom | tr -dc 'a-z0-9' | head -c 16)
    # Capturar size, words e lines da resposta
    resp=$(curl -sk --connect-timeout 5 "${BASE_URL}/${rand_path}" 2>/dev/null)
    code=$(curl -sk -o /dev/null -w "%{http_code}" --connect-timeout 5 "${BASE_URL}/${rand_path}" 2>/dev/null)
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

    # Extensões comuns
    info "ffuf — arquivos com extensões..."
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
    ok "→ ffuf_files.txt"

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

# ── Buscar vhosts ──
if has ffuf; then
    info "ffuf — vhost bruteforce..."
    VHOST_WL="/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
    if [[ -f "$VHOST_WL" ]]; then
        # Calibrar: pegar size de um vhost aleatório inexistente
        rand_vhost=$(cat /dev/urandom | tr -dc 'a-z' | head -c 12)
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

