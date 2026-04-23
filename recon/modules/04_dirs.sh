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

# ── ffuf (preferido) ──
if has ffuf; then
    info "ffuf — diretórios..."
    ffuf -u "${BASE_URL}/FUZZ" \
        -w "$WORDLIST" \
        -mc 200,204,301,302,307,401,403,405 \
        -fc 404 \
        -t 50 \
        -c \
        -o "${OUTDIR}/ffuf_dirs.json" \
        -of json \
        | tee "${OUTDIR}/ffuf_dirs.txt" 2>/dev/null
    ok "→ ffuf_dirs.txt / ffuf_dirs.json"

    # Extensões comuns
    info "ffuf — arquivos com extensões..."
    ffuf -u "${BASE_URL}/FUZZ" \
        -w "$WORDLIST" \
        -e .php,.html,.txt,.bak,.old,.conf,.xml,.json,.sql,.zip,.tar.gz,.log \
        -mc 200,204,301,302,307,401,403 \
        -fc 404 \
        -t 50 \
        -c \
        -o "${OUTDIR}/ffuf_files.json" \
        -of json \
        | tee "${OUTDIR}/ffuf_files.txt" 2>/dev/null
    ok "→ ffuf_files.txt"

# ── gobuster fallback ──
elif has gobuster; then
    info "gobuster — diretórios..."
    gobuster dir -u "$BASE_URL" \
        -w "$WORDLIST" \
        -s "200,204,301,302,307,401,403,405" \
        -t 50 \
        -o "${OUTDIR}/gobuster_dirs.txt" \
        --no-error 2>/dev/null || true
    ok "→ gobuster_dirs.txt"

    info "gobuster — arquivos com extensões..."
    gobuster dir -u "$BASE_URL" \
        -w "$WORDLIST" \
        -x "php,html,txt,bak,old,conf,xml,json,sql,zip,log" \
        -s "200,204,301,302,307,401,403" \
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
    # Pegar o tamanho do response padrão para filtrar
    default_size=$(curl -sk -o /dev/null -w "%{size_download}" "${BASE_URL}" 2>/dev/null)

    ffuf -u "$BASE_URL" \
        -H "Host: FUZZ.${CLEAN}" \
        -w "/usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt" \
        -mc 200,301,302,307 \
        -fs "$default_size" \
        -t 50 \
        -c \
        -o "${OUTDIR}/ffuf_vhosts.json" \
        -of json 2>/dev/null | tee "${OUTDIR}/ffuf_vhosts.txt" 2>/dev/null || true
    ok "→ ffuf_vhosts.txt"
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
