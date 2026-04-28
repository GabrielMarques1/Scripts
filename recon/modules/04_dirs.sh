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
            dirs)  color="$GRN" ;;
            subs)  color="$CYN" ;;
            files) color="$MAG" ;;
            ext)   color="$YLW" ;;
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
    echo -e "  ${GRN}6${RST}) ${MAG}FULL${RST} (tudo sequencial)"
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

                if [[ -n "$ext_wl_found" ]]; then
                    echo -e "\n${YLW}[?]${RST} Usar extensões de $(basename "$ext_wl_found")? (s/n)"
                    read -rp "    > " use_ext
                    if [[ "$use_ext" == "s" || "$use_ext" == "" ]]; then
                        local exts
                        exts=$(head -50 "$ext_wl_found" | tr '\n' ',' | sed 's/,$//')
                        scan_extensions "$dir_picked" "$exts"
                    else
                        read -rp "$(echo -e "${YLW}[?]${RST} Extensões (ex: .php,.html,.txt): ")" custom_ext
                        scan_extensions "$dir_picked" "${custom_ext:-.php,.html,.txt,.bak}"
                    fi
                else
                    read -rp "$(echo -e "${YLW}[?]${RST} Extensões (ex: .php,.html,.txt): ")" custom_ext
                    scan_extensions "$dir_picked" "${custom_ext:-.php,.html,.txt,.bak,.old,.conf}"
                fi
                ;;
            5)
                pick_wordlist "files"
                scan_files_only "$PICKED_WL"
                ;;
            6)
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
show_summary
