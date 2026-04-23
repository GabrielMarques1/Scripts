#!/bin/bash
# ═══════════════════════════════════════════════════════
#  RECON AUTOMATION TOOLKIT
#  Orquestrador principal — chama módulos individuais
# ═══════════════════════════════════════════════════════

set -euo pipefail

# ── Cores ──
RED='\033[0;31m'
GRN='\033[0;32m'
YLW='\033[1;33m'
BLU='\033[0;34m'
MAG='\033[0;35m'
CYN='\033[0;36m'
RST='\033[0m'
BOLD='\033[1m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
MODULES_DIR="${SCRIPT_DIR}/modules"

# ── Funções utilitárias ──
banner() {
    echo -e "${CYN}"
    echo "╔══════════════════════════════════════════════╗"
    echo "║        🔍 RECON AUTOMATION TOOLKIT           ║"
    echo "║        Pentest / CTF / Bug Bounty            ║"
    echo "╚══════════════════════════════════════════════╝"
    echo -e "${RST}"
}

info()  { echo -e "${BLU}[*]${RST} $1"; }
ok()    { echo -e "${GRN}[+]${RST} $1"; }
warn()  { echo -e "${YLW}[!]${RST} $1"; }
fail()  { echo -e "${RED}[-]${RST} $1"; }

check_tool() {
    if command -v "$1" &>/dev/null; then
        echo -e "  ${GRN}✔${RST} $1"
        return 0
    else
        echo -e "  ${RED}✘${RST} $1 ${YLW}(não instalado)${RST}"
        return 1
    fi
}

setup_output() {
    local target="$1"
    local clean
    clean=$(echo "$target" | sed 's|https\?://||;s|/.*||;s|:.*||')
    OUTPUT_DIR="${SCRIPT_DIR}/output/${clean}"
    mkdir -p "${OUTPUT_DIR}"/{subdomains,ports,webinfo,dirs,vulns}
    export OUTPUT_DIR
    export TARGET_CLEAN="$clean"
    ok "Output → ${OUTPUT_DIR}"
}

check_tools() {
    echo ""
    info "Verificando ferramentas instaladas..."
    echo ""
    local missing=0

    echo -e "${BOLD} Essenciais:${RST}"
    check_tool nmap       || ((missing++))
    check_tool curl       || ((missing++))
    check_tool dig        || ((missing++))
    check_tool whois      || ((missing++))

    echo -e "\n${BOLD} Web Recon:${RST}"
    check_tool whatweb     || true
    check_tool wafw00f     || true
    check_tool nikto       || true

    echo -e "\n${BOLD} Bruteforce:${RST}"
    check_tool ffuf        || true
    check_tool gobuster    || true

    echo -e "\n${BOLD} DNS/Subdomains:${RST}"
    check_tool dnsrecon    || true
    check_tool dnsenum     || true
    check_tool subfinder   || true
    check_tool amass       || true
    check_tool theHarvester || true

    echo -e "\n${BOLD} Vuln Scan:${RST}"
    check_tool nuclei      || true
    check_tool searchsploit || true

    echo ""
    if [[ $missing -gt 0 ]]; then
        fail "${missing} ferramenta(s) essencial(is) faltando!"
        return 1
    fi
    ok "Todas as essenciais disponíveis."
}

show_menu() {
    echo ""
    echo -e "${BOLD}═══════════════════════════════════════${RST}"
    echo -e "${CYN} ALVO: ${YLW}${TARGET:-não definido}${RST}"
    echo -e "${BOLD}═══════════════════════════════════════${RST}"
    echo ""
    echo -e "  ${GRN}0${RST}) Definir/mudar alvo"
    echo -e "  ${GRN}1${RST}) Subdomínios & DNS"
    echo -e "  ${GRN}2${RST}) Port scan & Serviços"
    echo -e "  ${GRN}3${RST}) Web fingerprint (tech, WAF, headers)"
    echo -e "  ${GRN}4${RST}) Directory bruteforce"
    echo -e "  ${GRN}5${RST}) Vulnerability scan"
    echo -e "  ${GRN}6${RST}) ${MAG}FULL RECON${RST} (tudo sequencial)"
    echo ""
    echo -e "  ${GRN}t${RST}) Checar ferramentas"
    echo -e "  ${GRN}r${RST}) Ver relatório"
    echo -e "  ${GRN}q${RST}) Sair"
    echo ""
}

run_module() {
    local module="$1"
    local module_path="${MODULES_DIR}/${module}"
    if [[ ! -f "$module_path" ]]; then
        fail "Módulo não encontrado: ${module}"
        return 1
    fi
    bash "$module_path" "$TARGET" "$OUTPUT_DIR"
}

generate_report() {
    local report="${OUTPUT_DIR}/report.txt"
    {
        echo "═══════════════════════════════════════"
        echo " RECON REPORT — ${TARGET_CLEAN}"
        echo " Data: $(date '+%Y-%m-%d %H:%M:%S')"
        echo "═══════════════════════════════════════"
        echo ""
        for dir in subdomains ports webinfo dirs vulns; do
            local path="${OUTPUT_DIR}/${dir}"
            if [[ -d "$path" ]] && ls "$path"/*.txt &>/dev/null 2>&1; then
                echo "━━━ ${dir^^} ━━━"
                for f in "$path"/*.txt; do
                    echo "── $(basename "$f") ──"
                    cat "$f"
                    echo ""
                done
            fi
        done
    } > "$report"
    ok "Relatório salvo em: ${report}"
    cat "$report"
}

main() {
    banner
    check_tools || true

    TARGET="${1:-}"
    if [[ -n "$TARGET" ]]; then
        setup_output "$TARGET"
    fi

    while true; do
        show_menu
        read -rp "$(echo -e "${BLU}[recon]${RST} Opção: ")" opt
        case "$opt" in
            0)
                read -rp "$(echo -e "${YLW}[?]${RST} Alvo (domínio ou IP): ")" TARGET
                [[ -z "$TARGET" ]] && { fail "Alvo vazio."; continue; }
                setup_output "$TARGET"
                ;;
            1) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "01_subdomains.sh" ;;
            2) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "02_ports.sh" ;;
            3) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "03_webinfo.sh" ;;
            4) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "04_dirs.sh" ;;
            5) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "05_vulns.sh" ;;
            6)
                [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }
                info "═══ FULL RECON INICIANDO ═══"
                for mod in 01_subdomains.sh 02_ports.sh 03_webinfo.sh 04_dirs.sh 05_vulns.sh; do
                    [[ -f "${MODULES_DIR}/${mod}" ]] && run_module "$mod"
                done
                generate_report
                ok "═══ FULL RECON COMPLETO ═══"
                ;;
            t) check_tools || true ;;
            r) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo"; continue; }; generate_report ;;
            q) echo -e "\n${GRN}Até mais! 👋${RST}"; exit 0 ;;
            *) warn "Opção inválida." ;;
        esac
    done
}

main "$@"
