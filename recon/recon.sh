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
CONF_FILE="${SCRIPT_DIR}/recon.conf"

# ── Carregar configuração global ──
if [[ -f "$CONF_FILE" ]]; then
    # shellcheck source=recon.conf
    source "$CONF_FILE"
else
    # Defaults se não existir conf
    THREADS_FFUF=50; THREADS_HTTPX=50; THREADS_KATANA=20; THREADS_GAU=5
    TIMEOUT_CURL=5; TIMEOUT_GAU=120; TIMEOUT_AMASS=180
    RATE_LIMIT_ADAPTIVE=true; RATE_LIMIT_MIN_THREADS=5
    CRAWL_DEPTH=3; CLEAN_ANSI=true; REPORT_FORMAT="both"
fi

# Exportar pra módulos
export THREADS_FFUF THREADS_HTTPX THREADS_KATANA THREADS_GAU THREADS_ALIVE
export TIMEOUT_CURL TIMEOUT_FFUF TIMEOUT_GAU TIMEOUT_AMASS TIMEOUT_KATANA
export RATE_LIMIT RATE_LIMIT_ADAPTIVE RATE_LIMIT_MIN_THREADS
export CRAWL_DEPTH CLEAN_ANSI DEFAULT_EXTENSIONS
export GAU_PATH KATANA_PATH URO_PATH HTTPX_PATH

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
    check_tool nmap       || missing=$((missing + 1))
    check_tool curl       || missing=$((missing + 1))
    check_tool dig        || missing=$((missing + 1))
    check_tool whois      || missing=$((missing + 1))

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

    echo -e "\n${BOLD} Recon Avançado:${RST}"
    check_tool httpx       || true
    check_tool gau         || true
    check_tool katana      || true
    check_tool uro         || true

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
    shift
    local extra_args="$*"
    local module_path="${MODULES_DIR}/${module}"
    if [[ ! -f "$module_path" ]]; then
        fail "Módulo não encontrado: ${module}"
        return 1
    fi
    bash "$module_path" "$TARGET" "$OUTPUT_DIR" $extra_args || {
        fail "Módulo '${module}' falhou (exit $?). Continuando..."
        return 1
    }
}

generate_report() {
    local report_txt="${OUTPUT_DIR}/report.txt"
    local report_html="${OUTPUT_DIR}/report.html"

    # ── Relatório TXT (mantido) ──
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
    } > "$report_txt"

    # ── Relatório HTML ──
    cat > "$report_html" <<'HTMLHEAD'
<!DOCTYPE html>
<html lang="pt-BR">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>Recon Report</title>
<style>
  :root { --bg: #0d1117; --card: #161b22; --border: #30363d; --text: #e6edf3;
          --green: #3fb950; --red: #f85149; --yellow: #d29922; --blue: #58a6ff;
          --cyan: #39d2c0; --purple: #bc8cff; }
  * { margin: 0; padding: 0; box-sizing: border-box; }
  body { font-family: 'Segoe UI', system-ui, sans-serif; background: var(--bg); color: var(--text); padding: 2rem; }
  .header { text-align: center; margin-bottom: 2rem; padding: 2rem; background: linear-gradient(135deg, #161b22, #1a2332);
            border: 1px solid var(--border); border-radius: 12px; }
  .header h1 { font-size: 1.8rem; color: var(--cyan); margin-bottom: 0.5rem; }
  .header .meta { color: #8b949e; font-size: 0.9rem; }
  .summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 1rem; margin-bottom: 2rem; }
  .stat { background: var(--card); border: 1px solid var(--border); border-radius: 8px; padding: 1rem; text-align: center; }
  .stat .num { font-size: 1.8rem; font-weight: bold; }
  .stat .label { color: #8b949e; font-size: 0.8rem; margin-top: 0.3rem; }
  .section { background: var(--card); border: 1px solid var(--border); border-radius: 8px; margin-bottom: 1rem; overflow: hidden; }
  .section-header { padding: 1rem 1.2rem; cursor: pointer; display: flex; justify-content: space-between; align-items: center;
                    font-weight: 600; font-size: 1.1rem; transition: background 0.2s; }
  .section-header:hover { background: #1a2332; }
  .section-header .icon { transition: transform 0.3s; }
  .section-header.open .icon { transform: rotate(90deg); }
  .section-body { padding: 0 1.2rem 1.2rem; display: none; }
  .section-body.show { display: block; }
  .file-block { margin-bottom: 1rem; }
  .file-name { color: var(--blue); font-weight: 600; font-size: 0.9rem; margin-bottom: 0.4rem;
               padding: 0.3rem 0; border-bottom: 1px solid var(--border); }
  pre { background: #0d1117; padding: 0.8rem; border-radius: 6px; overflow-x: auto;
        font-size: 0.8rem; line-height: 1.5; white-space: pre-wrap; word-break: break-word; max-height: 400px; overflow-y: auto; }
  .vuln { color: var(--red); } .ok { color: var(--green); } .warn { color: var(--yellow); }
  .badge { display: inline-block; padding: 0.15rem 0.5rem; border-radius: 4px; font-size: 0.75rem; font-weight: 600; }
  .badge-green { background: #1a3a2a; color: var(--green); } .badge-red { background: #3a1a1a; color: var(--red); }
  .badge-yellow { background: #3a2e1a; color: var(--yellow); } .badge-blue { background: #1a2a3a; color: var(--blue); }
  footer { text-align: center; color: #484f58; padding: 2rem; font-size: 0.8rem; }
</style>
</head>
<body>
HTMLHEAD

    # Header
    cat >> "$report_html" <<EOF
<div class="header">
  <h1>🔍 Recon Report</h1>
  <div class="meta">${TARGET_CLEAN} — $(date '+%Y-%m-%d %H:%M:%S')</div>
</div>
EOF

    # Contar resultados por módulo
    local sub_count=0 port_count=0 web_count=0 dir_count=0 vuln_count=0
    [[ -f "${OUTPUT_DIR}/subdomains/all_subdomains.txt" ]] && sub_count=$(wc -l < "${OUTPUT_DIR}/subdomains/all_subdomains.txt" 2>/dev/null || echo 0)
    [[ -f "${OUTPUT_DIR}/subdomains/alive.txt" ]] && alive_count=$(wc -l < "${OUTPUT_DIR}/subdomains/alive.txt" 2>/dev/null || echo 0) || alive_count=0
    [[ -f "${OUTPUT_DIR}/ports/quick_scan.gnmap" ]] && port_count=$(grep -c '/open' "${OUTPUT_DIR}/ports/quick_scan.gnmap" 2>/dev/null || echo 0)
    for f in "${OUTPUT_DIR}/dirs"/ffuf_*.txt "${OUTPUT_DIR}/dirs"/gobuster_*.txt; do
        [[ -f "$f" ]] && dir_count=$((dir_count + $(wc -l < "$f" 2>/dev/null || echo 0)))
    done
    [[ -f "${OUTPUT_DIR}/dirs/params_vulns.txt" ]] && vuln_count=$(grep -c "VULN" "${OUTPUT_DIR}/dirs/params_vulns.txt" 2>/dev/null || echo 0)

    cat >> "$report_html" <<EOF
<div class="summary">
  <div class="stat"><div class="num ok">${sub_count}</div><div class="label">Subdomínios</div></div>
  <div class="stat"><div class="num" style="color:var(--cyan)">${alive_count}</div><div class="label">Alive</div></div>
  <div class="stat"><div class="num" style="color:var(--purple)">${port_count}</div><div class="label">Portas</div></div>
  <div class="stat"><div class="num" style="color:var(--blue)">${dir_count}</div><div class="label">Dirs/Files</div></div>
  <div class="stat"><div class="num vuln">${vuln_count}</div><div class="label">Vulns</div></div>
</div>
EOF

    # Seções
    local section_idx=0
    local -A SECTION_ICONS=( [subdomains]="📡" [ports]="🔌" [webinfo]="🌐" [dirs]="📂" [vulns]="⚠️" )
    local -A SECTION_COLORS=( [subdomains]="var(--green)" [ports]="var(--purple)" [webinfo]="var(--blue)" [dirs]="var(--cyan)" [vulns]="var(--red)" )

    for dir in subdomains ports webinfo dirs vulns; do
        local path="${OUTPUT_DIR}/${dir}"
        [[ ! -d "$path" ]] && continue
        local has_files=false
        for f in "$path"/*.txt "$path"/*.json; do [[ -f "$f" ]] && { has_files=true; break; }; done
        $has_files || continue

        section_idx=$((section_idx + 1))
        local icon="${SECTION_ICONS[$dir]:-📄}"
        local scolor="${SECTION_COLORS[$dir]:-var(--text)}"

        local file_count=0
        for f in "$path"/*.txt; do [[ -f "$f" && -s "$f" ]] && file_count=$((file_count + 1)); done

        cat >> "$report_html" <<EOF
<div class="section">
  <div class="section-header" onclick="toggle(this)" style="color:${scolor}">
    <span>${icon} ${dir^^} <span class="badge badge-blue">${file_count} arquivos</span></span>
    <span class="icon">▶</span>
  </div>
  <div class="section-body">
EOF
        for f in "$path"/*.txt; do
            [[ ! -f "$f" || ! -s "$f" ]] && continue
            local fname
            fname=$(basename "$f")
            # Escapar HTML
            local content
            content=$(sed 's/&/\&amp;/g; s/</\&lt;/g; s/>/\&gt;/g' "$f" | head -500)
            cat >> "$report_html" <<EOF
    <div class="file-block">
      <div class="file-name">📄 ${fname}</div>
      <pre>${content}</pre>
    </div>
EOF
        done

        echo '  </div></div>' >> "$report_html"
    done

    # Footer + JS
    cat >> "$report_html" <<'HTMLFOOT'
<footer>Gerado por Recon Automation Toolkit</footer>
<script>
function toggle(el) {
  el.classList.toggle('open');
  el.nextElementSibling.classList.toggle('show');
}
// Abrir primeira seção por padrão
document.querySelector('.section-header')?.click();
</script>
</body>
</html>
HTMLFOOT

    ok "Relatório TXT: ${report_txt}"
    ok "Relatório HTML: ${report_html}"
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
            1) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "01_subdomains.sh" || true ;;
            2) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "02_ports.sh" || true ;;
            3) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "03_webinfo.sh" || true ;;
            4) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "04_dirs.sh" || true ;;
            5) [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }; run_module "05_vulns.sh" || true ;;
            6)
                [[ -z "${TARGET:-}" ]] && { fail "Defina o alvo (opção 0)"; continue; }
                info "═══ FULL RECON INICIANDO ═══"
                for mod in 01_subdomains.sh 02_ports.sh 03_webinfo.sh 05_vulns.sh; do
                    [[ -f "${MODULES_DIR}/${mod}" ]] && { run_module "$mod" || true; }
                done
                # Módulo 04 em modo auto (sem menu interativo)
                [[ -f "${MODULES_DIR}/04_dirs.sh" ]] && { run_module "04_dirs.sh" auto || true; }
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
