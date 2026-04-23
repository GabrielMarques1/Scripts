# 🛠️ Payloads & Offensive Scripts

> Coleção de scripts Python para automação de ataques em CTFs e pentests autorizados.

![Python](https://img.shields.io/badge/Python-3.8%2B-blue?style=flat-square&logo=python)
![License](https://img.shields.io/badge/License-MIT-green?style=flat-square)
![Context](https://img.shields.io/badge/Context-CTF%20%2F%20Pentest-red?style=flat-square)

---

## 📁 Scripts

### [`sqli_blind.py`](./sqli_blind.py) — SQLi Time-Based Blind Dumper ⚡

Ferramenta interativa para exploração de **SQL Injection Time-Based Blind** com múltiplos modos de extração.

**Funcionalidades:**
- 🔍 **Detecção automática** do tipo de banco (MySQL, PostgreSQL, MSSQL) e sintaxe do payload
- 🔢 **Busca binária** — ~7 requests por caractere (em vez de ~70), 10x mais rápido
- 🗄️ Extração de banco, tabelas, colunas e dados
- 📂 **LOAD_FILE** — leitura de arquivos do servidor via time-based
- ⚡ **INTO OUTFILE** — dump instantâneo via escrita na webroot
- ⚡ **Error-Based** — extração por `extractvalue` / `updatexml` quando disponível
- 💾 Salva loot em `.txt` e em banco SQLite local (`loot.db`)
- 🔐 Suporte a CSRF token com cache por thread

**Uso:**
```bash
# Ajuste o alvo e delay no topo do script
python3 sqli_blind.py
```

**Configuração rápida (topo do script):**
```python
TARGET = "http://<alvo>/"
DELAY  = 1        # segundos para o SLEEP/pg_sleep
THREADS = 3       # posições simultâneas (time-based)
```

**Menu interativo:**
```
  0. Detectar injeção (testar payloads)
  1. Descobrir nome do banco
  2. Listar tabelas
  3. Listar colunas
  4. DUMP dados (time-based)
  5. Auto completo (faz tudo sequencial)
  6. Ler arquivo do servidor (LOAD_FILE)
  7. ⚡ DUMP RÁPIDO via INTO OUTFILE
  8. ⚡ DUMP RÁPIDO via Error-Based
```

---

### [`NoSql.py`](./NoSql.py) — NoSQL Injection Credential Extractor

Script para extração de credenciais via **NoSQL Injection** (MongoDB) usando operador `$regex`.

**Técnica:** Enumeração caractere a caractere com regex `^<prefixo><char>` — detecta flag/valor com base no conteúdo da resposta HTTP.

**Uso:**
```bash
# Ajuste a URL e o marcador de sucesso no script
python3 NoSql.py
```

**Configuração:**
```python
url   = "http://<alvo>/login/"
chars = string.printable      # charset testado
# Linha 21: troque "CS{" pelo marcador que indica login bem-sucedido
```

**Exemplo de request gerada:**
```http
POST /login/ HTTP/1.1

email[$regex]=^admin&password[$ne]=a
```

---

### [`recon/`](./recon/) — Recon Automation Toolkit 🔍

Toolkit modular em Bash para automação completa de reconhecimento.

**Módulos:**
| # | Script | Função |
|---|---|---|
| 🎯 | `recon.sh` | Orquestrador principal com menu interativo |
| 01 | `01_subdomains.sh` | WHOIS, DNS, crt.sh, subfinder, amass, alive check |
| 02 | `02_ports.sh` | nmap quick/full, services, OS detect, UDP, vuln scripts |
| 03 | `03_webinfo.sh` | Headers, security headers, whatweb, WAF, robots, paths |
| 04 | `04_dirs.sh` | ffuf/gobuster dirs + extensões + vhosts |
| 05 | `05_vulns.sh` | nikto, nuclei, searchsploit, SSL/TLS, CORS |

**Uso:**
```bash
# Menu interativo
./recon/recon.sh

# Com alvo direto
./recon/recon.sh exemplo.com

# Módulo standalone
./recon/modules/02_ports.sh 10.10.10.1 ./output/10.10.10.1
```

---

## ⚙️ Requisitos

```bash
pip install requests       # Para scripts Python
sudo apt install seclists  # Wordlists para o módulo 04
```

Python 3.8+ · Kali Linux com ferramentas padrão + ffuf.

---

## 🗂️ Estrutura

```
Scripts/
├── sqli_blind.py           # Time-Based Blind SQLi — dumper completo
├── NoSql.py                # NoSQL Injection — extrator por regex
└── recon/
    ├── recon.sh             # Orquestrador principal
    └── modules/
        ├── 01_subdomains.sh # Subdomínios & DNS
        ├── 02_ports.sh      # Port scan & Serviços
        ├── 03_webinfo.sh    # Web fingerprint
        ├── 04_dirs.sh       # Directory bruteforce
        └── 05_vulns.sh      # Vulnerability scan
```

---

## 📌 Notas

- Todos os scripts foram desenvolvidos e testados em ambientes de **CTF / pentest autorizado**.
- Ajuste sempre o **alvo, delay e marcadores de sucesso** antes de executar.
- O `sqli_blind.py` usa uma session por thread para evitar problemas com CSRF tokens.
- Cada módulo do recon funciona **standalone** — pode rodar independente do `recon.sh`.
