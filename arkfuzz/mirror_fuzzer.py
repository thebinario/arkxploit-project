#!/usr/bin/env python3

"""
Mirror Fuzzer

Exemplo:

python mirror_fuzzer.py \
    --url https://target.com \
    --mirrors https://mirror1.com,https://mirror2.com \
    --wordlist words.txt

Objetivo:
Comparar caminhos entre o alvo principal e mirrors para identificar
conteúdos diferentes, diretórios expostos e possíveis versões distintas.
"""


import argparse
import hashlib
import re
from dataclasses import dataclass
from urllib.parse import urljoin, urlparse
import requests


@dataclass
class Result:
    url: str
    status: int
    length: int
    sha256: str
    body: str


session = requests.Session()
session.headers.update({
    "User-Agent": "Mozilla/5.0",
    "Accept": "*/*",
    "Accept-Language": "en-US,en;q=0.9",
})


def load_words(path: str | None) -> list[str]:
    if path is None:
        return []

    with open(path, encoding="utf-8", errors="ignore") as f:
        return [
            line.strip()
            for line in f
            if line.strip()
        ]


def extract_paths_from_mirror(mirrors: list[str], timeout: int) -> list[str]:
    """
    Faz crawl dos mirrors.

    Diretórios:
        usados apenas para continuar a navegação.

    Arquivos:
        adicionados em discovered e serão testados no target.
    """

    discovered: set[str] = set()

    for mirror in mirrors:

        queue = ["/"]
        visited: set[str] = set()
        mirror_host = urlparse(mirror).netloc

        while queue:

            current_path = queue.pop(0)

            if current_path in visited:
                continue

            visited.add(current_path)

            url = normalize_url(mirror, current_path)
            result = fetch(url, timeout)

            if result is None or result.status != 200:
                continue

            hrefs = re.findall(
                r'href=["\']([^"\']+)["\']',
                result.body,
                re.IGNORECASE,
            )

            print(f"[DEBUG] {url} -> {len(hrefs)} hrefs")

            for href in hrefs:

                if href.startswith(("#", "mailto:", "javascript:")):
                    continue

                absolute = urljoin(url, href)
                parsed = urlparse(absolute)

                # ignora links externos
                if parsed.netloc != mirror_host:
                    continue

                path = parsed.path or "/"

                # ignora parent directory
                if path.endswith("/.."):
                    continue

                #
                # Diretório -> continua crawl
                #
                if href.endswith("/") or path.endswith("/"):

                    if path not in visited:
                        queue.append(path)

                #
                # Arquivo -> guarda para testar no target
                #
                else:
                    discovered.add(path)

    return sorted(discovered)

def extract_paths_from_target(
    target: str,
    seeds: list[str],
    timeout: int,
) -> list[str]:

    discovered: set[str] = set()
    visited: set[str] = set()

    # usa os paths descobertos nos mirrors como ponto de partida
    queue = list(seeds)

    while queue:

        current_path = queue.pop(0)

        if current_path in visited:
            continue

        visited.add(current_path)

        url = normalize_url(target, current_path)
        result = fetch(url, timeout)

        if result is None or result.status != 200:
            continue

        discovered.add(current_path)

        hrefs = re.findall(
            r'href=["\']([^"\']+)["\']',
            result.body,
            re.IGNORECASE,
        )

        for href in hrefs:

            if href.startswith(("#", "mailto:", "javascript:")):
                continue

            absolute = urljoin(url, href)
            parsed = urlparse(absolute)

            # ignora links externos
            if parsed.netloc != urlparse(target).netloc:
                continue

            path = parsed.path or "/"

            if path not in visited:
                queue.append(path)

    return sorted(discovered)


def normalize_url(base: str, path: str) -> str:
    return f"{base.rstrip('/')}/{path.lstrip('/')}"


def fetch(url: str, timeout: int) -> Result | None:
    try:
        response = session.get(
            url,
            timeout=timeout,
            allow_redirects=True,
        )

        return Result(
            url=url,
            status=response.status_code,
            length=len(response.content),
            sha256=hashlib.sha256(response.content).hexdigest(),
            body=response.text,
        )

    except requests.RequestException:
        return None


def is_directory_listing(body: str) -> bool:
    indicators = [
        "Index of /",
        "Parent Directory",
        "Last modified",
        "<title>Index of",
    ]

    body_lower = body.lower()

    for indicator in indicators:
        if indicator.lower() in body_lower:
            return True

    return False


def compare(target: Result | None, mirror: Result | None, path: str):
    if mirror is None:
        return

    # Target inexistente e mirror existe
    if target is None:
        print(f"[+] Mirror respondeu e target falhou")
        print(f"    Path   : {path}")
        print(f"    Mirror : {mirror.url} ({mirror.status})")
        print()
        return

    # 403/401 no target -> 200 no mirror
    if target.status in [401, 403] and mirror.status == 200:
        print("[+] Possível conteúdo exposto no mirror")
        print(f"    Path   : {path}")
        print(f"    Target : {target.url} ({target.status})")
        print(f"    Mirror : {mirror.url} ({mirror.status})")
        print()

    # Conteúdo diferente (ambos 200 mas hash diverge)
    elif (
        target.status == 200
        and mirror.status == 200
        and target.sha256 != mirror.sha256
    ):
        print("[+] Conteúdo diferente entre target e mirror")
        print(f"    Path         : {path}")
        print(f"    Target bytes : {target.length} -> {target.url}")
        print(f"    Mirror bytes : {mirror.length} -> {mirror.url}")
        print()

    # Directory listing no mirror
    if mirror.status == 200 and is_directory_listing(mirror.body):
        print("[+] Directory listing encontrado no mirror")
        print(f"    {mirror.url}")
        print()

def execute(url: str, mirrors: list[str], wordlist: str | None, timeout: int):

    # Paths vindos da wordlist
    all_paths = set(load_words(wordlist))

    #
    # Fase 1 - Crawl dos mirrors
    #
    print("[*] Crawling dos mirrors...")

    mirror_paths = extract_paths_from_mirror(mirrors, timeout)

    print(f"[*] Paths descobertos nos mirrors: {len(mirror_paths)}")

    all_paths.update(mirror_paths)

    #
    # Fase 2 - Crawl do target usando os paths dos mirrors como seed
    #
    print("[*] Crawling do target usando os paths dos mirrors...")

    target_paths = extract_paths_from_target(
        target=url,
        seeds=mirror_paths,
        timeout=timeout,
    )

    print(f"[*] Paths descobertos no target: {len(target_paths)}")

    all_paths.update(target_paths)

    #
    # União final
    #
    all_paths = sorted(all_paths)

    if "/" not in all_paths:
        all_paths.insert(0, "/")

    print()
    print(f"[*] Total final de paths: {len(all_paths)}")
    print()

    #
    # Fase 3 - Apenas validação no target
    #
    for path in all_paths:

        target_url = normalize_url(url, path)
        target_result = fetch(target_url, timeout)

        if target_result:
            print(
                f"[TARGET] {target_result.status} "
                f"{target_result.length} bytes -> {path}"
            )

def main():
    parser = argparse.ArgumentParser(description="Mirror Fuzzer")

    parser.add_argument(
        "--url",
        required=True,
        help="URL principal"
    )

    parser.add_argument(
        "--mirrors",
        required=True,
        help="mirror1.com,mirror2.com"
    )

    parser.add_argument(
        "--wordlist",
        required=False,
        help="Arquivo contendo os paths (opcional quando mirrors são crawleáveis)"
    )

    parser.add_argument(
        "--timeout",
        default=10,
        type=int,
        help="Timeout em segundos"
    )

    args = parser.parse_args()

    mirrors = [
        m.strip()
        for m in args.mirrors.split(",")
        if m.strip()
    ]

    execute(
        url=args.url,
        mirrors=mirrors,
        wordlist=args.wordlist,
        timeout=args.timeout,
    )


if __name__ == "__main__":
    main()