import requests
import re
import os
import time

SECRET_PATTERNS = [
    r'AKIA[0-9A-Z]{16}',  # AWS Access Key ID
    r'(?i)aws(.{0,20})?(secret|key)[^a-zA-Z0-9]([A-Za-z0-9/+=]{40})',  # AWS Secret Key
    r'(?i)api[_-]?key[^a-zA-Z0-9]?([A-Za-z0-9]{16,45})',
    r'(?i)secret[^a-zA-Z0-9]?([A-Za-z0-9]{8,})',
    r'(?i)token[^a-zA-Z0-9]?([A-Za-z0-9\-_=\.]{8,})',
    r'(?i)password[^a-zA-Z0-9]?([A-Za-z0-9!@#$%^&*()_+\-=\[\]{};\'\\:"|<,./<>?]{6,})',
    # ...agrega más patrones según necesidad...
]

def extract_secrets(text):
    secrets = []
    for pattern in SECRET_PATTERNS:
        for match in re.findall(pattern, text):
            if isinstance(match, tuple):
                match = match[-1]
            secrets.append(match)
    return secrets

def search_github_secrets(domain, token=None, max_pages=10, save_file=None):
    print(f"[+] Buscando secretos expuestos en GitHub relacionados con: {domain}")

    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "User-Agent": "ShadowRecon-Tool"
    }
    if token:
        headers["Authorization"] = f"token {token}"

    # Query avanzada
    query = f'"{domain}" (key OR token OR password OR secret OR credentials OR AWS OR API OR bearer OR Authorization)'
    per_page = 100
    results = []
    page = 1

    while page <= max_pages:
        url = f"https://api.github.com/search/code?q={requests.utils.quote(query)}&per_page={per_page}&page={page}"
        try:
            response = requests.get(url, headers=headers, timeout=20)
            if response.status_code == 403:
                print("[-] Rate Limit Excedido. Usa un token personal de GitHub para más resultados.")
                break
            elif response.status_code != 200:
                print(f"[-] Error en la búsqueda: {response.status_code}")
                break

            data = response.json()
            items = data.get("items", [])
            if not items:
                break

            for item in items:
                repo = item.get("repository", {}).get("full_name", "")
                file_path = item.get("path", "")
                html_url = item.get("html_url", "")
                fragment = ""
                secrets_found = []

                # Obtener fragmento de código si está disponible
                text_matches = item.get("text_matches", [])
                for match in text_matches:
                    fragment += match.get("fragment", "") + "\n"
                if not fragment:
                    # Si no hay fragmento, intentar obtener el archivo completo (limitado a 5KB)
                    raw_url = item.get("html_url", "").replace("github.com", "raw.githubusercontent.com").replace("/blob/", "/")
                    try:
                        raw_resp = requests.get(raw_url, timeout=10)
                        if raw_resp.status_code == 200:
                            fragment = raw_resp.text[:5000]
                    except Exception:
                        pass

                secrets_found = extract_secrets(fragment)
                results.append({
                    "repo": repo,
                    "file": file_path,
                    "url": html_url,
                    "secrets": secrets_found,
                    "fragment": fragment[:300]  # Solo muestra los primeros 300 caracteres
                })

            if 'next' not in response.links:
                break
            page += 1
            time.sleep(1)  # Evita rate limit

        except Exception as e:
            print(f"[-] Error durante búsqueda en GitHub: {e}")
            break

    # Guardar resultados si se solicita
    if save_file:
        with open(save_file, "w", encoding="utf-8") as f:
            for r in results:
                f.write(f"{r['repo']} - {r['file']} -> {r['url']}\n")
                if r['secrets']:
                    f.write(f"  [!] Posibles secretos: {r['secrets']}\n")
                f.write(f"  Fragmento:\n{r['fragment']}\n{'-'*60}\n")

    return results

# Ejecución directa para pruebas
if __name__ == "__main__":
    dominio = input("Dominio a buscar en GitHub: ")
    token = os.getenv("GITHUB_TOKEN") or input("Token personal de GitHub (opcional, Enter para omitir): ").strip() or None
    save_file = input("Archivo para guardar resultados (opcional, Enter para omitir): ").strip() or None
    hallazgos = search_github_secrets(dominio, token=token, max_pages=10, save_file=save_file)
    print(f"\n[+] Resultados encontrados ({len(hallazgos)}):")
    for h in hallazgos:
        print(f" - {h['repo']} - {h['file']} -> {h['url']}")
        if h['secrets']:
            print(f"   [!] Posibles secretos: {h['secrets']}")
        print(f"   Fragmento:\n{h['fragment']}\n{'-'*40}")
