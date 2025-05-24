import os
import requests

def github_api_search(query, token):
    headers = {
        "Authorization": f"token {token}",
        "Accept": "application/vnd.github.v3.text-match+json"
    }
    url = f"https://api.github.com/search/code?q={query}"
    response = requests.get(url, headers=headers)
    if response.status_code == 200:
        return response.json().get("items", [])
    else:
        print(f"[-] Error en la búsqueda API: {response.status_code} {response.text}")
        return []

def search_github_secrets(domain, token, extra_keywords=None):
    print(f"[+] Buscando credenciales filtradas en GitHub para {domain}...")

    keywords = ["password", "api_key", "secret", "token"]
    if extra_keywords:
        keywords.extend(extra_keywords)
    queries = [f'"{domain}" {kw}' for kw in keywords]

    output_file = "github_secrets.txt"
    found_secrets = []

    for query in queries:
        print(f"[+] Buscando con query: {query}")
        items = github_api_search(query, token)
        for item in items:
            repo = item['repository']['full_name']
            file_path = item['path']
            html_url = item['html_url']
            matches = item.get('text_matches', [])
            for match in matches:
                fragment = match.get('fragment', '').strip()
                secret_info = f"Repo: {repo}\nFile: {file_path}\nURL: {html_url}\nFragment: {fragment}\n{'-'*40}"
                found_secrets.append(secret_info)

    # También ejecuta github-dorker como fallback
    dork_query = f"{domain} password OR api_key OR secret OR token"
    os.system(f"github-dorker -q '{dork_query}' -o {output_file}")

    try:
        with open(output_file, "r") as f:
            dorker_secrets = f.readlines()
            for secret in dorker_secrets:
                found_secrets.append(secret.strip())
    except Exception:
        pass

    if found_secrets:
        print("[+] Posibles credenciales filtradas:")
        for secret in found_secrets:
            print(secret)
        with open(output_file, "w") as f:
            for secret in found_secrets:
                f.write(secret + "\n")
    else:
        print("[-] No se encontraron credenciales filtradas.")

    return found_secrets

# Uso de ejemplo:
# token = "TU_TOKEN_PERSONAL_GITHUB"
# search_github_secrets("ejemplo.com", token, extra_keywords=["jwt", "access_key"])
