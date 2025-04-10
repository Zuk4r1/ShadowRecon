import requests
import re

def search_github_secrets(domain):
    print(f"[+] Buscando secretos expuestos en GitHub relacionados con: {domain}")
    
    headers = {
        "Accept": "application/vnd.github.v3.text-match+json",
        "User-Agent": "ShadowRecon-Tool"
    }

    # Si tienes un token personal de GitHub, puedes agregarlo así para más capacidad de búsqueda
    # headers["Authorization"] = "token TU_TOKEN_GITHUB"

    query = f"{domain} AND (key OR token OR password OR secret)"
    url = f"https://api.github.com/search/code?q={query}&per_page=10"

    try:
        response = requests.get(url, headers=headers, timeout=15)
        if response.status_code == 403:
            print("[-] Rate Limit Excedido. Usa un token personal de GitHub para más resultados.")
            return []
        elif response.status_code != 200:
            print(f"[-] Error en la búsqueda: {response.status_code}")
            return []

        results = []
        data = response.json()
        for item in data.get("items", []):
            repo = item.get("repository", {}).get("full_name", "")
            file_path = item.get("path", "")
            html_url = item.get("html_url", "")
            results.append(f"{repo} - {file_path} -> {html_url}")
        
        return results

    except Exception as e:
        print(f"[-] Error durante búsqueda en GitHub: {e}")
        return []

# Ejecución directa para pruebas
if __name__ == "__main__":
    dominio = input("Dominio a buscar en GitHub: ")
    hallazgos = search_github_secrets(dominio)
    print(f"\n[+] Resultados encontrados ({len(hallazgos)}):")
    for h in hallazgos:
        print(" -", h)
