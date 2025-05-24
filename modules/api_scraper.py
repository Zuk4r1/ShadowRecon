import re
import requests
from urllib.parse import urljoin, urlparse
from collections import deque

def extract_api_endpoints(url, max_depth=2):
    print(f"[+] Buscando endpoints API en {url}...")

    headers = {
        "User-Agent": "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
        "Accept": "*/*",
    }

    try:
        response = requests.get(url, headers=headers, timeout=10)
    except Exception as e:
        print(f"[-] Error al conectar con {url}: {e}")
        return []

    js_files = set(re.findall(r'src=["\'](.*?\.js)["\']', response.text))
    endpoints = set()
    visited_js = set()
    queue = deque([(js_file, 0) for js_file in js_files])

    def fetch_js(js_url):
        try:
            resp = requests.get(js_url, headers=headers, timeout=10)
            if resp.status_code == 200:
                return resp.text
        except Exception:
            pass
        return ""

    while queue:
        js_file, depth = queue.popleft()
        if depth > max_depth:
            continue
        full_js_url = urljoin(url, js_file)
        if full_js_url in visited_js:
            continue
        visited_js.add(full_js_url)
        js_code = fetch_js(full_js_url)
        # Busca endpoints tipo /api/ o URLs completas http(s)://
        matches = re.findall(r'["\']((?:/api/|https?://)[a-zA-Z0-9/_\-\.\?\=\&\%]+)["\']', js_code)
        for m in matches:
            endpoints.add((m, full_js_url))
        # Busca imports de otros JS
        imports = re.findall(r'import.*?["\'](.*?\.js)["\']', js_code)
        for imp in imports:
            queue.append((imp, depth + 1))

    if endpoints:
        print("[+] Endpoints encontrados:")
        for endpoint, src in sorted(endpoints):
            print(f"- {endpoint} (en {src})")
    else:
        print("[-] No se encontraron endpoints.")

    return list(endpoints)
