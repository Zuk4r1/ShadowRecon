import re
import requests

def extract_api_endpoints(url):
    print(f"[+] Buscando endpoints API en {url}...")

    response = requests.get(url)
    js_files = re.findall(r'src=["\'](.*?\.js)["\']', response.text)

    endpoints = []
    
    for js_file in js_files:
        if not js_file.startswith("http"):
            js_file = url + "/" + js_file  # Ajusta rutas relativas
        js_response = requests.get(js_file).text
        matches = re.findall(r'["\'](\/api\/[a-zA-Z0-9/_-]+)["\']', js_response)
        endpoints.extend(matches)

    if endpoints:
        print("[+] Endpoints encontrados:")
        for endpoint in endpoints:
            print(f"- {endpoint}")
    else:
        print("[-] No se encontraron endpoints.")

    return endpoints
