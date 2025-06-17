import requests

def scan_security_headers(url):
    try:
        response = requests.get(url, timeout=10)
        headers = response.headers

        security_headers = {
            "Content-Security-Policy": "Protege contra XSS",
            "Strict-Transport-Security": "Obliga HTTPS",
            "X-Frame-Options": "Previene clickjacking",
            "X-Content-Type-Options": "Evita MIME-sniffing",
            "Referrer-Policy": "Controla envío de referrer",
            "Permissions-Policy": "Restringe funciones del navegador",
            "Access-Control-Allow-Origin": "CORS"
        }

        print(f"\n[+] Cabeceras de seguridad en {url}:\n")
        for header, description in security_headers.items():
            if header in headers:
                print(f"   ✔ {header}: {headers[header]}")
            else:
                print(f"   ✘ {header} no encontrado ({description})")

    except Exception as e:
        print(f"[!] Error al escanear cabeceras de seguridad: {e}")
