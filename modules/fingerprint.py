import requests

def fingerprint_technologies(url):
    try:
        print(f"\n[+] Fingerprinting de tecnologías para: {url}\n")
        response = requests.get(url, timeout=10)
        headers = response.headers

        techs = []

        # Detección básica por headers
        server = headers.get('Server', '')
        powered_by = headers.get('X-Powered-By', '')

        if 'nginx' in server.lower():
            techs.append("Nginx")
        if 'apache' in server.lower():
            techs.append("Apache")
        if 'cloudflare' in server.lower():
            techs.append("Cloudflare")
        if 'php' in powered_by.lower():
            techs.append("PHP")
        if 'express' in powered_by.lower():
            techs.append("Express.js")
        if 'asp.net' in powered_by.lower():
            techs.append("ASP.NET")
        if 'python' in powered_by.lower():
            techs.append("Python")

        # Cookies
        set_cookie = headers.get('Set-Cookie', '')
        if 'wordpress' in set_cookie.lower():
            techs.append("WordPress")
        if 'laravel' in set_cookie.lower():
            techs.append("Laravel")

        if techs:
            for tech in techs:
                print(f"   ✔ Tecnología detectada: {tech}")
        else:
            print("   ✘ No se detectaron tecnologías conocidas.")
    except Exception as e:
        print(f"[!] Error en fingerprinting: {e}")
