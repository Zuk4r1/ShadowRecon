import requests
import re

def crtsh_enum(domain):
    print(f"[+] Enumerando subdominios con crt.sh para: {domain}")
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print("[-] Error en la respuesta de crt.sh")
            return []

        data = response.json()
        subdomains = set()
        for entry in data:
            name_value = entry.get("name_value", "")
            for sub in name_value.split('\n'):
                if domain in sub:
                    subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        print(f"[-] Error al enumerar con crt.sh: {e}")
        return []

def dnsdumpster_enum(domain):
    print(f"[+] Enumerando subdominios con DNSDumpster para: {domain}")
    # Nota: DNSDumpster requiere interacción con cookies y CSRF token.
    # Puedes usar selenium o scrapy para eso. Este es un placeholder.
    print("[!] Integración con DNSDumpster no implementada aún.")
    return []

def enumerate_subdomains(domain):
    all_subdomains = set()

    # Añadir más fuentes si lo deseas
    crtsh_results = crtsh_enum(domain)
    all_subdomains.update(crtsh_results)

    # Placeholder para DNSDumpster u otras fuentes
    # dnsdumpster_results = dnsdumpster_enum(domain)
    # all_subdomains.update(dnsdumpster_results)

    return sorted(all_subdomains)

if __name__ == "__main__":
    target = input("Dominio a enumerar: ")
    results = enumerate_subdomains(target)
    print(f"\n[+] Subdominios encontrados ({len(results)}):")
    for sub in results:
        print(f" - {sub}")
