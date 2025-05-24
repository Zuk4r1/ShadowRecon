import requests
import re
import sys
import socket
import argparse
from concurrent.futures import ThreadPoolExecutor

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

def certspotter_enum(domain):
    print(f"[+] Enumerando subdominios con Certspotter para: {domain}")
    url = f"https://api.certspotter.com/v1/issuances?domain={domain}&include_subdomains=true&expand=dns_names"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200:
            print("[-] Error en la respuesta de Certspotter")
            return []
        data = response.json()
        subdomains = set()
        for entry in data:
            for sub in entry.get("dns_names", []):
                if domain in sub:
                    subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        print(f"[-] Error al enumerar con Certspotter: {e}")
        return []

def hackertarget_enum(domain):
    print(f"[+] Enumerando subdominios con HackerTarget para: {domain}")
    url = f"https://api.hackertarget.com/hostsearch/?q={domain}"
    try:
        response = requests.get(url, timeout=10)
        if response.status_code != 200 or "error" in response.text.lower():
            print("[-] Error en la respuesta de HackerTarget")
            return []
        subdomains = set()
        for line in response.text.splitlines():
            sub = line.split(',')[0]
            if domain in sub:
                subdomains.add(sub.strip())
        return sorted(subdomains)
    except Exception as e:
        print(f"[-] Error al enumerar con HackerTarget: {e}")
        return []

def threatcrowd_enum(domain):
    print(f"[+] Enumerando subdominios con ThreatCrowd para: {domain}")
    url = f"https://www.threatcrowd.org/searchApi/v2/domain/report/?domain={domain}"
    try:
        response = requests.get(url, timeout=10)
        data = response.json()
        subdomains = set(data.get("subdomains", []))
        return sorted([s for s in subdomains if domain in s])
    except Exception as e:
        print(f"[-] Error al enumerar con ThreatCrowd: {e}")
        return []

def sublist3r_enum(domain):
    print(f"[+] Enumerando subdominios con Sublist3r API para: {domain}")
    url = f"https://api.sublist3r.com/search.php?domain={domain}"
    try:
        response = requests.get(url, timeout=10)
        subdomains = response.json()
        return sorted([s for s in subdomains if domain in s])
    except Exception as e:
        print(f"[-] Error al enumerar con Sublist3r API: {e}")
        return []

def dnsdumpster_enum(domain):
    print(f"[+] Enumerando subdominios con DNSDumpster para: {domain}")
    # Nota: DNSDumpster requiere interacción con cookies y CSRF token.
    # Puedes usar selenium o scrapy para eso. Este es un placeholder.
    print("[!] Integración con DNSDumpster no implementada aún.")
    return []

def brute_force_enum(domain, wordlist_path):
    print(f"[+] Enumerando subdominios por fuerza bruta para: {domain}")
    subdomains = set()
    try:
        with open(wordlist_path, "r") as f:
            words = [line.strip() for line in f if line.strip()]
        with ThreadPoolExecutor(max_workers=20) as executor:
            futures = []
            for word in words:
                sub = f"{word}.{domain}"
                futures.append(executor.submit(resolve_subdomain, sub))
            for future in futures:
                result = future.result()
                if result:
                    subdomains.add(result)
    except Exception as e:
        print(f"[-] Error en fuerza bruta: {e}")
    return sorted(subdomains)

def resolve_subdomain(subdomain):
    try:
        socket.gethostbyname(subdomain)
        return subdomain
    except:
        return None

def filter_resolvable(subdomains):
    print("[*] Resolviendo subdominios encontrados...")
    valid = set()
    with ThreadPoolExecutor(max_workers=20) as executor:
        results = executor.map(resolve_subdomain, subdomains)
        for res in results:
            if res:
                valid.add(res)
    return sorted(valid)

def enumerate_subdomains(domain, wordlist=None, resolve=False):
    all_subdomains = set()
    all_subdomains.update(crtsh_enum(domain))
    all_subdomains.update(certspotter_enum(domain))
    all_subdomains.update(hackertarget_enum(domain))
    all_subdomains.update(threatcrowd_enum(domain))
    all_subdomains.update(sublist3r_enum(domain))
    # Placeholder para DNSDumpster u otras fuentes
    # dnsdumpster_results = dnsdumpster_enum(domain)
    # all_subdomains.update(dnsdumpster_results)
    if wordlist:
        all_subdomains.update(brute_force_enum(domain, wordlist))
    all_subdomains = set([s.lower() for s in all_subdomains if domain in s])
    if resolve:
        all_subdomains = set(filter_resolvable(all_subdomains))
    return sorted(all_subdomains)

def main():
    parser = argparse.ArgumentParser(description="Subdomain Enumerator Avanzado")
    parser.add_argument("domain", help="Dominio a enumerar")
    parser.add_argument("-w", "--wordlist", help="Wordlist para fuerza bruta")
    parser.add_argument("-r", "--resolve", action="store_true", help="Resolver subdominios encontrados")
    args = parser.parse_args()

    results = enumerate_subdomains(args.domain, args.wordlist, args.resolve)
    print(f"\n[+] Subdominios encontrados ({len(results)}):")
    for sub in results:
        print(f" - {sub}")

if __name__ == "__main__":
    main()
