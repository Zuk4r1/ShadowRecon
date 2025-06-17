import requests

def host_header_injection(url):
    print(f"\n[+] Probando Host Header Injection en: {url}\n")

    # Host malicioso para test
    fake_host = "evil.com"

    try:
        headers = {
            "Host": fake_host
        }

        response = requests.get(url, headers=headers, timeout=10, allow_redirects=True)

        reflected = fake_host in response.text or fake_host in str(response.headers)

        if reflected:
            print(f"   ✔ Posible Host Header Injection detectado: '{fake_host}' se reflejó en la respuesta.")
        elif response.status_code in [301, 302] and fake_host in response.headers.get("Location", ""):
            print(f"   ✔ Redirección sospechosa encontrada con Host falso → {response.headers.get('Location')}")
        else:
            print("   ✘ No se detectó vulnerabilidad de Host Header Injection.")
    except Exception as e:
        print(f"   [!] Error durante prueba de Host Header Injection: {e}")
