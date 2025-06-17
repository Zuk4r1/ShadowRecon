import requests

def fuzz_parameters(url, wordlist=None):
    if wordlist is None:
        # Lista básica de parámetros comunes
        wordlist = [
            "id", "user", "admin", "debug", "test", "redirect", "url", "token", 
            "search", "email", "page", "q", "ref", "file", "include"
        ]

    print(f"\n[+] Fuzzing de parámetros en: {url}\n")

    vulnerable_params = []

    for param in wordlist:
        fuzzed_url = f"{url}?{param}=FUZZ"
        try:
            response = requests.get(fuzzed_url, timeout=10)
            if "error" in response.text.lower() or "exception" in response.text.lower():
                print(f"   ⚠ Posible parámetro interesante encontrado: {param}")
                vulnerable_params.append(param)
        except Exception as e:
            print(f"   [!] Error al probar parámetro {param}: {e}")

    if not vulnerable_params:
        print("   ✘ No se detectaron parámetros sensibles.")
    else:
        print(f"\n[✔] Parámetros sospechosos detectados: {', '.join(vulnerable_params)}")

    return vulnerable_params
