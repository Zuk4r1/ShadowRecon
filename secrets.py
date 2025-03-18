import os

def search_github_secrets(domain):
    print(f"[+] Buscando credenciales filtradas en GitHub para {domain}...")

    query = f"{domain} password OR api_key OR secret OR token"
    output_file = "github_secrets.txt"

    os.system(f"github-dorker -q '{query}' -o {output_file}")

    with open(output_file, "r") as f:
        secrets = f.readlines()

    if secrets:
        print("[+] Posibles credenciales filtradas:")
        for secret in secrets:
            print(secret.strip())
    else:
        print("[-] No se encontraron credenciales filtradas.")

    return secrets
