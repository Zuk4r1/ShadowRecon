import os
import subprocess
import json

def fuzz_directories(
    url,
    wordlist="wordlists/common.txt",
    threads=40,
    headers=None,
    cookies=None
):
    print(f"[+] Realizando fuzzing avanzado en {url}...")

    output_file = "fuzzing_results.json"
    cmd = [
        "ffuf",
        "-u", f"{url}/FUZZ",
        "-w", wordlist,
        "-t", str(threads),
        "-o", output_file,
        "-of", "json"
    ]

    if headers:
        for h in headers:
            cmd.extend(["-H", h])
    if cookies:
        cmd.extend(["-b", cookies])

    try:
        subprocess.run(cmd, check=True)
    except subprocess.CalledProcessError as e:
        print(f"[-] Error ejecutando ffuf: {e}")
        return []

    if not os.path.exists(output_file):
        print("[-] No se encontró el archivo de resultados.")
        return []

    with open(output_file, "r") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError:
            print("[-] Error al parsear el JSON de resultados.")
            return []

    results = []
    if "results" in data and data["results"]:
        print("[+] Archivos/directorios encontrados:")
        for entry in data["results"]:
            url_found = entry.get("url")
            status = entry.get("status")
            length = entry.get("length")
            words = entry.get("words")
            lines = entry.get("lines")
            print(f"{url_found} [Status: {status}, Length: {length}, Words: {words}, Lines: {lines}]")
            results.append(entry)
    else:
        print("[-] No se encontraron archivos ni directorios.")

    return results
