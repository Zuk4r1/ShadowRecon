import os

def fuzz_directories(url):
    print(f"[+] Realizando fuzzing en {url}...")
    
    wordlist = "wordlists/common.txt"  # Usa un diccionario predefinido
    output_file = "fuzzing_results.txt"

    os.system(f"ffuf -u {url}/FUZZ -w {wordlist} -o {output_file} -of json")

    with open(output_file, "r") as f:
        results = f.readlines()

    if results:
        print("[+] Archivos/directorios encontrados:")
        for line in results:
            print(line.strip())
    else:
        print("[-] No se encontraron archivos ni directorios.")

    return results
