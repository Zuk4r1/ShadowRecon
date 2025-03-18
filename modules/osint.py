import os

def run_osint_scan(domain):
    print(f"[+] Realizando escaneo OSINT para {domain}...")

    output_file = "osint_results.txt"

    os.system(f"theHarvester -d {domain} -b all -f {output_file}")
    os.system(f"shodan search {domain} >> {output_file}")
    os.system(f"censys search {domain} >> {output_file}")

    with open(output_file, "r") as f:
        osint_data = f.readlines()

    if osint_data:
        print("[+] Resultados de OSINT obtenidos.")
    else:
        print("[-] No se encontraron datos relevantes.")

    return osint_data
