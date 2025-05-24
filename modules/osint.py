import os
import subprocess

def run_command(command):
    try:
        result = subprocess.check_output(command, shell=True, stderr=subprocess.STDOUT, text=True)
        return result
    except subprocess.CalledProcessError as e:
        return f"Error ejecutando '{command}':\n{e.output}"

def run_osint_scan(domain):
    print(f"[+] Realizando escaneo OSINT avanzado para {domain}...")

    output_file = "osint_results.txt"
    with open(output_file, "w") as f:
        f.write(f"=== OSINT para {domain} ===\n\n")

    # theHarvester
    print("[*] Ejecutando theHarvester...")
    harvester_result = run_command(f"theHarvester -d {domain} -b all")
    with open(output_file, "a") as f:
        f.write("=== theHarvester ===\n")
        f.write(harvester_result + "\n")

    # Shodan
    print("[*] Buscando en Shodan...")
    shodan_result = run_command(f"shodan search {domain}")
    with open(output_file, "a") as f:
        f.write("=== Shodan ===\n")
        f.write(shodan_result + "\n")

    # Censys
    print("[*] Buscando en Censys...")
    censys_result = run_command(f"censys search {domain}")
    with open(output_file, "a") as f:
        f.write("=== Censys ===\n")
        f.write(censys_result + "\n")

    # Sublist3r
    print("[*] Buscando subdominios con Sublist3r...")
    sublist3r_result = run_command(f"sublist3r -d {domain} -o -")
    with open(output_file, "a") as f:
        f.write("=== Sublist3r (Subdominios) ===\n")
        f.write(sublist3r_result + "\n")

    # Whois
    print("[*] Obteniendo información WHOIS...")
    whois_result = run_command(f"whois {domain}")
    with open(output_file, "a") as f:
        f.write("=== WHOIS ===\n")
        f.write(whois_result + "\n")

    # DNSRecon
    print("[*] Ejecutando DNSRecon...")
    dnsrecon_result = run_command(f"dnsrecon -d {domain}")
    with open(output_file, "a") as f:
        f.write("=== DNSRecon ===\n")
        f.write(dnsrecon_result + "\n")

    # HaveIBeenPwned (requiere API Key, aquí solo ejemplo de consulta)
    print("[*] Buscando leaks en HaveIBeenPwned (solo emails encontrados)...")
    emails = []
    for line in harvester_result.splitlines():
        if "@" in line and domain in line:
            emails.append(line.strip())
    for email in set(emails):
        hibp_result = run_command(f"curl -s https://haveibeenpwned.com/unifiedsearch/{email}")
        with open(output_file, "a") as f:
            f.write(f"=== HaveIBeenPwned para {email} ===\n")
            f.write(hibp_result + "\n")

    # Leer resultados
    with open(output_file, "r") as f:
        osint_data = f.readlines()

    if osint_data:
        print("[+] Resultados de OSINT obtenidos y guardados en", output_file)
    else:
        print("[-] No se encontraron datos relevantes.")

    return osint_data
