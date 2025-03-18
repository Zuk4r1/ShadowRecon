import argparse
import os
from modules.subdomain_enum import enumerate_subdomains
from modules.fuzzing import fuzz_directories
from modules.api_scraper import extract_api_endpoints
from modules.github_secrets import search_github_secrets
from modules.s3_scanner import scan_s3_buckets
from modules.vulnerability_scanner import run_nuclei_scan
from modules.osint import run_osint_scan
from modules.reporting import generate_report

BANNER = """
 ██████╗  ██████╗ ██╗   ██╗██████╗  ██████╗ ██████╗ ███████╗ ██████╗ 
██╔═══██╗██╔═══██╗██║   ██║██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝ 
██║   ██║██║   ██║██║   ██║██████╔╝██║   ██║██████╔╝█████╗  ██║  ███╗
██║   ██║██║   ██║██║   ██║██╔═══╝ ██║   ██║██╔═══╝ ██╔══╝  ██║   ██║
╚██████╔╝╚██████╔╝╚██████╔╝██║     ╚██████╔╝██║     ███████╗╚██████╔╝
 ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝      ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ 
"""
print(BANNER)

def main():
    parser = argparse.ArgumentParser(description="ShadowRecon - Bug Bounty Enumeration Tool")
    parser.add_argument("-d", "--domain", help="Dominio objetivo")
    parser.add_argument("-u", "--url", help="URL objetivo")
    parser.add_argument("--subs", action="store_true", help="Enumerar subdominios")
    parser.add_argument("--fuzz", action="store_true", help="Fuzzing de directorios y archivos")
    parser.add_argument("--api", action="store_true", help="Extraer endpoints API ocultos")
    parser.add_argument("--github", action="store_true", help="Buscar credenciales filtradas en GitHub")
    parser.add_argument("--s3", action="store_true", help="Escaneo de buckets S3 abiertos")
    parser.add_argument("--nuclei", action="store_true", help="Escanear vulnerabilidades con Nuclei")
    parser.add_argument("--osint", action="store_true", help="Ejecutar escaneo OSINT")
    parser.add_argument("--report", action="store_true", help="Generar reporte final de hallazgos")
    parser.add_argument("-o", "--output", default="reports", help="Directorio de salida para reportes (default: reports/)")
    parser.add_argument("-t", "--threads", type=int, default=10, help="Número de hilos para mejorar velocidad (default: 10)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detallado de ejecución")

    args = parser.parse_args()
    
    results = {}

    if args.domain and args.subs:
        print("[*] Enumerando subdominios...") if args.verbose else None
        results["subdomains"] = enumerate_subdomains(args.domain)
    
    if args.url and args.fuzz:
        print("[*] Ejecutando fuzzing...") if args.verbose else None
        results["fuzzing"] = fuzz_directories(args.url, args.threads)

    if args.url and args.api:
        print("[*] Extrayendo endpoints API...") if args.verbose else None
        results["api_endpoints"] = extract_api_endpoints(args.url)

    if args.domain and args.github:
        print("[*] Buscando credenciales en GitHub...") if args.verbose else None
        results["github_secrets"] = search_github_secrets(args.domain)

    if args.domain and args.s3:
        print("[*] Escaneando buckets S3...") if args.verbose else None
        results["s3_buckets"] = scan_s3_buckets(args.domain)

    if args.domain and args.nuclei:
        print("[*] Ejecutando escaneo con Nuclei...") if args.verbose else None
        results["vulnerabilities"] = run_nuclei_scan(args.domain)

    if args.domain and args.osint:
        print("[*] Recolectando OSINT...") if args.verbose else None
        results["osint"] = run_osint_scan(args.domain)

    if args.report:
        print("[*] Generando reporte...") if args.verbose else None
        generate_report(results, args.output)

if __name__ == "__main__":
    main()
