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

# Nuevos imports para agresividad/intrusión
from modules.ports import aggressive_port_scan
from modules.headers import scan_security_headers
from modules.fingerprint import fingerprint_technologies
from modules.fuzz_params import fuzz_parameters
from modules.bruteforce import brute_force_login
from modules.ssrf import ssrf_test
from modules.crlf import crlf_injection
from modules.hostheader import host_header_injection
from modules.upload import upload_malicious_files
from modules.common_vulns import scan_for_common_vulnerabilities

# Librerías adicionales para máxima agresividad/intrusión
import requests
from bs4 import BeautifulSoup
import shodan
import censys.search
import datetime
import scapy.all as scapy
import nmap
import dns.resolver
import paramiko
import socket
import ssl
import cryptography
import jwt
import socks
import colorama
import concurrent.futures
import pyfiglet
import subprocess
import whois
import tldextract
import pyzipper
import py7zr
import openpyxl
import pandas
import OpenSSL

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
    parser = argparse.ArgumentParser(description="ShadowRecon - Bug Bounty Enumeration Tool (Modo Agresivo/Intrusivo Disponible)")
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
    parser.add_argument("-t", "--threads", type=int, default=20, help="Número de hilos para mejorar velocidad (default: 20)")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo detallado de ejecución")
    # Opciones agresivas/intrusivas
    parser.add_argument("--aggressive", action="store_true", help="Modo agresivo/intrusivo: ejecuta todos los módulos posibles")
    parser.add_argument("--ports", action="store_true", help="Escaneo agresivo de puertos")
    parser.add_argument("--headers", action="store_true", help="Escaneo de cabeceras de seguridad")
    parser.add_argument("--fingerprint", action="store_true", help="Fingerprinting de tecnologías")
    parser.add_argument("--fuzzparams", action="store_true", help="Fuzzing de parámetros GET")
    parser.add_argument("--bruteforce", action="store_true", help="Fuerza bruta de login")
    parser.add_argument("--ssrf", action="store_true", help="Test SSRF")
    parser.add_argument("--crlf", action="store_true", help="Test CRLF injection")
    parser.add_argument("--hostheader", action="store_true", help="Test Host Header Injection")
    parser.add_argument("--upload", action="store_true", help="Test de subida de archivos maliciosos")
    parser.add_argument("--commonvulns", action="store_true", help="Escaneo de vulnerabilidades comunes (open redirect, backups, etc)")

    args = parser.parse_args()
    results = {}

    if args.aggressive:
        print("[!] MODO AGRESIVO/INTRUSIVO ACTIVADO. ¡Esto puede ser detectado y es potencialmente ilegal sin permiso explícito!")
        args.subs = args.fuzz = args.api = args.github = args.s3 = args.nuclei = args.osint = args.ports = True
        args.headers = args.fingerprint = args.fuzzparams = args.bruteforce = args.ssrf = args.crlf = args.hostheader = args.upload = args.commonvulns = True

    try:
        if args.domain and args.subs:
            print("[*] Enumerando subdominios...") if args.verbose else None
            results["subdomains"] = enumerate_subdomains(args.domain)
    except Exception as e:
        print(f"[ERROR] Subdomain enumeration: {e}")

    try:
        if args.url and args.fuzz:
            print("[*] Ejecutando fuzzing...") if args.verbose else None
            results["fuzzing"] = fuzz_directories(args.url, args.threads)
    except Exception as e:
        print(f"[ERROR] Fuzzing: {e}")

    try:
        if args.url and args.api:
            print("[*] Extrayendo endpoints API...") if args.verbose else None
            results["api_endpoints"] = extract_api_endpoints(args.url)
    except Exception as e:
        print(f"[ERROR] API extraction: {e}")

    try:
        if args.domain and args.github:
            print("[*] Buscando credenciales en GitHub...") if args.verbose else None
            results["github_secrets"] = search_github_secrets(args.domain)
    except Exception as e:
        print(f"[ERROR] GitHub secrets: {e}")

    try:
        if args.domain and args.s3:
            print("[*] Escaneando buckets S3...") if args.verbose else None
            results["s3_buckets"] = scan_s3_buckets(args.domain)
    except Exception as e:
        print(f"[ERROR] S3 scan: {e}")

    try:
        if args.domain and args.nuclei:
            print("[*] Ejecutando escaneo con Nuclei...") if args.verbose else None
            results["vulnerabilities"] = run_nuclei_scan(args.domain)
    except Exception as e:
        print(f"[ERROR] Nuclei scan: {e}")

    try:
        if args.domain and args.osint:
            print("[*] Recolectando OSINT...") if args.verbose else None
            results["osint"] = run_osint_scan(args.domain)
    except Exception as e:
        print(f"[ERROR] OSINT: {e}")

    # --- AGRESIVO/INTRUSIVO ---
    try:
        if args.domain and args.ports:
            print("[*] Escaneo agresivo de puertos...") if args.verbose else None
            results["ports"] = aggressive_port_scan(args.domain, threads=args.threads)
    except Exception as e:
        print(f"[ERROR] Port scan: {e}")

    try:
        if args.url and args.headers:
            print("[*] Escaneando cabeceras de seguridad...") if args.verbose else None
            results["headers"] = scan_security_headers(args.url)
    except Exception as e:
        print(f"[ERROR] Headers: {e}")

    try:
        if args.url and args.fingerprint:
            print("[*] Fingerprinting de tecnologías...") if args.verbose else None
            results["fingerprint"] = fingerprint_technologies(args.url)
    except Exception as e:
        print(f"[ERROR] Fingerprint: {e}")

    try:
        if args.url and args.fuzzparams:
            print("[*] Fuzzing de parámetros GET...") if args.verbose else None
            results["fuzzparams"] = fuzz_parameters(args.url)
    except Exception as e:
        print(f"[ERROR] Fuzz params: {e}")

    try:
        if args.url and args.bruteforce:
            print("[*] Fuerza bruta de login...") if args.verbose else None
            results["bruteforce"] = brute_force_login(args.url)
    except Exception as e:
        print(f"[ERROR] Bruteforce: {e}")

    try:
        if args.url and args.ssrf:
            print("[*] Test SSRF...") if args.verbose else None
            results["ssrf"] = ssrf_test(args.url)
    except Exception as e:
        print(f"[ERROR] SSRF: {e}")

    try:
        if args.url and args.crlf:
            print("[*] Test CRLF injection...") if args.verbose else None
            results["crlf"] = crlf_injection(args.url)
    except Exception as e:
        print(f"[ERROR] CRLF: {e}")

    try:
        if args.url and args.hostheader:
            print("[*] Test Host Header Injection...") if args.verbose else None
            results["hostheader"] = host_header_injection(args.url)
    except Exception as e:
        print(f"[ERROR] Host header: {e}")

    try:
        if args.url and args.upload:
            print("[*] Test de subida de archivos maliciosos...") if args.verbose else None
            results["upload"] = upload_malicious_files(args.url)
    except Exception as e:
        print(f"[ERROR] Upload: {e}")

    try:
        if args.url and args.commonvulns:
            print("[*] Escaneo de vulnerabilidades comunes...") if args.verbose else None
            results["commonvulns"] = scan_for_common_vulnerabilities(args.url)
    except Exception as e:
        print(f"[ERROR] Common vulns: {e}")

    if args.report:
        print("[*] Generando reporte...") if args.verbose else None
        generate_report(results, args.output)

if __name__ == "__main__":
    main()
