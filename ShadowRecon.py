import argparse
import os
import sys
import threading
import logging
import random
import time
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

# Librerías adicionales para máxima agresividad/intrusivo
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

# --- NUEVO: Configuración de logging avanzado ---
LOG_FORMAT = "%(asctime)s [%(levelname)s] %(message)s"
logging.basicConfig(
    level=logging.INFO,
    format=LOG_FORMAT,
    handlers=[
        logging.FileHandler("shadowrecon.log", encoding="utf-8"),
        logging.StreamHandler(sys.stdout)
    ]
)
logger = logging.getLogger("ShadowRecon")

# --- NUEVO: Banner de advertencia legal ---
LEGAL_WARNING = """
[!] ADVERTENCIA LEGAL: El uso de este script sin autorización explícita es ilegal y puede ser detectado.
    Solo úsalo en sistemas que poseas o tengas permiso explícito. El autor NO se responsabiliza por el mal uso.
"""

BANNER = """
 ██████╗  ██████╗ ██╗   ██╗██████╗  ██████╗ ██████╗ ███████╗ ██████╗ 
██╔═══██╗██╔═══██╗██║   ██║██╔══██╗██╔═══██╗██╔══██╗██╔════╝██╔════╝ 
██║   ██║██║   ██║██║   ██║██████╔╝██║   ██║██████╔╝█████╗  ██║  ███╗
██║   ██║██║   ██║██║   ██║██╔═══╝ ██║   ██║██╔═══╝ ██╔══╝  ██║   ██║
╚██████╔╝╚██████╔╝╚██████╔╝██║     ╚██████╔╝██║     ███████╗╚██████╔╝
 ╚═════╝  ╚═════╝  ╚═════╝ ╚═╝      ╚═════╝ ╚═╝     ╚══════╝ ╚═════╝ 
"""
print(BANNER)
print(LEGAL_WARNING)

# --- NUEVO: User-Agents y proxies para rotación ---
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Safari/605.1.15",
    # ...agrega más si lo deseas...
]
PROXIES = [
    # "http://127.0.0.1:8080",
    # "socks5://127.0.0.1:9050",
    # ...agrega proxies si lo deseas...
]

def get_random_headers():
    return {
        "User-Agent": random.choice(USER_AGENTS)
    }

def get_random_proxy():
    return {"http": random.choice(PROXIES), "https": random.choice(PROXIES)} if PROXIES else None

# --- NUEVO: Función para ejecutar módulos con timeout y control de errores ---
def run_module(module_func, *args, timeout=120, **kwargs):
    result = None
    exc = None
    def target():
        nonlocal result, exc
        try:
            result = module_func(*args, **kwargs)
        except Exception as e:
            exc = e
    thread = threading.Thread(target=target)
    thread.daemon = True
    thread.start()
    thread.join(timeout)
    if thread.is_alive():
        logger.error(f"[TIMEOUT] {module_func.__name__} excedió {timeout}s")
        return None
    if exc:
        logger.error(f"[ERROR] {module_func.__name__}: {exc}")
        return None
    return result

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
    # Nuevas opciones
    parser.add_argument("--insecure", action="store_true", help="Ignorar errores de certificado SSL")
    parser.add_argument("--useragent", help="User-Agent personalizado")
    parser.add_argument("--proxy", help="Proxy HTTP/SOCKS personalizado")
    parser.add_argument("--timeout", type=int, default=120, help="Timeout global por módulo (default: 120s)")

    args = parser.parse_args()
    results = {}

    # --- NUEVO: Configuración global de requests ---
    if args.insecure:
        import urllib3
        urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
        os.environ["PYTHONHTTPSVERIFY"] = "0"
    if args.useragent:
        USER_AGENTS.insert(0, args.useragent)
    if args.proxy:
        PROXIES.insert(0, args.proxy)

    # --- NUEVO: Función para lanzar módulos en paralelo (modo agresivo) ---
    def run_all_modules_parallel():
        tasks = []
        with concurrent.futures.ThreadPoolExecutor(max_workers=args.threads) as executor:
            if args.domain:
                tasks.append(executor.submit(run_module, enumerate_subdomains, args.domain, timeout=args.timeout))
                tasks.append(executor.submit(run_module, search_github_secrets, args.domain, timeout=args.timeout))
                tasks.append(executor.submit(run_module, scan_s3_buckets, args.domain, timeout=args.timeout))
                tasks.append(executor.submit(run_module, run_nuclei_scan, args.domain, timeout=args.timeout))
                tasks.append(executor.submit(run_module, run_osint_scan, args.domain, timeout=args.timeout))
                tasks.append(executor.submit(run_module, aggressive_port_scan, args.domain, threads=args.threads, timeout=args.timeout))
            if args.url:
                tasks.append(executor.submit(run_module, fuzz_directories, args.url, args.threads, timeout=args.timeout))
                tasks.append(executor.submit(run_module, extract_api_endpoints, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, scan_security_headers, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, fingerprint_technologies, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, fuzz_parameters, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, brute_force_login, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, ssrf_test, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, crlf_injection, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, host_header_injection, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, upload_malicious_files, args.url, timeout=args.timeout))
                tasks.append(executor.submit(run_module, scan_for_common_vulnerabilities, args.url, timeout=args.timeout))
            # Recoge resultados
            keys = [
                "subdomains", "github_secrets", "s3_buckets", "vulnerabilities", "osint", "ports",
                "fuzzing", "api_endpoints", "headers", "fingerprint", "fuzzparams", "bruteforce",
                "ssrf", "crlf", "hostheader", "upload", "commonvulns"
            ]
            for i, future in enumerate(tasks):
                try:
                    results[keys[i]] = future.result()
                except Exception as e:
                    logger.error(f"[ERROR] {keys[i]}: {e}")

    if args.aggressive:
        logger.warning("[!] MODO AGRESIVO/INTRUSIVO ACTIVADO. ¡Esto puede ser detectado y es potencialmente ilegal sin permiso explícito!")
        args.subs = args.fuzz = args.api = args.github = args.s3 = args.nuclei = args.osint = args.ports = True
        args.headers = args.fingerprint = args.fuzzparams = args.bruteforce = args.ssrf = args.crlf = args.hostheader = args.upload = args.commonvulns = True
        run_all_modules_parallel()
    else:
        try:
            if args.domain and args.subs:
                logger.info("[*] Enumerando subdominios...")
                results["subdomains"] = run_module(enumerate_subdomains, args.domain, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Subdomain enumeration: {e}")

        try:
            if args.url and args.fuzz:
                logger.info("[*] Ejecutando fuzzing...")
                results["fuzzing"] = run_module(fuzz_directories, args.url, args.threads, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Fuzzing: {e}")

        try:
            if args.url and args.api:
                logger.info("[*] Extrayendo endpoints API...")
                results["api_endpoints"] = run_module(extract_api_endpoints, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] API extraction: {e}")

        try:
            if args.domain and args.github:
                logger.info("[*] Buscando credenciales en GitHub...")
                results["github_secrets"] = run_module(search_github_secrets, args.domain, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] GitHub secrets: {e}")

        try:
            if args.domain and args.s3:
                logger.info("[*] Escaneando buckets S3...")
                results["s3_buckets"] = run_module(scan_s3_buckets, args.domain, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] S3 scan: {e}")

        try:
            if args.domain and args.nuclei:
                logger.info("[*] Ejecutando escaneo con Nuclei...")
                results["vulnerabilities"] = run_module(run_nuclei_scan, args.domain, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Nuclei scan: {e}")

        try:
            if args.domain and args.osint:
                logger.info("[*] Recolectando OSINT...")
                results["osint"] = run_module(run_osint_scan, args.domain, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] OSINT: {e}")

        # --- AGRESIVO/INTRUSIVO ---
        try:
            if args.domain and args.ports:
                logger.info("[*] Escaneo agresivo de puertos...")
                results["ports"] = run_module(aggressive_port_scan, args.domain, threads=args.threads, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Port scan: {e}")

        try:
            if args.url and args.headers:
                logger.info("[*] Escaneando cabeceras de seguridad...")
                results["headers"] = run_module(scan_security_headers, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Headers: {e}")

        try:
            if args.url and args.fingerprint:
                logger.info("[*] Fingerprinting de tecnologías...")
                results["fingerprint"] = run_module(fingerprint_technologies, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Fingerprint: {e}")

        try:
            if args.url and args.fuzzparams:
                logger.info("[*] Fuzzing de parámetros GET...")
                results["fuzzparams"] = run_module(fuzz_parameters, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Fuzz params: {e}")

        try:
            if args.url and args.bruteforce:
                logger.info("[*] Fuerza bruta de login...")
                results["bruteforce"] = run_module(brute_force_login, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Bruteforce: {e}")

        try:
            if args.url and args.ssrf:
                logger.info("[*] Test SSRF...")
                results["ssrf"] = run_module(ssrf_test, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] SSRF: {e}")

        try:
            if args.url and args.crlf:
                logger.info("[*] Test CRLF injection...")
                results["crlf"] = run_module(crlf_injection, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] CRLF: {e}")

        try:
            if args.url and args.hostheader:
                logger.info("[*] Test Host Header Injection...")
                results["hostheader"] = run_module(host_header_injection, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Host header: {e}")

        try:
            if args.url and args.upload:
                logger.info("[*] Test de subida de archivos maliciosos...")
                results["upload"] = run_module(upload_malicious_files, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Upload: {e}")

        try:
            if args.url and args.commonvulns:
                logger.info("[*] Escaneo de vulnerabilidades comunes...")
                results["commonvulns"] = run_module(scan_for_common_vulnerabilities, args.url, timeout=args.timeout)
        except Exception as e:
            logger.error(f"[ERROR] Common vulns: {e}")

    if args.report:
        logger.info("[*] Generando reporte...")
        try:
            generate_report(results, args.output)
            logger.info(f"[+] Reporte generado en {args.output}")
        except Exception as e:
            logger.error(f"[ERROR] Generando reporte: {e}")

if __name__ == "__main__":
    try:
        main()
    except Exception as e:
        logger.critical(f"[FATAL] Error inesperado: {e}")
        sys.exit(1)
