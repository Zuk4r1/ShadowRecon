import os
import requests
import itertools

def generate_bucket_names(domain):
    # Variantes comunes para fuzzing de nombres de buckets
    patterns = [
        "{domain}",
        "{domain}-backup",
        "{domain}-files",
        "{domain}-media",
        "{domain}-static",
        "{domain}-dev",
        "{domain}-prod",
        "{domain}-test",
        "backup-{domain}",
        "files-{domain}",
        "media-{domain}",
        "static-{domain}",
        "dev-{domain}",
        "prod-{domain}",
        "test-{domain}",
        "{domain}1",
        "{domain}2",
        "{domain}3"
    ]
    domain = domain.replace('.', '-')
    return [p.format(domain=domain) for p in patterns]

def check_bucket_public(bucket_name):
    url = f"http://{bucket_name}.s3.amazonaws.com"
    try:
        r = requests.get(url, timeout=5)
        if r.status_code == 200 and "<ListBucketResult" in r.text:
            return True, r.text
        elif r.status_code == 403:
            return False, None  # Existe pero no es público
        elif r.status_code == 404:
            return None, None  # No existe
    except Exception:
        pass
    return None, None

def download_bucket_files(bucket_name, xml_content, max_files=3):
    # Descarga hasta max_files archivos del bucket si es público
    from xml.etree import ElementTree
    try:
        tree = ElementTree.fromstring(xml_content)
        files = [elem.text for elem in tree.findall('.//{http://s3.amazonaws.com/doc/2006-03-01/}Key')]
        for file_key in files[:max_files]:
            url = f"http://{bucket_name}.s3.amazonaws.com/{file_key}"
            r = requests.get(url, timeout=5)
            if r.status_code == 200:
                with open(f"{bucket_name}_{os.path.basename(file_key)}", "wb") as f:
                    f.write(r.content)
                print(f"[+] Archivo descargado: {bucket_name}_{os.path.basename(file_key)}")
    except Exception as e:
        print(f"[-] Error al descargar archivos de {bucket_name}: {e}")

def scan_s3_buckets(domain):
    print(f"[+] Escaneando buckets S3 asociados a {domain}...")

    output_file = "s3_buckets.txt"
    lazy_s3_path = "/ShadowRecon/modules/lazys3.rb"
    # Check if LazyS3 script exists before running
    if os.path.exists(lazy_s3_path):
        os.system(f"ruby {lazy_s3_path} -d {domain} -o {output_file}")
    else:
        print(f"[-] LazyS3 script not found at {lazy_s3_path}, skipping LazyS3 enumeration.")

    # Leer resultados de LazyS3
    s3_buckets = []
    if os.path.exists(output_file):
        with open(output_file, "r") as f:
            s3_buckets = [line.strip() for line in f if line.strip()]
    else:
        print("[-] LazyS3 no generó resultados.")

    # Añadir variantes generadas por fuzzing
    fuzzed_buckets = generate_bucket_names(domain)
    all_buckets = set(s3_buckets + fuzzed_buckets)

    found_public = []
    for bucket in all_buckets:
        status, xml_content = check_bucket_public(bucket)
        if status is True:
            print(f"[+] Bucket público encontrado: {bucket}")
            found_public.append(bucket)
            download_bucket_files(bucket, xml_content)
        elif status is False:
            print(f"[-] Bucket privado (existe): {bucket}")
        elif status is None:
            print(f"[-] Bucket no existe: {bucket}")

    if found_public:
        print("[+] Buckets S3 públicos encontrados:")
        for bucket in found_public:
            print(bucket)
    else:
        print("[-] No se encontraron buckets públicos.")

    # Limpieza de archivos temporales
    if os.path.exists(output_file):
        os.remove(output_file)

    return list(all_buckets)
