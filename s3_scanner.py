import os

def scan_s3_buckets(domain):
    print(f"[+] Escaneando buckets S3 asociados a {domain}...")

    output_file = "s3_buckets.txt"
    os.system(f"python3 ~/LazyS3/lazys3.py -d {domain} -o {output_file}")

    with open(output_file, "r") as f:
        s3_buckets = f.readlines()

    if s3_buckets:
        print("[+] Buckets S3 encontrados:")
        for bucket in s3_buckets:
            print(bucket.strip())
    else:
        print("[-] No se encontraron buckets públicos.")

    return s3_buckets
