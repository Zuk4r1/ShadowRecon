import socket
from concurrent.futures import ThreadPoolExecutor

def scan_port(ip, port, timeout=1):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(timeout)
        sock.connect((ip, port))
        sock.close()
        return port
    except:
        return None

def aggressive_port_scan(target_ip, ports=range(1, 1025), threads=100):
    open_ports = []

    with ThreadPoolExecutor(max_workers=threads) as executor:
        results = executor.map(lambda p: scan_port(target_ip, p), ports)

    for port, result in zip(ports, results):
        if result:
            open_ports.append(port)

    return open_ports
