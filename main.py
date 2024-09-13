import socket
import ipaddress
import threading
import argparse
import asyncio
import aiohttp
import ssl
from queue import Queue
from tqdm import tqdm
from concurrent.futures import ThreadPoolExecutor
import time

# Configuration
NUM_THREADS = 100
DEFAULT_TIMEOUT = 2  
DEFAULT_PORTS = [80, 443, 22, 21, 25, 110, 143, 3306, 8080]  
HTTP_PORTS = [80, 443]
RATE_LIMIT = 10  

queue = Queue()
semaphore = asyncio.Semaphore(RATE_LIMIT)

# DNS Resolution
def resolve_dns(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        print(f"Error: Unable to resolve {target}")
        return None

# Banner Grabbing
def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            s.connect((ip, port))
            banner = s.recv(1024).decode('utf-8').strip()
            if banner:
                print(f"[{ip}:{port}] Banner: {banner}")
    except Exception as e:
        print(f"Error grabbing banner on {ip}:{port}: {e}")

# SSL/TLS Certificate Fetching
def get_ssl_cert(hostname):
    try:
        context = ssl.create_default_context()
        with socket.create_connection((hostname, 443)) as sock:
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                print(f"[{hostname}:443] SSL Certificate: {cert}")
    except Exception as e:
        print(f"Error fetching SSL cert for {hostname}: {e}")

# Asynchronous HTTP Scanning
async def check_service(ip_or_url, port, service_type='HTTP'):
    url = f"http://{ip_or_url}" if port == 80 else f"https://{ip_or_url}"
    async with semaphore:
        try:
            async with aiohttp.ClientSession() as session:
                async with session.get(url, timeout=DEFAULT_TIMEOUT) as response:
                    print(f"[{ip_or_url}:{port}] HTTP {response.status} {response.reason}")
        except Exception as e:
            print(f"Error scanning {service_type} for {ip_or_url}:{port}: {e}")

# Asynchronous Wrapper for Services
async def scan_services_async(ip_or_url, ports):
    tasks = [check_service(ip_or_url, port) for port in ports]
    await asyncio.gather(*tasks)

# General Port Scanning
def scan_port(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                print(f"Open port {port} on {ip}")
                grab_banner(ip, port)
                if port == 443:
                    get_ssl_cert(ip)
    except Exception as e:
        print(f"Error scanning port {ip}:{port}: {e}")

# Worker Function for Threading
def worker(func, ip_or_url):
    while not queue.empty():
        item = queue.get()
        func(ip_or_url, item)
        queue.task_done()

# Start Multiple Threads
def start_threads(num_threads, worker_func, ip_or_url, task_func):
    for _ in range(num_threads):
        thread = threading.Thread(target=worker_func, args=(task_func, ip_or_url))
        thread.daemon = True
        thread.start()

# Scan Ports with Progress Bar
def scan_ports(target, ports, show_progress=False):
    if not is_valid_ip(target) and not target.startswith("http"):
        print("Invalid IP address or URL")
        return

    port_list = parse_ports(ports)
    if show_progress:
        progress = tqdm(total=len(port_list), desc=f"Scanning {target}")
    
    for port in port_list:
        queue.put(port)

    start_threads(NUM_THREADS, worker, target, scan_port)
    
    if show_progress:
        while not queue.empty():
            queue.get()
            progress.update(1)
            queue.task_done()

# Scan Subnet
def scan_subnet(subnet, show_progress=False):
    if not is_valid_subnet(subnet):
        print("Invalid subnet")
        return

    network = ipaddress.ip_network(subnet, strict=False)
    ip_list = [str(ip) for ip in network]
    
    if show_progress:
        progress = tqdm(total=len(ip_list), desc="Scanning subnet")

    for ip in ip_list:
        queue.put(ip)

    start_threads(NUM_THREADS, worker, None, scan_ip)
    
    if show_progress:
        while not queue.empty():
            queue.get()
            progress.update(1)
            queue.task_done()

# Validate Subnet
def is_valid_subnet(subnet):
    try:
        ipaddress.ip_network(subnet, strict=False)
        return True
    except ValueError:
        return False

# Validate IP
def is_valid_ip(ip):
    try:
        ipaddress.ip_address(ip)
        return True
    except ValueError:
        return False

# Service Detection
def detect_service(port):
    services = {
        22: "SSH",
        80: "HTTP",
        443: "HTTPS",
        21: "FTP",
        25: "SMTP",
        110: "POP3",
        143: "IMAP",
        3306: "MySQL",
        8080: "HTTP-Proxy"
    }
    return services.get(port, "Unknown")

# CLI Arguments Parser
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced IP, URL, and Port Scanner Tool")
    parser.add_argument('--target', help='Target IP or URL for scanning (e.g., 192.168.1.1, example.com)', required=True)
    parser.add_argument('--ports', help='Comma-separated list or range of ports (e.g., 22,80-100)', default="80,443")
    parser.add_argument('--full-scan', action='store_true', help='Scan all common ports (default: only HTTP/HTTPS ports)')
    parser.add_argument('--subnet', help='Target subnet for IP scanning (e.g., 192.168.1.0/24)', type=str)
    parser.add_argument('--progress', action='store_true', help='Show a progress bar during the scan')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Set custom timeout in seconds')
    return parser.parse_args()

# Parse Port List and Ranges
def parse_ports(ports):
    port_list = []
    for part in ports.split(','):
        if '-' in part:
            start, end = part.split('-')
            port_list.extend(range(int(start), int(end) + 1))
        else:
            port_list.append(int(part))
    return port_list

# Main Function
if __name__ == "__main__":
    args = parse_args()

    # Set custom timeout if provided
    global DEFAULT_TIMEOUT
    DEFAULT_TIMEOUT = args.timeout

    if args.target:
        resolved_target = resolve_dns(args.target)
        if not resolved_target:
            print(f"Unable to resolve {args.target}")
            exit(1)
        
        ports = parse_ports(args.ports)
        if args.full_scan:
            ports = DEFAULT_PORTS
        asyncio.run(scan_services_async(resolved_target, ports))
        scan_ports(resolved_target, args.ports, show_progress=args.progress)

    elif args.subnet:
        scan_subnet(args.subnet, show_progress=args.progress)

    else:
        print("You must provide a target IP/URL with ports or a subnet to scan.")
