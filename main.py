import socket
import ipaddress
import threading
import argparse
import asyncio
import aiohttp
import ssl
from queue import Queue
from tqdm import tqdm
import logging
import sys
import time
import json

# Configuration
NUM_THREADS = 100
DEFAULT_TIMEOUT = 2
DEFAULT_PORTS = [80, 443, 22, 21, 25, 110, 143, 3306, 8080]
HTTP_PORTS = [80, 443]
RATE_LIMIT = 10

queue = Queue()
semaphore = asyncio.Semaphore(RATE_LIMIT)
progress_bar = None
scan_results = {
    'open_ports': [],
    'closed_ports': [],
    'errors': [],
    'start_time': None,
    'end_time': None
}

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# DNS Resolution
def resolve_dns(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        logging.error(f"Unable to resolve {target}")
        return None

# Banner Grabbing
def grab_banner(ip, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(3)  # Shorter timeout for banner grabbing
            s.connect((ip, port))
            
            # Send appropriate banner request based on port
            if port in [80, 8080]:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
            elif port == 443:
                s.sendall(b"HEAD / HTTP/1.1\r\nHost: " + ip.encode() + b"\r\nConnection: close\r\n\r\n")
            else:
                s.sendall(b"\r\n")  # Generic probe
            
            banner = s.recv(1024).decode('utf-8', errors='ignore').strip()
            if banner:
                # Show only first line of banner for cleaner output
                first_line = banner.split('\n')[0].strip()
                if first_line:
                    logging.info(f"[{ip}:{port}] Banner: {first_line}")
    except Exception as e:
        logging.debug(f"Banner grab failed for {ip}:{port}: {e}")  # Changed to debug level

# SSL/TLS Certificate Fetching
def get_ssl_cert(hostname):
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
        with socket.create_connection((hostname, 443), timeout=3) as sock:  # Shorter timeout
            with context.wrap_socket(sock, server_hostname=hostname) as ssock:
                cert = ssock.getpeercert()
                if cert:
                    subject = dict(x[0] for x in cert['subject'])
                    issuer = dict(x[0] for x in cert['issuer'])
                    logging.info(f"[{hostname}:443] SSL Certificate Subject: {subject.get('commonName', 'N/A')}")
                    logging.info(f"[{hostname}:443] SSL Certificate Issuer: {issuer.get('commonName', 'N/A')}")
    except Exception as e:
        logging.debug(f"SSL cert fetch failed for {hostname}: {e}")  # Changed to debug level

# Asynchronous HTTP Scanning
async def check_service(ip_or_url, port, session):
    url = f"http://{ip_or_url}" if port == 80 else f"https://{ip_or_url}"
    try:
        async with session.get(url, timeout=DEFAULT_TIMEOUT) as response:
            logging.info(f"[{ip_or_url}:{port}] HTTP {response.status} {response.reason}")
    except asyncio.TimeoutError:
        logging.warning(f"Timeout error for {url}")
    except Exception as e:
        logging.error(f"Error scanning HTTP service for {url}: {e}")

# Asynchronous Wrapper for Services
async def scan_services_async(ip_or_url, ports):
    async with aiohttp.ClientSession() as session:
        tasks = [check_service(ip_or_url, port, session) for port in ports if port in HTTP_PORTS]
        await asyncio.gather(*tasks)

# General Port Scanning
def scan_port(ip, port, update_progress=True, enable_banner=True, enable_ssl=True):
    global progress_bar, scan_results
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            result = s.connect_ex((ip, port))
            if result == 0:
                scan_results['open_ports'].append({'ip': ip, 'port': port, 'status': 'open'})
                logging.info(f"Open port {port} on {ip}")
                
                if enable_banner:
                    grab_banner(ip, port)
                if enable_ssl and port == 443:
                    get_ssl_cert(ip)
            else:
                scan_results['closed_ports'].append({'ip': ip, 'port': port, 'status': 'closed'})
    except Exception as e:
        scan_results['errors'].append({'ip': ip, 'port': port, 'error': str(e)})
        logging.error(f"Error scanning port {ip}:{port}: {e}")
    finally:
        if progress_bar and update_progress:
            progress_bar.update(1)

# Scan single IP for common ports (for subnet scanning)
def scan_ip(ip, port_list=None, enable_banner=True, enable_ssl=True):
    global progress_bar
    if port_list is None:
        port_list = [22, 80, 443]  # Common ports for quick subnet scan
    
    for port in port_list:
        scan_port(ip, port, update_progress=False, enable_banner=enable_banner, enable_ssl=enable_ssl)  # Don't update progress per port
    
    # Update progress once per IP instead of per port for subnet scanning
    if progress_bar:
        progress_bar.update(1)

# Worker Function for Threading
def worker(func, ip_or_url, enable_banner=True, enable_ssl=True):
    while not queue.empty():
        try:
            item = queue.get(timeout=1)  # Add timeout to prevent hanging
            if func == scan_ip:
                func(item, enable_banner=enable_banner, enable_ssl=enable_ssl)  # For subnet scanning, item is the IP
            else:
                func(ip_or_url, item, enable_banner=enable_banner, enable_ssl=enable_ssl)  # For port scanning, item is the port
            queue.task_done()
        except:
            break

# Start Multiple Threads
def start_threads(num_threads, worker_func, ip_or_url, task_func, enable_banner=True, enable_ssl=True):
    for _ in range(num_threads):
        thread = threading.Thread(target=worker_func, args=(task_func, ip_or_url, enable_banner, enable_ssl))
        thread.daemon = True
        thread.start()

# Scan Ports with Progress Bar
def scan_ports(target, ports, show_progress=False, enable_banner=True, enable_ssl=True):
    global progress_bar
    if not is_valid_ip(target) and not target.startswith("http"):
        logging.error("Invalid IP address or URL")
        return

    port_list = parse_ports(ports)
    if show_progress:
        progress_bar = tqdm(total=len(port_list), desc=f"Scanning {target}")
    
    for port in port_list:
        queue.put(port)

    start_threads(NUM_THREADS, worker, target, scan_port, enable_banner, enable_ssl)
    queue.join()  # Wait for all tasks to complete
    
    if show_progress:
        progress_bar.close()
        progress_bar = None

# Scan Subnet
def scan_subnet(subnet, show_progress=False, enable_banner=True, enable_ssl=True):
    global progress_bar
    if not is_valid_subnet(subnet):
        logging.error("Invalid subnet")
        return

    network = ipaddress.ip_network(subnet, strict=False)
    ip_list = [str(ip) for ip in network]
    
    if show_progress:
        progress_bar = tqdm(total=len(ip_list), desc="Scanning subnet")

    for ip in ip_list:
        queue.put(ip)

    start_threads(NUM_THREADS, worker, None, scan_ip, enable_banner, enable_ssl)
    queue.join()  # Wait for all tasks to complete
    
    if show_progress:
        progress_bar.close()
        progress_bar = None

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

# Print Scan Results Summary
def print_scan_summary():
    global scan_results
    print("\n" + "="*60)
    print("SCAN RESULTS SUMMARY")
    print("="*60)
    
    if scan_results['start_time'] and scan_results['end_time']:
        duration = scan_results['end_time'] - scan_results['start_time']
        print(f"Scan Duration: {duration:.2f} seconds")
    
    print(f"Open Ports Found: {len(scan_results['open_ports'])}")
    print(f"Closed Ports: {len(scan_results['closed_ports'])}")
    print(f"Errors: {len(scan_results['errors'])}")
    
    if scan_results['open_ports']:
        print("\nOPEN PORTS:")
        for result in scan_results['open_ports']:
            print(f"  {result['ip']}:{result['port']} - {result['status']}")
    
    if scan_results['errors']:
        print("\nERRORS:")
        for result in scan_results['errors'][:5]:  # Show first 5 errors
            print(f"  {result['ip']}:{result['port']} - {result['error']}")
        if len(scan_results['errors']) > 5:
            print(f"  ... and {len(scan_results['errors']) - 5} more errors")
    
    print("="*60)

# Save scan results to file
def save_scan_results(filename):
    global scan_results
    try:
        # Add timestamp to results
        results_with_timestamp = scan_results.copy()
        results_with_timestamp['scan_timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_results['start_time']))
        
        with open(filename, 'w') as f:
            json.dump(results_with_timestamp, f, indent=2)
        print(f"Scan results saved to: {filename}")
    except Exception as e:
        logging.error(f"Failed to save results to {filename}: {e}")

# CLI Arguments Parser
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced IP, URL, and Port Scanner Tool")
    parser.add_argument('--target', help='Target IP or URL for scanning (e.g., 192.168.1.1, example.com)')
    parser.add_argument('--ports', help='Comma-separated list or range of ports (e.g., 22,80-100)', default="80,443")
    parser.add_argument('--full-scan', action='store_true', help='Scan all common ports (default: only HTTP/HTTPS ports)')
    parser.add_argument('--subnet', help='Target subnet for IP scanning (e.g., 192.168.1.0/24)', type=str)
    parser.add_argument('--progress', action='store_true', help='Show a progress bar during the scan')
    parser.add_argument('--timeout', type=int, default=DEFAULT_TIMEOUT, help='Set custom timeout in seconds')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner grabbing for faster scanning')
    parser.add_argument('--no-ssl', action='store_true', help='Skip SSL certificate fetching for faster scanning')
    parser.add_argument('--output', help='Save scan results to file (JSON format)')
    return parser.parse_args()

# Main Function
async def main():
    global scan_results
    args = parse_args()

    # Validate that either target or subnet is provided
    if not args.target and not args.subnet:
        logging.error("You must provide either a target IP/URL (--target) or a subnet (--subnet) to scan.")
        sys.exit(1)

    # Reset scan results for new scan
    scan_results = {
        'open_ports': [],
        'closed_ports': [],
        'errors': [],
        'start_time': time.time(),
        'end_time': None
    }

    global DEFAULT_TIMEOUT
    DEFAULT_TIMEOUT = args.timeout

    # Set banner and SSL options
    enable_banner = not args.no_banner
    enable_ssl = not args.no_ssl

    try:
        if args.target:
            resolved_target = resolve_dns(args.target)
            if not resolved_target:
                logging.error(f"Unable to resolve {args.target}")
                sys.exit(1)

            ports = parse_ports(args.ports)
            if args.full_scan:
                ports = DEFAULT_PORTS
            
            # Run async HTTP scanning first
            await scan_services_async(resolved_target, ports)
            
            # Then run port scanning
            scan_ports(resolved_target, args.ports, show_progress=args.progress, 
                      enable_banner=enable_banner, enable_ssl=enable_ssl)

        elif args.subnet:
            scan_subnet(args.subnet, show_progress=args.progress, 
                       enable_banner=enable_banner, enable_ssl=enable_ssl)
    
    finally:
        scan_results['end_time'] = time.time()
        print_scan_summary()
        
        # Save results to file if requested
        if args.output:
            save_scan_results(args.output)

if __name__ == "__main__":
    asyncio.run(main())
