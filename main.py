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
import csv
import random
import configparser
import os

# Configuration
NUM_THREADS = 100
DEFAULT_TIMEOUT = 2
DEFAULT_PORTS = [80, 443, 22, 21, 25, 110, 143, 3306, 8080]
HTTP_PORTS = [80, 443]
RATE_LIMIT = 10

# Service identification based on common ports
COMMON_SERVICES = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    25: "SMTP",
    53: "DNS",
    80: "HTTP",
    110: "POP3",
    135: "RPC",
    139: "NetBIOS-SSN",
    143: "IMAP",
    443: "HTTPS",
    445: "SMB",
    993: "IMAPS",
    995: "POP3S",
    1433: "MS-SQL",
    3306: "MySQL",
    3389: "RDP",
    5432: "PostgreSQL",
    5900: "VNC",
    8080: "HTTP-Proxy",
    8443: "HTTPS-Alt"
}

queue = Queue()
semaphore = asyncio.Semaphore(RATE_LIMIT)
progress_bar = None
scan_results = {
    'open_ports': [],
    'closed_ports': [],
    'errors': [],
    'start_time': None,
    'end_time': None,
    'scan_stats': {
        'total_ports_scanned': 0,
        'total_hosts_scanned': 0,
        'avg_response_time': 0
    }
}

# Setup Logging
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')
console = logging.StreamHandler()
console.setLevel(logging.INFO)
logging.getLogger().addHandler(console)

# Load configuration from file
def load_config(config_file):
    config = configparser.ConfigParser()
    if os.path.exists(config_file):
        try:
            config.read(config_file)
            return config
        except Exception as e:
            logging.warning(f"Failed to load config file {config_file}: {e}")
    return None

# Create default configuration file
def create_default_config(config_file):
    config = configparser.ConfigParser()
    
    config['DEFAULT'] = {
        'timeout': '2',
        'threads': '100',
        'progress': 'true',
        'no_banner': 'false',
        'no_ssl': 'false',
        'stealth': 'false',
        'delay': '0'
    }
    
    config['SCAN_PRESETS'] = {
        'quick': '22,80,443',
        'common': '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080',
        'web': '80,443,8080,8443,8000,9000,9080,9443',
        'database': '1433,3306,5432,1521,27017,6379',
        'remote': '22,23,3389,5900,5800'
    }
    
    try:
        with open(config_file, 'w') as f:
            config.write(f)
        print(f"Default configuration file created: {config_file}")
        return config
    except Exception as e:
        logging.error(f"Failed to create config file {config_file}: {e}")
        return None
def identify_service(port, banner=None):
    service = COMMON_SERVICES.get(port, "Unknown")
    
    # Enhanced service detection based on banners
    if banner:
        banner_lower = banner.lower()
        if "ssh" in banner_lower:
            return "SSH"
        elif "http" in banner_lower:
            return "HTTP" if port != 443 else "HTTPS"
        elif "ftp" in banner_lower:
            return "FTP"
        elif "smtp" in banner_lower:
            return "SMTP"
        elif "mysql" in banner_lower:
            return "MySQL"
        elif "postgresql" in banner_lower:
            return "PostgreSQL"
    
    return service
def resolve_dns(target):
    try:
        return socket.gethostbyname(target)
    except socket.gaierror:
        logging.error(f"Unable to resolve {target}")
        return None

# Banner Grabbing
def grab_banner(ip, port):
    try:
        start_time = time.time()
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
            response_time = time.time() - start_time
            
            if banner:
                # Show only first line of banner for cleaner output
                first_line = banner.split('\n')[0].strip()
                if first_line:
                    logging.info(f"[{ip}:{port}] Banner: {first_line}")
                    return first_line, response_time
            return None, response_time
    except Exception as e:
        logging.debug(f"Banner grab failed for {ip}:{port}: {e}")  # Changed to debug level
        return None, 0

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
                    
                    # Get certificate details
                    common_name = subject.get('commonName', 'N/A')
                    issuer_name = issuer.get('commonName', 'N/A')
                    
                    # Check if certificate is valid
                    not_before = cert.get('notBefore', '')
                    not_after = cert.get('notAfter', '')
                    
                    # Get protocol and cipher
                    protocol = ssock.version()
                    cipher = ssock.cipher()
                    cipher_name = cipher[0] if cipher else 'Unknown'
                    
                    ssl_info = {
                        'subject_cn': common_name,
                        'issuer_cn': issuer_name,
                        'not_before': not_before,
                        'not_after': not_after,
                        'protocol': protocol,
                        'cipher': cipher_name
                    }
                    
                    logging.info(f"[{hostname}:443] SSL Certificate: {common_name} (Issuer: {issuer_name})")
                    logging.info(f"[{hostname}:443] SSL Protocol: {protocol}, Cipher: {cipher_name}")
                    
                    # Store SSL info in scan results
                    for result in scan_results['open_ports']:
                        if result['ip'] == hostname and result['port'] == 443:
                            result['ssl_info'] = ssl_info
                            break
                    
                    return ssl_info
    except Exception as e:
        logging.debug(f"SSL cert fetch failed for {hostname}: {e}")  # Changed to debug level
        return None

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
def scan_port(ip, port, update_progress=True, enable_banner=True, enable_ssl=True, delay=0):
    global progress_bar, scan_results
    
    # Add stealth delay if specified
    if delay > 0:
        time.sleep(delay + random.uniform(0, delay * 0.5))  # Add random jitter
    
    start_time = time.time()
    banner = None
    response_time = 0
    
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.settimeout(DEFAULT_TIMEOUT)
            result = s.connect_ex((ip, port))
            response_time = time.time() - start_time
            
            if result == 0:
                service = identify_service(port)
                
                # Get banner if enabled
                if enable_banner:
                    banner, banner_response_time = grab_banner(ip, port)
                    if banner:
                        service = identify_service(port, banner)
                        response_time = banner_response_time
                
                port_result = {
                    'ip': ip, 
                    'port': port, 
                    'status': 'open',
                    'service': service,
                    'response_time': round(response_time * 1000, 2),  # Convert to milliseconds
                    'banner': banner if banner else None
                }
                
                scan_results['open_ports'].append(port_result)
                logging.info(f"Open port {port} on {ip} ({service})")
                
                if enable_ssl and port == 443:
                    get_ssl_cert(ip)
            else:
                scan_results['closed_ports'].append({
                    'ip': ip, 
                    'port': port, 
                    'status': 'closed',
                    'response_time': round(response_time * 1000, 2)
                })
                
    except Exception as e:
        scan_results['errors'].append({'ip': ip, 'port': port, 'error': str(e)})
        logging.error(f"Error scanning port {ip}:{port}: {e}")
    finally:
        scan_results['scan_stats']['total_ports_scanned'] += 1
        if progress_bar and update_progress:
            progress_bar.update(1)

# Scan single IP for common ports (for subnet scanning)
def scan_ip(ip, port_list=None, enable_banner=True, enable_ssl=True, delay=0):
    global progress_bar
    if port_list is None:
        port_list = [22, 80, 443]  # Common ports for quick subnet scan
    
    for port in port_list:
        scan_port(ip, port, update_progress=False, enable_banner=enable_banner, enable_ssl=enable_ssl, delay=delay)  # Don't update progress per port
    
    # Update progress once per IP instead of per port for subnet scanning
    if progress_bar:
        progress_bar.update(1)

# Worker Function for Threading
def worker(func, ip_or_url, enable_banner=True, enable_ssl=True, delay=0):
    while not queue.empty():
        try:
            item = queue.get(timeout=1)  # Add timeout to prevent hanging
            if func == scan_ip:
                func(item, enable_banner=enable_banner, enable_ssl=enable_ssl, delay=delay)  # For subnet scanning, item is the IP
            else:
                func(ip_or_url, item, enable_banner=enable_banner, enable_ssl=enable_ssl, delay=delay)  # For port scanning, item is the port
            queue.task_done()
        except:
            break

# Start Multiple Threads
def start_threads(num_threads, worker_func, ip_or_url, task_func, enable_banner=True, enable_ssl=True, delay=0):
    for _ in range(num_threads):
        thread = threading.Thread(target=worker_func, args=(task_func, ip_or_url, enable_banner, enable_ssl, delay))
        thread.daemon = True
        thread.start()

# Scan Ports with Progress Bar
def scan_ports(target, ports, show_progress=False, enable_banner=True, enable_ssl=True, stealth=False, delay=0):
    global progress_bar
    if not is_valid_ip(target) and not target.startswith("http"):
        logging.error("Invalid IP address or URL")
        return

    port_list = parse_ports(ports)
    
    # Randomize port order for stealth mode
    if stealth:
        random.shuffle(port_list)
        if delay == 0:
            delay = random.uniform(0.1, 0.5)  # Default stealth delay
    
    if show_progress:
        progress_bar = tqdm(total=len(port_list), desc=f"Scanning {target}")
    
    for port in port_list:
        queue.put(port)

    # Reduce thread count for stealth mode
    threads = 1 if stealth else NUM_THREADS
    start_threads(threads, worker, target, scan_port, enable_banner, enable_ssl, delay)
    queue.join()  # Wait for all tasks to complete
    
    if show_progress:
        progress_bar.close()
        progress_bar = None

# Scan Subnet
def scan_subnet(subnet, show_progress=False, enable_banner=True, enable_ssl=True, stealth=False, delay=0):
    global progress_bar
    if not is_valid_subnet(subnet):
        logging.error("Invalid subnet")
        return

    network = ipaddress.ip_network(subnet, strict=False)
    ip_list = [str(ip) for ip in network]
    
    # Randomize IP order for stealth mode
    if stealth:
        random.shuffle(ip_list)
        if delay == 0:
            delay = random.uniform(0.1, 0.5)
    
    if show_progress:
        progress_bar = tqdm(total=len(ip_list), desc="Scanning subnet")

    for ip in ip_list:
        queue.put(ip)

    # Reduce thread count for stealth mode
    threads = 1 if stealth else NUM_THREADS
    start_threads(threads, worker, None, scan_ip, enable_banner, enable_ssl, delay)
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
    print("\n" + "="*80)
    print("SCAN RESULTS SUMMARY")
    print("="*80)
    
    if scan_results['start_time'] and scan_results['end_time']:
        duration = scan_results['end_time'] - scan_results['start_time']
        print(f"Scan Duration: {duration:.2f} seconds")
    
    stats = scan_results['scan_stats']
    print(f"Total Ports Scanned: {stats['total_ports_scanned']}")
    print(f"Total Hosts Scanned: {stats.get('total_hosts_scanned', 1)}")
    print(f"Open Ports Found: {len(scan_results['open_ports'])}")
    print(f"Closed Ports: {len(scan_results['closed_ports'])}")
    print(f"Errors: {len(scan_results['errors'])}")
    
    if scan_results['open_ports']:
        print("\nOPEN PORTS:")
        print(f"{'IP':<15} {'Port':<6} {'Service':<12} {'Response(ms)':<12} {'Banner'}")
        print("-" * 80)
        for result in scan_results['open_ports']:
            banner = result.get('banner', '')
            if banner and len(banner) > 40:
                banner = banner[:37] + "..."
            print(f"{result['ip']:<15} {result['port']:<6} {result.get('service', 'Unknown'):<12} "
                  f"{result.get('response_time', 0):<12} {banner}")
            
            # Show SSL information if available
            if result.get('ssl_info'):
                ssl_info = result['ssl_info']
                print(f"{'':>15} {'':>6} {'SSL Info:':<12} {ssl_info.get('protocol', 'N/A')} - {ssl_info.get('subject_cn', 'N/A')}")
    
    if scan_results['errors']:
        print("\nERRORS:")
        for result in scan_results['errors'][:5]:  # Show first 5 errors
            print(f"  {result['ip']}:{result['port']} - {result['error']}")
        if len(scan_results['errors']) > 5:
            print(f"  ... and {len(scan_results['errors']) - 5} more errors")
    
    # Show scan statistics
    if scan_results['open_ports']:
        response_times = [r.get('response_time', 0) for r in scan_results['open_ports']]
        avg_response = sum(response_times) / len(response_times) if response_times else 0
        print(f"\nSCAN STATISTICS:")
        print(f"Average Response Time: {avg_response:.2f}ms")
        print(f"Fastest Response: {min(response_times):.2f}ms")
        print(f"Slowest Response: {max(response_times):.2f}ms")
    
    print("="*80)

# Save scan results to file
def save_scan_results(filename):
    global scan_results
    try:
        # Add timestamp to results
        results_with_timestamp = scan_results.copy()
        results_with_timestamp['scan_timestamp'] = time.strftime('%Y-%m-%d %H:%M:%S', time.localtime(scan_results['start_time']))
        
        # Determine format based on file extension
        if filename.lower().endswith('.csv'):
            save_csv_results(filename)
        else:
            # Default to JSON
            with open(filename, 'w') as f:
                json.dump(results_with_timestamp, f, indent=2)
        print(f"Scan results saved to: {filename}")
    except Exception as e:
        logging.error(f"Failed to save results to {filename}: {e}")

# Save results in CSV format
def save_csv_results(filename):
    global scan_results
    try:
        with open(filename, 'w', newline='') as csvfile:
            writer = csv.writer(csvfile)
            
            # Write header
            writer.writerow(['IP', 'Port', 'Status', 'Service', 'Response_Time_ms', 'Banner', 'SSL_Protocol', 'SSL_Subject'])
            
            # Write open ports
            for result in scan_results['open_ports']:
                ssl_protocol = ''
                ssl_subject = ''
                if result.get('ssl_info'):
                    ssl_info = result['ssl_info']
                    ssl_protocol = ssl_info.get('protocol', '')
                    ssl_subject = ssl_info.get('subject_cn', '')
                
                writer.writerow([
                    result['ip'],
                    result['port'],
                    result['status'],
                    result.get('service', 'Unknown'),
                    result.get('response_time', ''),
                    result.get('banner', ''),
                    ssl_protocol,
                    ssl_subject
                ])
            
            # Write closed ports (optional, but useful for comprehensive reporting)
            for result in scan_results['closed_ports']:
                writer.writerow([
                    result['ip'],
                    result['port'],
                    result['status'],
                    '',  # No service for closed ports
                    result.get('response_time', ''),
                    '',  # No banner for closed ports
                    '',  # No SSL for closed ports
                    ''   # No SSL for closed ports
                ])
                
    except Exception as e:
        logging.error(f"Failed to save CSV results to {filename}: {e}")

# CLI Arguments Parser
def parse_args():
    parser = argparse.ArgumentParser(description="Advanced IP, URL, and Port Scanner Tool")
    parser.add_argument('--target', help='Target IP or URL for scanning (e.g., 192.168.1.1, example.com)')
    parser.add_argument('--ports', help='Comma-separated list or range of ports (e.g., 22,80-100)')
    parser.add_argument('--full-scan', action='store_true', help='Scan all common ports (default: only HTTP/HTTPS ports)')
    parser.add_argument('--subnet', help='Target subnet for IP scanning (e.g., 192.168.1.0/24)', type=str)
    parser.add_argument('--progress', action='store_true', help='Show a progress bar during the scan')
    parser.add_argument('--timeout', type=int, help='Set custom timeout in seconds')
    parser.add_argument('--no-banner', action='store_true', help='Skip banner grabbing for faster scanning')
    parser.add_argument('--no-ssl', action='store_true', help='Skip SSL certificate fetching for faster scanning')
    parser.add_argument('--output', help='Save scan results to file (.json or .csv format)')
    parser.add_argument('--stealth', action='store_true', help='Enable stealth mode (randomize port order, add delays)')
    parser.add_argument('--delay', type=float, help='Add delay between port scans (seconds)')
    parser.add_argument('--config', help='Load settings from configuration file')
    parser.add_argument('--create-config', help='Create a default configuration file at specified path')
    parser.add_argument('--preset', help='Use predefined port preset (quick, common, web, database, remote)')
    return parser.parse_args()

# Main Function
async def main():
    global scan_results, DEFAULT_TIMEOUT, NUM_THREADS
    args = parse_args()
    
    # Handle config file creation
    if args.create_config:
        create_default_config(args.create_config)
        return

    # Load configuration file if specified
    config = None
    if args.config:
        config = load_config(args.config)
        if not config:
            logging.error(f"Failed to load configuration file: {args.config}")
            sys.exit(1)

    # Apply config defaults if available
    if config and 'DEFAULT' in config:
        defaults = config['DEFAULT']
        if not args.timeout:
            args.timeout = int(defaults.get('timeout', DEFAULT_TIMEOUT))
        if not args.progress and defaults.getboolean('progress', False):
            args.progress = True
        if not args.no_banner and defaults.getboolean('no_banner', False):
            args.no_banner = True
        if not args.no_ssl and defaults.getboolean('no_ssl', False):
            args.no_ssl = True
        if not args.stealth and defaults.getboolean('stealth', False):
            args.stealth = True
        if not args.delay:
            args.delay = float(defaults.get('delay', 0))
        
        # Override thread count from config
        NUM_THREADS = int(defaults.get('threads', NUM_THREADS))

    # Handle presets
    preset_ports = None
    if args.preset:
        if config and 'SCAN_PRESETS' in config and args.preset in config['SCAN_PRESETS']:
            preset_ports = config['SCAN_PRESETS'][args.preset]
        else:
            # Built-in presets
            presets = {
                'quick': '22,80,443',
                'common': '21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080',
                'web': '80,443,8080,8443,8000,9000,9080,9443',
                'database': '1433,3306,5432,1521,27017,6379',
                'remote': '22,23,3389,5900,5800'
            }
            preset_ports = presets.get(args.preset)
            
        if not preset_ports:
            logging.error(f"Unknown preset: {args.preset}")
            logging.info("Available presets: quick, common, web, database, remote")
            sys.exit(1)

    # Set default ports
    if not args.ports:
        if preset_ports:
            args.ports = preset_ports
        elif args.full_scan:
            args.ports = ','.join(map(str, DEFAULT_PORTS))
        else:
            args.ports = "80,443"  # Default
    
    # Apply timeout
    if not args.timeout:
        args.timeout = DEFAULT_TIMEOUT
    
    # Apply delay default
    if not args.delay:
        args.delay = 0
    
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
        'end_time': None,
        'scan_stats': {
            'total_ports_scanned': 0,
            'total_hosts_scanned': 1 if args.target else 0,
            'avg_response_time': 0
        }
    }

    DEFAULT_TIMEOUT = args.timeout

    # Set banner and SSL options
    enable_banner = not args.no_banner
    enable_ssl = not args.no_ssl
    
    # Set stealth mode options
    stealth_mode = args.stealth
    delay = args.delay
    
    if stealth_mode:
        logging.info("Stealth mode enabled - randomizing scan order and adding delays")
    
    if args.preset:
        logging.info(f"Using preset: {args.preset} ({args.ports})")

    try:
        if args.target:
            resolved_target = resolve_dns(args.target)
            if not resolved_target:
                logging.error(f"Unable to resolve {args.target}")
                sys.exit(1)

            ports = parse_ports(args.ports)
            if args.full_scan:
                ports = DEFAULT_PORTS
            
            # Run async HTTP scanning first (only if not in stealth mode)
            if not stealth_mode:
                await scan_services_async(resolved_target, ports)
            
            # Then run port scanning
            scan_ports(resolved_target, args.ports, show_progress=args.progress, 
                      enable_banner=enable_banner, enable_ssl=enable_ssl,
                      stealth=stealth_mode, delay=delay)

        elif args.subnet:
            scan_subnet(args.subnet, show_progress=args.progress, 
                       enable_banner=enable_banner, enable_ssl=enable_ssl,
                       stealth=stealth_mode, delay=delay)
    
    finally:
        scan_results['end_time'] = time.time()
        print_scan_summary()
        
        # Save results to file if requested
        if args.output:
            save_scan_results(args.output)

if __name__ == "__main__":
    asyncio.run(main())
