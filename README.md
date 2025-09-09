---

# Advanced IP, URL, and Port Scanner Tool

## Overview

This is an advanced tool for scanning IP addresses, URLs, and subnets to detect open ports and associated services. It features multithreaded and asynchronous scanning, customizable timeouts, SSL certificate fetching, banner grabbing, service detection, stealth scanning, and comprehensive reporting. Designed for penetration testing and network security assessments, this tool offers robust performance and usability.

## Features

### Core Scanning Features
- Fast and scalable scanning using both threads and async I/O
- Set custom timeouts for both socket connections and HTTP requests
- Control the rate of requests to avoid overwhelming targets or local resources
- Identify 22+ common services based on port numbers and banners
- Retrieve and analyze SSL certificates for HTTPS services
- Collect banners from open ports with protocol-specific probes
- Visual feedback during long scans with real-time progress bars

### Enhanced Detection & Analysis
- Advanced service detection (SSH, HTTP, MySQL, PostgreSQL, etc.)
- Response time measurement in milliseconds
- SSL/TLS certificate analysis with protocol and cipher information
- Smart banner grabbing with protocol-specific requests

### Stealth & Performance Options
- Stealth mode with randomized port scanning order
- Configurable delays between scans for evasion
- Single-threaded operation for reduced network footprint
- Skip banner grabbing or SSL analysis for faster scanning

### Output & Reporting
- Comprehensive scan results summary with statistics
- Multiple output formats: JSON and CSV
- Scan timing and performance metrics
- Detailed error reporting and logging

### Configuration & Presets
- Configuration file support for default settings
- Built-in scan presets (quick, common, web, database, remote)
- Custom port ranges and lists
- Flexible command-line interface

## Disclaimer

**_Use this tool responsibly. This tool is intended for educational purposes and legitimate security testing only._** Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical. The creator of this tool is not responsible for any misuse or legal consequences resulting from its use. Always obtain proper authorization before performing security testing. 

## Installation

1. **Clone the Repository**

   ```
   git clone https://github.com/SaadSaid158/Basic-Port-Scanner.git
   cd Basic-Port-Scanner
   ```

2. **Install Dependencies**

   You need to install Python 3.8+ and the required libraries. You can use `pip` to install them:

   ```
   pip install aiohttp tqdm
   ```

## Usage

### Basic Command Structure

```
python3 main.py [--target <IP_or_URL> | --subnet <subnet>] [options]
```

### Options

#### Core Options
- `--target <IP_or_URL>`: Specify the target IP address or URL for scanning
- `--subnet <subnet>`: Target subnet for IP scanning (e.g., `192.168.1.0/24`)
- `--ports <ports>`: Comma-separated list or range of ports (e.g., `22,80-100`)
- `--full-scan`: Scan all common ports (default is only HTTP/HTTPS ports)
- `--timeout <timeout>`: Set custom timeout in seconds for connections

#### Performance & Stealth Options
- `--progress`: Show a progress bar during the scan
- `--no-banner`: Skip banner grabbing for faster scanning
- `--no-ssl`: Skip SSL certificate fetching for faster scanning
- `--stealth`: Enable stealth mode (randomize port order, add delays)
- `--delay <seconds>`: Add custom delay between port scans

#### Configuration & Presets
- `--config <file>`: Load settings from configuration file
- `--create-config <file>`: Create a default configuration file
- `--preset <preset>`: Use predefined port preset (quick, common, web, database, remote)

#### Output Options
- `--output <file>`: Save scan results to file (.json or .csv format)

## Examples

### Basic Scanning

```bash
# Quick scan of common ports
python3 main.py --target 192.168.1.1 --preset quick --progress

# Scan specific ports with banner grabbing
python3 main.py --target example.com --ports 22,80,443 --progress

# Fast scan without banners or SSL analysis
python3 main.py --target 192.168.1.1 --ports 80,443 --no-banner --no-ssl --progress
```

### Advanced Scanning

```bash
# Stealth scan with randomized order and delays
python3 main.py --target 192.168.1.1 --preset common --stealth --progress

# Web application focused scan
python3 main.py --target webapp.com --preset web --progress --output webapp_scan.csv

# Database port scan with detailed SSL analysis
python3 main.py --target db-server.com --preset database --progress --output db_scan.json
```

### Subnet Scanning

```bash
# Quick subnet scan
python3 main.py --subnet 192.168.1.0/24 --progress

# Stealth subnet scan
python3 main.py --subnet 10.0.0.0/24 --stealth --no-ssl --progress
```

### Configuration Management

```bash
# Create default configuration file
python3 main.py --create-config scanner.conf

# Use configuration file
python3 main.py --target 192.168.1.1 --config scanner.conf --preset quick
```

## Built-in Presets

- **quick**: `22,80,443` - SSH, HTTP, HTTPS
- **common**: `21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,3306,3389,5432,5900,8080` - Most common services
- **web**: `80,443,8080,8443,8000,9000,9080,9443` - Web applications
- **database**: `1433,3306,5432,1521,27017,6379` - Database services
- **remote**: `22,23,3389,5900,5800` - Remote access services

## Output Formats

### Console Output
The scanner provides real-time feedback and a comprehensive summary including:
- Scan duration and statistics
- Open ports with service identification
- Response times in milliseconds
- SSL certificate information
- Banner information
- Error reporting

### File Output
- **JSON**: Complete scan results with all metadata
- **CSV**: Tabular format for analysis in spreadsheets

## Configuration File Format

```ini
[DEFAULT]
timeout = 2
threads = 100
progress = true
no_banner = false
no_ssl = false
stealth = false
delay = 0

[SCAN_PRESETS]
custom_web = 80,443,8000,8080,9000
```

## Performance Tips

1. **Fast Scanning**: Use `--no-banner --no-ssl` for maximum speed
2. **Stealth Scanning**: Use `--stealth --delay 0.5` to avoid detection
3. **Comprehensive Analysis**: Default settings provide detailed information
4. **Large Subnets**: Use presets and consider stealth mode for large network scans

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Make sure to follow the coding guidelines and include tests if applicable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or issues, please open an issue on GitHub or contact [my email](mailto:saad.dev158@gmail.com).

---

Happy scanning!

