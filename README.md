---


# Advanced IP, URL, and Port Scanner Tool

## Overview


This is an advanced tool for scanning IP addresses, URLs, and subnets to detect open ports and associated services. It features multithreaded and asynchronous scanning, customizable timeouts, SSL certificate fetching, banner grabbing, and rate limiting. Designed for penetration testing and network security assessments, this tool offers robust performance and usability.

## Disclaimer

**_Use this tool responsibly. This tool is intended for educational purposes and legitimate security testing only._** Unauthorized use of this tool against systems you do not own or have explicit permission to test is illegal and unethical. The creator of this tool is not responsible for any misuse or legal consequences resulting from its use. Always obtain proper authorization before performing security testing. 

## Features

- Fast and scalable scanning using both threads and async I/O.
- Set custom timeouts for both socket connections and HTTP requests.
- Control the rate of requests to avoid overwhelming targets or local resources.
- Identify common services based on port numbers.
- Retrieve SSL certificates for HTTPS services.
- Collect banners from open ports.
- Visual feedback during long scans.
- Easy-to-use command-line interface with detailed help.

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
python3 main.py --target <IP_or_URL> [--ports <ports>] [--full-scan] [--subnet <subnet>] [--progress] [--timeout <timeout>]
```

### Options

- `--target <IP_or_URL>`: Specify the target IP address or URL for scanning.
- `--ports <ports>`: Comma-separated list or range of ports to scan (e.g., `22,80-100`). Default is `80,443`.
- `--full-scan`: Scan all common ports (default is only HTTP/HTTPS ports).
- `--subnet <subnet>`: Target subnet for IP scanning (e.g., `192.168.1.0/24`).
- `--progress`: Show a progress bar during the scan.
- `--timeout <timeout>`: Set custom timeout in seconds for connections. Default is `2`.

## Examples

### Scanning an IP Address

```
python3 main.py --target 192.168.1.1 --ports 22,80,443 --progress
```

### Scanning a URL

```
python3 main.py --target example.com --full-scan --progress
```

### Scanning a Subnet

```
python3 main.py --subnet 192.168.1.0/24 --progress
```

### Full Scan with Custom Timeout

```
python3 main.py --target 192.168.1.1 --full-scan --timeout 5 --progress
```

## Contributing

Contributions are welcome! Please fork the repository and submit a pull request with your changes. Make sure to follow the coding guidelines and include tests if applicable.

## License

This project is licensed under the MIT License. See the [LICENSE](LICENSE) file for details.

## Contact

For any questions or issues, please open an issue on GitHub or contact [my email](mailto:saad.dev158@gmail.com).

---

Happy scanning!

