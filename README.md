# IP2Host - Hostname Finder from IP Addresses

## Description

IP2Host is a Python tool designed to discover hostnames associated with given IP addresses using multiple methods such as reverse DNS, WHOIS lookups, IPinfo API, Shodan API, VirusTotal API, and more. The tool also supports gathering subdomain information from crt.sh, Sublist3r, Subfinder, and VirusTotal.

The script relies on external tools like Gospider, Sublist3r, and Subfinder for enhanced subdomain discovery. It is specifically designed for cybersecurity and pentesting purposes.

## Features

- Reverse DNS lookup.
- WHOIS lookup.
- Shodan and VirusTotal integration.
- Subdomain enumeration using crt.sh, Sublist3r, Subfinder, and VirusTotal.
- Content-based hostname extraction.
- Gospider integration to crawl URLs and gather information.
- Multi-threaded execution for faster processing.

## Requirements

- Python 3.8+
- External Tools:
  - **gospider** (for crawling)
  - **subfinder** (for subdomain discovery)
  - **sublist3r** (for subdomain discovery)

Ensure these tools are installed and available in your PATH.

## Installation

1. **Clone the repository:**

   ```sh
   git clone https://github.com/WhileEndless/IP2Host.git
   cd ip2host
   ```

2. **Install Python dependencies:**

   ```sh
   pip install -r requirements.txt
   ```

3. **Install external tools:** Ensure that `gospider`, `subfinder`, and `sublist3r` are installed and added to your PATH.

4. **Run the script:**

   ```sh
   python ip2host.py -i input_ips.txt -o output_results.csv
   ```

## Usage

```sh
python ip2host.py -i <input_file> -o <output_file> [options]
```

### Arguments

- `-i, --input`: Input file containing a list of IP addresses.
- `-o, --output`: Output file to save matches.
- `--dns-servers`: DNS servers to use for reverse lookups (default: 8.8.8.8, 1.1.1.1).
- `--output-format`: Output format (`csv` or `json`, default: `csv`).
- `--debug`: Enable debug mode.
- `--threads`: Number of threads to run (default: 10).
- `--ports`: Ports to scan (default: `80 443`).
- `--shodan-api-key`: Shodan API key.
- `--virustotal-api-key`: VirusTotal API key.
- `--concurrent-requests`: Number of concurrent requests for Gospider (default: 5).

### Example

```sh
python ip2host.py -i ip_addresses.txt -o results.csv --ports 80 443 --threads 20
```

## Important Notes

- **External Tools**: Ensure that `gospider`, `subfinder`, and `sublist3r` are installed. The script will exit if any of these tools are missing.
- **API Keys**: Shodan and VirusTotal API keys are optional but recommended for more extensive data gathering.
- **Security**: Use this tool responsibly, as some actions may be interpreted as intrusive by target networks. Always get authorization before conducting any scans or queries.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is intended for legal use in authorized security testing. The author is not responsible for any misuse or damages caused by the use of this tool.

