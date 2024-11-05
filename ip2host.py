import socket
import sys
import dns.resolver
import ssl
import requests
from bs4 import BeautifulSoup, Comment
from urllib.parse import urlparse, urljoin
import argparse
from concurrent.futures import ThreadPoolExecutor, as_completed
from rich.console import Console
from rich.progress import Progress, BarColumn, TextColumn
import json
import urllib3
import whois
import shodan
import subprocess
import re
import shutil
import tldextract
from functools import wraps

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

console = Console()

if not shutil.which("gospider"):
    console.print("[red]Gospider is not installed or not found in PATH. Please install gospider or add it to PATH.[/red]")
    sys.exit(1)

if not shutil.which("subfinder"):
    console.print("[red]subfinder is not installed or not found in PATH. Please install gospider or add it to PATH.[/red]")
    sys.exit(1)

if not shutil.which("sublist3r"):
    console.print("[red]sublist3r is not installed or not found in PATH. Please install gospider or add it to PATH.[/red]")
    sys.exit(1)

def reverse_dns_lookup(ip_address, debug=False):
    try:
        hostname, _, _ = socket.gethostbyaddr(ip_address)
        if debug:
            console.print(f"[DEBUG] Reverse DNS found hostname: {hostname}")
        return hostname
    except socket.herror:
        if debug:
            console.print(f"[DEBUG] No reverse DNS record found for {ip_address}.")
        return None

def whois_lookup(ip_address, debug=False):
    try:
        data = whois.whois(ip_address)
        hostname = data.domain_name
        if isinstance(hostname, list):
            hostname = hostname[0]
        if debug:
            console.print(f"[DEBUG] WHOIS found hostname: {hostname}")
        return hostname
    except Exception:
        if debug:
            console.print(f"[DEBUG] WHOIS information not found for {ip_address}.")
        return None

def ipinfo_lookup(ip_address, debug=False):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}/json")
        data = response.json()
        hostname = data.get('hostname')
        if debug and hostname:
            console.print(f"[DEBUG] IPinfo API found hostname: {hostname}")
        return hostname
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] Failed to get info from IPinfo API: {e}")
        return None

def shodan_lookup(ip_address, shodan_api_key, debug=False):
    try:
        api = shodan.Shodan(shodan_api_key)
        host = api.host(ip_address)
        hostnames = host.get('hostnames', [])
        if debug and hostnames:
            console.print(f"[DEBUG] Shodan API found hostnames: {hostnames}")
        return hostnames
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] Failed to get info from Shodan API: {e}")
        return []


def generate_base_domains(hostname):
    base_domains = []
    ext = tldextract.extract(hostname)
    registered_domain = '.'.join([ext.domain, ext.suffix])
    subdomains = ext.subdomain.split('.') if ext.subdomain else []
    for i in range(len(subdomains) + 1):
        subdomain = '.'.join(subdomains[i:])
        if subdomain:
            base_domain = f"{subdomain}.{registered_domain}"
        else:
            base_domain = registered_domain
        if base_domain not in base_domains:
            base_domains.append(base_domain)
    return base_domains

def get_subdomains_from_crtsh(domain, debug=False):
    url = f"https://crt.sh/?q=%25.{domain}&output=json"
    subdomains = set()
    try:
        response = requests.get(url, timeout=10)
        if response.status_code == 200:
            data = response.json()
            for entry in data:
                name_value = entry.get('name_value')
                if name_value:
                    names = name_value.split('\n')
                    for name in names:
                        name = name.strip()
                        if name.startswith('*.'):
                            name = name[2:]
                        subdomains.add(name.lower())
            if debug:
                console.print(f"[DEBUG] Subdomains from crt.sh: {subdomains}")
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] crt.sh query failed: {e}")
    return list(subdomains)

def get_subdomains_from_sublist3r(domain, debug=False):
    subdomains = set()
    try:
        command = ["sublist3r", "-d", domain, "-o", "/dev/stdout"]
        if debug:
            console.print(f"[DEBUG] Sublist3r command: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        for line in stdout.splitlines():
            line = line.strip()
            if line and not line.startswith('[-]'):
                subdomains.add(line.lower())
        if debug and stderr:
            console.print(f"[DEBUG] Sublist3r stderr: {stderr}")
        if debug:
            console.print(f"[DEBUG] Subdomains from Sublist3r: {subdomains}")
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] Sublist3r failed to run: {e}")
    return list(subdomains)

def get_subdomains_from_subfinder(domain, debug=False):
    subdomains = set()
    try:
        command = ["subfinder", "-d", domain, "-silent"]
        if debug:
            console.print(f"[DEBUG] Subfinder command: {' '.join(command)}")
        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()
        for line in stdout.splitlines():
            line = line.strip()
            if line:
                subdomains.add(line.lower())
        if debug and stderr:
            console.print(f"[DEBUG] Subfinder stderr: {stderr}")
        if debug:
            console.print(f"[DEBUG] Subdomains from Subfinder: {subdomains}")
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] Subfinder failed to run: {e}")
    return list(subdomains)

def get_subdomains_from_virustotal(domain, virustotal_api_key, debug=False):
    subdomains = set()
    headers = {"x-apikey": virustotal_api_key}
    url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains?limit=40"
    try:
        while url:
            response = requests.get(url, headers=headers, timeout=10)
            if response.status_code == 200:
                data = response.json()
                for item in data.get('data', []):
                    subdomain = item.get('id')
                    if subdomain:
                        subdomains.add(subdomain.lower())
                url = data.get('links', {}).get('next')
            else:
                if debug:
                    console.print(f"[DEBUG] VirusTotal query failed: {response.status_code} {response.text}")
                break
        if debug:
            console.print(f"[DEBUG] Subdomains from VirusTotal: {subdomains}")
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] VirusTotal query failed: {e}")
    return list(subdomains)

tested_hostnames=[]

def subdomain_lookup(hostname, virustotal_api_key=None, debug=False):
    subdomains = set()
    base_domains = generate_base_domains(hostname)
    for base_domain in base_domains:
        if base_domain in tested_hostnames:
            continue
        tested_hostnames.append(base_domain)
        subdomains.update(get_subdomains_from_crtsh(base_domain, debug=debug))
        subdomains.update(get_subdomains_from_sublist3r(base_domain, debug=debug))
        subdomains.update(get_subdomains_from_subfinder(base_domain, debug=debug))
        if virustotal_api_key:
            subdomains.update(get_subdomains_from_virustotal(base_domain, virustotal_api_key, debug=debug))
    return list(subdomains)

def run_gospider(url, depth, concurrent_requests, debug=False):
    try:
        command = [
            "gospider",
            "-s", url,
            "-d", str(depth),
            "-c", str(concurrent_requests),
            "--json"
        ]
        if debug:
            console.print(f"[DEBUG] Gospider command: {' '.join(command)}")

        process = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        stdout, stderr = process.communicate()

        if stderr and debug:
            console.print(f"[DEBUG] Gospider stderr: {stderr}")

        paths = set()
        for line in stdout.splitlines():
            try:
                data = json.loads(line)
                if data.get('status_code') == 200:
                    url = data.get('output', '')
                    parsed_url = urlparse(url)
                    paths.add(parsed_url.path)
            except json.JSONDecodeError:
                continue

        if debug:
            console.print(f"[DEBUG] Paths found by Gospider: {paths}")

        return paths
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] Failed to run Gospider: {e}")
        return set()

def extract_hostnames_from_content(content, base_url, debug=False):
    hostnames = set()
    soup = BeautifulSoup(content, "html.parser")

    for tag in soup.find_all(['a', 'img', 'script', 'link', 'iframe'], href=True, src=True):
        url = tag.get('href') or tag.get('src')
        if url:
            full_url = urljoin(base_url, url)
            hostname = urlparse(full_url).hostname
            if hostname:
                hostnames.add(hostname.rstrip('.'))

    comments = soup.find_all(string=lambda text: isinstance(text, Comment))
    for comment in comments:
        potential_hostnames = re.findall(r'[\w\.-]+\.[\w\.-]+', comment)
        hostnames.update(potential_hostnames)

    css_links = soup.find_all('link', rel='stylesheet', href=True)
    for link in css_links:
        css_url = urljoin(base_url, link['href'])
        try:
            css_response = requests.get(css_url, timeout=5, verify=False)
            css_hostnames = re.findall(r'url\(["\']?(https?://[^)"\']+)["\']?\)', css_response.text)
            for css_hostname in css_hostnames:
                hostname = urlparse(css_hostname).hostname
                if hostname:
                    hostnames.add(hostname.rstrip('.'))
        except Exception as e:
            if debug:
                console.print(f"[DEBUG] Failed to fetch CSS file: {e}")

    potential_hostnames = re.findall(r'[\w\.-]+\.[\w\.-]+', content)
    hostnames.update(potential_hostnames)

    if debug:
        console.print(f"[DEBUG] Hostnames extracted from content: {hostnames}")

    return hostnames

def get_hostname_from_cert(ip_address, port, debug=False):
    hostnames = []
    try:
        context = ssl.create_default_context()
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE

        with socket.create_connection((ip_address, port), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=ip_address) as ssock:
                cert = ssock.getpeercert()

                cn = cert.get("subject", ((("commonName", ""),),))[0][0][1].rstrip('.')
                if cn:
                    hostnames.append(cn)
                alt_names = cert.get("subjectAltName", [])
                sans = [name[1].rstrip('.') for name in alt_names if name[0] == "DNS"]
                hostnames.extend(sans)

                if debug:
                    console.print(f"[DEBUG] Hostnames from certificate: {hostnames}")
    except Exception as e:
        if debug:
            console.print(f"[DEBUG] Failed to get certificate from {ip_address}:{port}: {e}")
    return hostnames

def write_output(output_file, entry, output_format="csv"):
    if output_format == "json":
        with open(output_file, "a") as f:
            json.dump(entry, f)
            f.write("\n")
    else:
        with open(output_file, "a") as f:
            if f.tell() == 0:
                f.write("ip,hostname,source\n")
            f.write(",".join([entry["ip"], entry["hostname"], entry["source"]]) + "\n")

def verify_hostname_ip(ip_address, dns_server, ip_list, unique_results, output_file, output_format="csv", debug=False):
    try:
        resolver = dns.resolver.Resolver()
        resolver.nameservers = [dns_server]

        ptr_query = '.'.join(reversed(ip_address.split("."))) + ".in-addr.arpa"
        answers = resolver.resolve(ptr_query, "PTR")

        hostname = str(answers[0]).rstrip('.')
        resolved_ip_answers = resolver.resolve(hostname, "A")
        resolved_ip = resolved_ip_answers[0].to_text()

        if resolved_ip == ip_address:
            entry = {"ip": resolved_ip, "hostname": hostname, "source": "dns"}
            if (resolved_ip, hostname) not in unique_results:
                unique_results.add((resolved_ip, hostname))
                console.print(f"[green]Found match: IP: {resolved_ip}, Hostname: {hostname}[/green]")
                write_output(output_file, entry, output_format)
                if debug:
                    console.print(f"[DEBUG] Matching IP: {resolved_ip} and Hostname: {hostname}")

    except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer, dns.resolver.Timeout, socket.gaierror):
        if debug:
            console.print(f"[DEBUG] No hostname found or DNS did not respond for {ip_address}.")


def process_hostnames(hostnames, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug):
    for hostname in hostnames:
        hostname = hostname.rstrip('.')
        if not hostname.replace(".", "").isdigit():
            process_domain(hostname, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug)

def process_domain(domain, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug):
    if domain in processed_domains:
        return
    processed_domains.add(domain)

    try:
        ips = socket.gethostbyname_ex(domain)[2]
    except socket.gaierror:
        if debug:
            console.print(f"[DEBUG] {domain} could not be resolved.")
        return
    f=False
    for ip in ips:
        if ip in ip_list:
            entry = {"ip": ip, "hostname": domain, "source": "domain_resolution"}
            f=True
            if (ip, domain) not in unique_results:
                unique_results.add((ip, domain))
                console.print(f"[green]Found match (domain resolution): IP: {ip}, Hostname: {domain}[/green]")
                write_output(output_file, entry, output_format)
    if not f:
        return
    subdomains = subdomain_lookup(domain, virustotal_api_key=virustotal_api_key, debug=debug)
    for subdomain in subdomains:
        process_domain(subdomain, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug)

    for scheme in ["http", "https"]:
        base_url = f"{scheme}://{domain}"
        try:
            response = requests.get(base_url, timeout=10, verify=False)
            hostnames = extract_hostnames_from_content(response.text, base_url, debug=debug)
            process_hostnames(hostnames, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug)

            paths = run_gospider(base_url, depth=3, concurrent_requests=concurrent_requests, debug=debug)
            for path in paths:
                full_url = f"{base_url}{path}"
                try:
                    sub_response = requests.get(full_url, timeout=5, verify=False)
                    sub_hostnames = extract_hostnames_from_content(sub_response.text, base_url, debug=debug)
                    process_hostnames(sub_hostnames, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug)
                except Exception as e:
                    if debug:
                        console.print(f"[DEBUG] Request failed for {full_url}: {e}")
        except Exception as e:
            if debug:
                console.print(f"[DEBUG] Request failed for {base_url}: {e}")

def check_redirect_and_extract_hostnames(ip_address, ip_list, unique_results, processed_domains, output_file, output_format="csv", ports=[80, 443], concurrent_requests=5, debug=False):
    for port in ports:
        scheme = "https" if port == 443 else "http"
        base_url = f"{scheme}://{ip_address}"
        try:
            response = requests.get(base_url, allow_redirects=True, timeout=10, verify=False)
            if response.history:
                redirect_url = response.url
                redirect_hostname = urlparse(redirect_url).hostname.rstrip('.')
                if redirect_hostname and not redirect_hostname.replace(".", "").isdigit():
                    try:
                        resolved_redirect_ips = socket.gethostbyname_ex(redirect_hostname)[2]
                        if ip_address in resolved_redirect_ips:
                            entry = {"ip": ip_address, "hostname": redirect_hostname, "source": "redirect"}
                            if (ip_address, redirect_hostname) not in unique_results:
                                unique_results.add((ip_address, redirect_hostname))
                                console.print(f"[green]Found match (redirect): IP: {ip_address}, Hostname: {redirect_hostname}[/green]")
                                write_output(output_file, entry, output_format)
                                if debug:
                                    console.print(f"[DEBUG] Redirected hostname matches: {redirect_hostname}")
                            process_domain(redirect_hostname, ip_list, unique_results, processed_domains, output_file, output_format, ports, None, None, concurrent_requests, debug)
                    except socket.gaierror:
                        if debug:
                            console.print(f"[DEBUG] {redirect_hostname} could not be resolved.")

            hostnames = extract_hostnames_from_content(response.text, base_url, debug=debug)
            process_hostnames(hostnames, ip_list, unique_results, processed_domains, output_file, output_format, ports, None, None, concurrent_requests, debug)

            paths = run_gospider(base_url, depth=1, concurrent_requests=concurrent_requests, debug=debug)
            for path in paths:
                full_url = f"{base_url}{path}"
                try:
                    sub_response = requests.get(full_url, timeout=5, verify=False)
                    sub_hostnames = extract_hostnames_from_content(sub_response.text, base_url, debug=debug)
                    process_hostnames(sub_hostnames, ip_list, unique_results, processed_domains, output_file, output_format, ports, None, None, concurrent_requests, debug)
                except Exception as e:
                    if debug:
                        console.print(f"[DEBUG] Request failed for {full_url}: {e}")

        except requests.exceptions.RequestException as e:
            if debug:
                console.print(f"[DEBUG] GET request failed for {base_url}: {e}")

def process_ip(ip_address, dns_servers, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug):
    hostnames_found = set()

    for port in ports:
        cert_hostnames = get_hostname_from_cert(ip_address, port, debug=debug)
        for cert_hostname in cert_hostnames:
            cert_hostname = cert_hostname.rstrip('.')
            if not cert_hostname.replace(".", "").isdigit():
                try:
                    resolved_ips = socket.gethostbyname_ex(cert_hostname)[2]
                    if ip_address in resolved_ips:
                        entry = {"ip": ip_address, "hostname": cert_hostname, "source": f"cert:{port}"}
                        if (ip_address, cert_hostname) not in unique_results:
                            unique_results.add((ip_address, cert_hostname))
                            hostnames_found.add(cert_hostname)
                            console.print(f"[green]Found match (cert): IP: {ip_address}, Hostname: {cert_hostname}[/green]")
                            write_output(output_file, entry, output_format)
                            if debug:
                                console.print(f"[DEBUG] Hostname from cert matches IP: {ip_address} and Hostname: {cert_hostname}")
                except socket.gaierror:
                    if debug:
                        console.print(f"[DEBUG] {cert_hostname} could not be resolved.")

    reverse_dns_hostname = reverse_dns_lookup(ip_address, debug=debug)
    if reverse_dns_hostname:
        entry = {"ip": ip_address, "hostname": reverse_dns_hostname, "source": "reverse_dns"}
        if (ip_address, reverse_dns_hostname) not in unique_results:
            unique_results.add((ip_address, reverse_dns_hostname))
            hostnames_found.add(reverse_dns_hostname)
            console.print(f"[green]Found match (reverse DNS): IP: {ip_address}, Hostname: {reverse_dns_hostname}[/green]")
            write_output(output_file, entry, output_format)

    whois_hostname = whois_lookup(ip_address, debug=debug)
    if whois_hostname:
        entry = {"ip": ip_address, "hostname": whois_hostname, "source": "whois"}
        if (ip_address, whois_hostname) not in unique_results:
            unique_results.add((ip_address, whois_hostname))
            hostnames_found.add(whois_hostname)
            console.print(f"[green]Found match (WHOIS): IP: {ip_address}, Hostname: {whois_hostname}[/green]")
            write_output(output_file, entry, output_format)

    ipinfo_hostname = ipinfo_lookup(ip_address, debug=debug)
    if ipinfo_hostname:
        entry = {"ip": ip_address, "hostname": ipinfo_hostname, "source": "ipinfo"}
        if (ip_address, ipinfo_hostname) not in unique_results:
            unique_results.add((ip_address, ipinfo_hostname))
            hostnames_found.add(ipinfo_hostname)
            console.print(f"[green]Found match (IPinfo API): IP: {ip_address}, Hostname: {ipinfo_hostname}[/green]")
            write_output(output_file, entry, output_format)

    if shodan_api_key:
        shodan_hostnames = shodan_lookup(ip_address, shodan_api_key, debug=debug)
        for shodan_hostname in shodan_hostnames:
            if not shodan_hostname.replace(".", "").isdigit():
                try:
                    resolved_ips = socket.gethostbyname_ex(shodan_hostname)[2]
                    if ip_address in resolved_ips:
                        entry = {"ip": ip_address, "hostname": shodan_hostname, "source": "shodan"}
                        if (ip_address, shodan_hostname) not in unique_results:
                            unique_results.add((ip_address, shodan_hostname))
                            hostnames_found.add(shodan_hostname)
                            console.print(f"[green]Found match (Shodan): IP: {ip_address}, Hostname: {shodan_hostname}[/green]")
                            write_output(output_file, entry, output_format)
                            if debug:
                                console.print(f"[DEBUG] Shodan found hostname matching IP: {ip_address} and Hostname: {shodan_hostname}")
                except socket.gaierror:
                    if debug:
                        console.print(f"[DEBUG] {shodan_hostname} could not be resolved.")

    for dns_server in dns_servers:
        verify_hostname_ip(ip_address, dns_server, ip_list, unique_results, output_file, output_format, debug=debug)

    check_redirect_and_extract_hostnames(ip_address, ip_list, unique_results, processed_domains, output_file, output_format, ports=ports, concurrent_requests=concurrent_requests, debug=debug)

    for hostname in hostnames_found:
        process_domain(hostname, ip_list, unique_results, processed_domains, output_file, output_format, ports, shodan_api_key, virustotal_api_key, concurrent_requests, debug)

def main():
    parser = argparse.ArgumentParser(description="IP2Host v1: A tool to find hostname information from IP addresses")
    parser.add_argument("-i", "--input", required=True, help="Input file (IP addresses)")
    parser.add_argument("-o", "--output", required=True, help="Output file (matches)")
    parser.add_argument("--dns-servers", nargs="+", default=["8.8.8.8", "1.1.1.1"], help="DNS servers to use")
    parser.add_argument("--output-format", choices=["csv", "json"], default="csv", help="Output format (csv or json)")
    parser.add_argument("--debug", action="store_true", help="Enable debug mode")
    parser.add_argument("--threads", type=int, default=10, help="Number of threads to run")
    parser.add_argument("--ports", nargs="+", type=int, default=[80, 443], help="Ports to scan (e.g., --ports 80 443 8080)")
    parser.add_argument("--shodan-api-key", help="Shodan API key")
    parser.add_argument("--virustotal-api-key", help="VirusTotal API key")
    parser.add_argument("--concurrent-requests", type=int, default=5, help="Number of concurrent requests for gospider")
    args = parser.parse_args()

    if not shutil.which("gospider"):
        console.print("[red]Gospider is not installed or not found in PATH. Please install gospider or add it to PATH.[/red]")
        sys.exit(1)

    with open(args.input, "r") as f:
        ip_list = [line.strip() for line in f]

    unique_results = set()
    processed_domains = set()

    with Progress(
        TextColumn("[progress.description]{task.description}"),
        BarColumn(),
        TextColumn("[progress.percentage]{task.percentage:>3.1f}%"),
        console=console
    ) as progress:
        task = progress.add_task("[cyan]Processing...", total=len(ip_list))

        with ThreadPoolExecutor(max_workers=args.threads) as executor:
            futures = [
                executor.submit(
                    process_ip, ip, args.dns_servers, ip_list, unique_results, processed_domains, args.output, args.output_format, args.ports, args.shodan_api_key, args.virustotal_api_key, args.concurrent_requests, args.debug
                ) for ip in ip_list
            ]
            for future in as_completed(futures):
                progress.update(task, advance=1)

if __name__ == "__main__":
    main()
