#!/usr/bin/env python3
"""
WebKnight Pro Elite Ultimate - Professional Web Reconnaissance Tool
Version: 4.1 | Enterprise Grade
Author: @HacktifyDiaries
Description: Advanced subdomain enumeration with intelligent verification,
             accurate status code detection, professional reporting,
             and comprehensive web asset discovery.
"""

import argparse
import asyncio
import aiohttp
import dns.resolver
import socket
import ssl
from urllib.parse import urlparse
import random
import time
from datetime import datetime
from colorama import init, Fore, Style
import re
import os
import json
import multiprocessing
import threading
from typing import List, Dict, Tuple, Optional
import warnings

# Suppress SSL warnings
warnings.filterwarnings("ignore", category=DeprecationWarning)
warnings.filterwarnings("ignore", category=UserWarning, module='aiohttp')

# Initialize colorama
init(autoreset=True)

# ===== CONFIGURATION =====
CONFIG = {
    "user_agents": [
        "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
        "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
        "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.101 Safari/537.36"
    ],
    "timeout": 10,
    "max_redirects": 5,
    "max_concurrency": 50,
    "verify_ssl": False,
    "follow_redirects": True,
    "max_retries": 2,
    "delay_between_requests": 0.5
}

# Enhanced subdomain wordlist
SUBDOMAIN_WORDLIST = [
    "www", "mail", "admin", "api", "test", "dev", "staging", 
    "web", "ftp", "ns1", "cdn", "secure", "portal", "blog",
    "app", "m", "mobile", "demo", "beta", "old", "new", "webmail",
    "smtp", "pop", "imap", "git", "svn", "vpn", "proxy", "firewall"
]

# Comprehensive directory list with proper weighting
CRITICAL_DIRECTORIES = [
    ("/admin", 10), ("/wp-admin", 10), ("/administrator", 10), ("/cpanel", 10),
    ("/manager", 9), ("/login", 9), ("/admin/login", 9), ("/admincp", 9),
    ("/backend", 8), ("/secure", 8), ("/dashboard", 8), ("/config", 10),
    ("/db", 7), ("/database", 7), ("/backup", 10), ("/.git", 10), ("/.env", 10),
    ("/wp-content", 6), ("/wp-includes", 6), ("/phpmyadmin", 10),
    ("/server-status", 7), ("/console", 8), ("/swagger", 7), ("/api-docs", 7),
    ("/graphql", 7), ("/rest", 7), ("/soap", 7), ("/owa", 8), ("/ecp", 8)
]

# Common ports for scanning
COMMON_PORTS = [21, 22, 23, 25, 53, 80, 110, 143, 443, 465, 587, 993, 995, 1433, 1521, 3306, 3389, 5432, 5900, 5985, 6379, 8000, 8008, 8080, 8443, 8888, 9000, 9200, 11211, 27017]

# ===== TOOL CLASS =====
class WebKnightPro:
    def __init__(self, domain: str):
        self.domain = self._clean_domain(domain)
        self.session = None
        self.results = {
            "target": self.domain,
            "scan_time": datetime.now().isoformat(),
            "origin_ips": [],
            "subdomains": {},
            "directories": {},
            "open_ports": {},
            "technologies": {},
            "vulnerabilities": []
        }

    def _clean_domain(self, domain: str) -> str:
        """Clean and normalize the domain input"""
        domain = domain.lower().strip()
        if domain.startswith(('http://', 'https://')):
            domain = domain.split('//')[1]
        if domain.startswith('www.'):
            domain = domain[4:]
        return domain.split('/')[0]

    async def __aenter__(self):
        """Initialize async context"""
        connector = aiohttp.TCPConnector(
            limit=CONFIG["max_concurrency"],
            ssl=CONFIG["verify_ssl"],
            force_close=True
        )
        self.session = aiohttp.ClientSession(
            connector=connector,
            timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"]),
            headers={"User-Agent": random.choice(CONFIG["user_agents"])},
            raise_for_status=False
        )
        return self

    async def __aexit__(self, exc_type, exc, tb):
        """Clean up async context"""
        await self.session.close()

    async def discover_origin_ips(self):
        """Discover origin server IPs with DNS resolution"""
        try:
            # Try different DNS resolution methods
            try:
                answers = dns.resolver.query(self.domain, 'A')
            except AttributeError:
                answers = dns.resolver.resolve(self.domain, 'A')
            
            for rdata in answers:
                ip = str(rdata)
                if ip not in self.results["origin_ips"]:
                    self.results["origin_ips"].append(ip)
                    # Perform reverse DNS lookup
                    try:
                        hostname = socket.gethostbyaddr(ip)[0]
                        if hostname not in self.results["subdomains"]:
                            self.results["subdomains"][hostname] = {
                                "ip": ip,
                                "status": None,
                                "services": []
                            }
                    except:
                        pass
                    
        except Exception as e:
            print(Fore.YELLOW + f"[!] DNS resolution failed: {str(e)}")

    async def scan_subdomains(self, bruteforce: bool = False, threads: int = 30):
        """Scan for subdomains with multiple verification methods"""
        print(Fore.CYAN + "[*] Starting subdomain enumeration..." + Style.RESET_ALL)
        
        # Check common subdomains
        tasks = []
        for sub in SUBDOMAIN_WORDLIST:
            full_domain = f"{sub}.{self.domain}"
            tasks.append(self._verify_and_scan_subdomain(full_domain))
        
        # Process in batches to avoid overwhelming
        for i in range(0, len(tasks), CONFIG["max_concurrency"]):
            batch = tasks[i:i + CONFIG["max_concurrency"]]
            await asyncio.gather(*batch)
            await asyncio.sleep(CONFIG["delay_between_requests"])  # Rate limiting

        # Additional checks for common patterns
        common_patterns = [
            f"dev-{self.domain}", f"staging-{self.domain}", 
            f"test-{self.domain}", f"api-{self.domain}"
        ]
        for pattern in common_patterns:
            await self._verify_and_scan_subdomain(pattern)

    async def _verify_and_scan_subdomain(self, subdomain: str) -> None:
        """Verify subdomain exists and scan it"""
        try:
            # First check DNS
            try:
                await asyncio.get_event_loop().getaddrinfo(subdomain, None)
                dns_exists = True
            except:
                dns_exists = False

            if dns_exists:
                # Check HTTP and HTTPS
                http_url = f"http://{subdomain}"
                https_url = f"https://{subdomain}"
                
                http_result = await self._check_url(http_url)
                https_result = await self._check_url(https_url)
                
                # Prefer HTTPS if available
                if https_result and https_result["status"] < 500:
                    result = https_result
                    protocol = "https"
                elif http_result and http_result["status"] < 500:
                    result = http_result
                    protocol = "http"
                else:
                    return
                
                if result:
                    self.results["subdomains"][subdomain] = {
                        "url": result["url"],
                        "status": result["status"],
                        "content_length": result["content_length"],
                        "final_url": result["final_url"],
                        "protocol": protocol,
                        "ip": await self._get_ip_for_subdomain(subdomain),
                        "headers": result.get("headers", {}),
                        "technologies": await self._detect_tech(result["final_url"])
                    }
        except Exception as e:
            print(Fore.YELLOW + f"[!] Error scanning {subdomain}: {str(e)}")

    async def _get_ip_for_subdomain(self, subdomain: str) -> str:
        """Get IP address for a subdomain"""
        try:
            return (await asyncio.get_event_loop().getaddrinfo(subdomain, None))[0][4][0]
        except:
            return ""

    async def scan_directories(self):
        """Scan for directories with proper status code checking"""
        print(Fore.CYAN + "[*] Scanning critical directories..." + Style.RESET_ALL)
        
        # Sort directories by priority (weight)
        sorted_dirs = sorted(CRITICAL_DIRECTORIES, key=lambda x: x[1], reverse=True)
        
        tasks = []
        for directory, weight in sorted_dirs:
            for protocol in ['http', 'https']:
                url = f"{protocol}://{self.domain}{directory}"
                tasks.append(self._check_url(url, is_directory=True))
        
        # Process in batches
        for i in range(0, len(tasks), CONFIG["max_concurrency"]):
            batch = tasks[i:i + CONFIG["max_concurrency"]]
            results = await asyncio.gather(*batch)
            
            for result in results:
                if result and result["status"] < 500:
                    dir_path = urlparse(result["url"]).path
                    self.results["directories"][dir_path] = {
                        "url": result["url"],
                        "status": result["status"],
                        "content_length": result["content_length"],
                        "final_url": result["final_url"],
                        "headers": result.get("headers", {}),
                        "redirect_chain": result.get("redirect_chain", [])
                    }

    async def scan_ports(self, ports: List[int] = None):
        """Scan ports for discovered subdomains"""
        if not ports:
            ports = COMMON_PORTS
        
        print(Fore.CYAN + f"[*] Scanning top {len(ports)} ports..." + Style.RESET_ALL)
        
        targets = set()
        # Add main domain
        targets.add(self.domain)
        # Add all discovered subdomains
        targets.update(self.results["subdomains"].keys())
        
        tasks = []
        for target in targets:
            for port in ports:
                tasks.append(self._scan_port(target, port))
        
        # Process in batches
        for i in range(0, len(tasks), CONFIG["max_concurrency"]):
            batch = tasks[i:i + CONFIG["max_concurrency"]]
            await asyncio.gather(*batch)
            await asyncio.sleep(0.1)  # Rate limiting

    async def _scan_port(self, host: str, port: int) -> None:
        """Scan a single port on a host"""
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port),
                timeout=CONFIG["timeout"]
            )
            writer.close()
            await writer.wait_closed()
            
            # Get service banner if possible
            service = await self._get_service_banner(host, port)
            
            if host not in self.results["open_ports"]:
                self.results["open_ports"][host] = []
            
            self.results["open_ports"][host].append({
                "port": port,
                "service": service or "unknown",
                "banner": await self._get_service_banner(host, port)
            })
            
        except (ConnectionRefusedError, asyncio.TimeoutError, OSError):
            pass
        except Exception as e:
            print(Fore.YELLOW + f"[!] Error scanning {host}:{port}: {str(e)}")

    async def _get_service_banner(self, host: str, port: int) -> str:
        """Attempt to get service banner"""
        try:
            if port in [80, 443, 8080, 8443]:
                # HTTP service
                protocol = "https" if port in [443, 8443] else "http"
                url = f"{protocol}://{host}:{port}"
                try:
                    async with self.session.get(url, timeout=5) as response:
                        server = response.headers.get('Server', '')
                        powered_by = response.headers.get('X-Powered-By', '')
                        return f"{server} {powered_by}".strip()
                except:
                    return ""
            else:
                # Generic TCP service
                reader, writer = await asyncio.open_connection(host, port)
                writer.write(b"GET / HTTP/1.0\r\n\r\n")
                data = await reader.read(1024)
                writer.close()
                return data.decode('utf-8', errors='ignore').split('\n')[0]
        except:
            return ""

    async def _check_url(self, url: str, is_directory: bool = False) -> Optional[Dict]:
        """Check URL with proper status code and redirect handling"""
        for attempt in range(CONFIG["max_retries"]):
            try:
                redirect_chain = []
                final_url = url
                
                async with self.session.get(
                    url,
                    allow_redirects=CONFIG["follow_redirects"],
                    ssl=CONFIG["verify_ssl"],
                    timeout=aiohttp.ClientTimeout(total=CONFIG["timeout"])
                ) as response:
                    # Follow redirects manually to track them
                    while response.status in (301, 302, 303, 307, 308):
                        redirect_url = response.headers.get('Location')
                        if not redirect_url:
                            break
                        
                        redirect_chain.append({
                            "from": str(response.url),
                            "to": redirect_url,
                            "status": response.status
                        })
                        
                        # Handle relative redirects
                        if not redirect_url.startswith(('http://', 'https://')):
                            redirect_url = urlparse(str(response.url))._replace(path=redirect_url).geturl()
                        
                        final_url = redirect_url
                        response = await self.session.get(
                            redirect_url,
                            allow_redirects=False,
                            ssl=CONFIG["verify_ssl"]
                        )
                    
                    content = await response.text()
                    headers = dict(response.headers)
                    
                    return {
                        "url": url,
                        "final_url": str(response.url),
                        "status": response.status,
                        "content_length": len(content),
                        "headers": headers,
                        "redirect_chain": redirect_chain,
                        "content_type": headers.get('Content-Type', '')
                    }
            except aiohttp.ClientError as e:
                if attempt == CONFIG["max_retries"] - 1:
                    return None
                await asyncio.sleep(1)
            except Exception as e:
                return None

    async def _detect_tech(self, url: str) -> Dict:
        """Detect technologies used by a web application"""
        tech = {}
        try:
            async with self.session.get(url) as response:
                headers = dict(response.headers)
                server = headers.get('Server', '')
                powered_by = headers.get('X-Powered-By', '')
                
                if server:
                    tech['web_server'] = server
                if powered_by:
                    tech['platform'] = powered_by
                
                # Check for common frameworks
                content = await response.text()
                if 'wp-content' in content:
                    tech['cms'] = 'WordPress'
                elif 'Joomla' in content:
                    tech['cms'] = 'Joomla'
                elif 'Drupal' in content:
                    tech['cms'] = 'Drupal'
                
                # Check for frontend frameworks
                if 'react' in content.lower():
                    tech['frontend'] = 'React'
                elif 'vue' in content.lower():
                    tech['frontend'] = 'Vue.js'
                elif 'angular' in content.lower():
                    tech['frontend'] = 'Angular'
                
                return tech
        except:
            return tech

    def print_results(self):
        """Display professional results with proper formatting"""
        print(Fore.CYAN + "\n" + "="*80)
        print(Fore.GREEN + "WEB KNIGHT PRO ELITE - SCAN RESULTS")
        print(Fore.CYAN + "="*80 + Style.RESET_ALL)
        
        # Basic Info
        print(Fore.YELLOW + "\n[ TARGET INFORMATION ]" + Style.RESET_ALL)
        print(f"Domain: {Fore.CYAN}{self.results['target']}{Style.RESET_ALL}")
        print(f"Scan Time: {Fore.CYAN}{self.results['scan_time']}{Style.RESET_ALL}")
        
        # Origin IPs
        if self.results["origin_ips"]:
            print(Fore.YELLOW + "\n[ ORIGIN IP ADDRESSES ]" + Style.RESET_ALL)
            for ip in self.results["origin_ips"]:
                print(f" - {Fore.GREEN}{ip}{Style.RESET_ALL}")
        
        # Subdomains
        if self.results["subdomains"]:
            print(Fore.YELLOW + "\n[ DISCOVERED SUBDOMAINS ]" + Style.RESET_ALL)
            for subdomain, data in sorted(self.results["subdomains"].items()):
                status = data["status"]
                status_color = Fore.GREEN if status == 200 else Fore.YELLOW if status < 400 else Fore.RED
                
                print(f"{Fore.CYAN}{subdomain}{Style.RESET_ALL}")
                print(f"  URL: {data['url']}")
                print(f"  Status: {status_color}{status}{Style.RESET_ALL}")
                print(f"  IP: {data.get('ip', 'Unknown')}")
                if data.get('technologies'):
                    print(f"  Technologies: {', '.join(f'{k}:{v}' for k, v in data['technologies'].items())}")
                print()
        
        # Directories
        if self.results["directories"]:
            print(Fore.YELLOW + "\n[ DIRECTORY FINDINGS ]" + Style.RESET_ALL)
            for path, data in sorted(self.results["directories"].items(), key=lambda x: x[1]['status']):
                status = data["status"]
                status_color = Fore.GREEN if status == 200 else Fore.YELLOW if status < 400 else Fore.RED
                
                print(f"{Fore.CYAN}{path}{Style.RESET_ALL}")
                print(f"  URL: {data['url']}")
                print(f"  Status: {status_color}{status}{Style.RESET_ALL}")
                if data.get('redirect_chain'):
                    print(f"  Redirects: {' -> '.join(str(r['status']) for r in data['redirect_chain'])}")
                print()
        
        # Open Ports
        if self.results["open_ports"]:
            print(Fore.YELLOW + "\n[ OPEN PORTS ]" + Style.RESET_ALL)
            for host, ports in self.results["open_ports"].items():
                print(f"{Fore.CYAN}{host}{Style.RESET_ALL}")
                for port_info in sorted(ports, key=lambda x: x['port']):
                    print(f"  {port_info['port']}/tcp - {port_info.get('service', 'unknown')}")
                    if port_info.get('banner'):
                        print(f"    Banner: {port_info['banner']}")
                print()
        
        print(Fore.CYAN + "="*80)
        print(Fore.GREEN + "SCAN COMPLETED SUCCESSFULLY")
        print(Fore.CYAN + "="*80 + Style.RESET_ALL)

    def save_results(self, filename: str):
        """Save results to JSON file"""
        with open(filename, 'w') as f:
            json.dump(self.results, f, indent=2)
        print(Fore.GREEN + f"\n[+] Results saved to {filename}")

# ===== MAIN =====
async def main():
    parser = argparse.ArgumentParser(description="WebKnight Pro Elite - Professional Web Reconnaissance Tool")
    parser.add_argument("-d", "--domain", required=True, help="Target domain to scan")
    parser.add_argument("-b", "--bruteforce", action="store_true", help="Enable subdomain bruteforcing")
    parser.add_argument("-p", "--ports", help="Comma-separated ports to scan (default: top 30 common ports)")
    parser.add_argument("-o", "--output", help="Save results to JSON file")
    args = parser.parse_args()

    # Display banner
    print(Fore.CYAN + r"""
     █     █░ ▄▄▄       ██▓     ██▓    ▄▄▄      ▓█████▄  ██▓ ███▄ ▄███▓
    ▓█░ █ ░█░▒████▄    ▓██▒    ▓██▒   ▒████▄    ▒██▀ ██▌▓██▒▓██▒▀█▀ ██▒
    ▒█░ █ ░█ ▒██  ▀█▄  ▒██░    ▒██░   ▒██  ▀█▄  ░██   █▌▒██▒▓██    ▓██░
    ░█░ █ ░█ ░██▄▄▄▄██ ▒██░    ▒██░   ░██▄▄▄▄██ ░▓█▄   ▌░██░▒██    ▒██ 
    ░░██▒██▓  ▓█   ▓██▒░██████▒░██████▒▓█   ▓██▒░▒████▓ ░██░▒██▒   ░██▒
    ░ ▓░▒ ▒   ▒▒   ▓▒█░░ ▒░▓  ░░ ▒░▓  ░▒▒   ▓▒█░ ▒▒▓  ▒ ░▓  ░ ▒░   ░  ░
      ▒ ░ ░    ▒   ▒▒ ░░ ░ ▒  ░░ ░ ▒  ░ ▒   ▒▒ ░ ░ ▒  ▒  ▒ ░░  ░      ░
      ░   ░    ░   ▒     ░ ░     ░ ░    ░   ▒    ░ ░  ░  ▒ ░░      ░   
        ░          ░  ░    ░  ░    ░  ░     ░  ░   ░     ░         ░   
                                              ░                      
    """)
    print(Fore.YELLOW + "WEB KNIGHT PRO ELITE ULTIMATE - Professional Web Reconnaissance")
    print(Fore.WHITE + "Version 4.1 | Enterprise Grade\n")
    
    # Parse ports
    ports = None
    if args.ports:
        try:
            ports = [int(p.strip()) for p in args.ports.split(',')]
        except ValueError:
            print(Fore.RED + "[!] Invalid port list. Using default ports." + Style.RESET_ALL)
            ports = COMMON_PORTS
    
    scanner = WebKnightPro(args.domain)
    async with scanner:
        print(Fore.BLUE + "[*] Discovering origin IPs..." + Style.RESET_ALL)
        await scanner.discover_origin_ips()
        
        print(Fore.BLUE + "[*] Enumerating subdomains..." + Style.RESET_ALL)
        await scanner.scan_subdomains(bruteforce=args.bruteforce)
        
        print(Fore.BLUE + "[*] Scanning critical directories..." + Style.RESET_ALL)
        await scanner.scan_directories()
        
        print(Fore.BLUE + "[*] Scanning ports..." + Style.RESET_ALL)
        await scanner.scan_ports(ports)
        
        scanner.print_results()
        
        if args.output:
            scanner.save_results(args.output)

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(Fore.RED + "\n[!] Scan interrupted by user" + Style.RESET_ALL)
    except Exception as e:
        print(Fore.RED + f"\n[!] An error occurred: {str(e)}" + Style.RESET_ALL)