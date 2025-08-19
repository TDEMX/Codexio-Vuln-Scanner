#!/usr/bin/env python3
"""
රන් කිරීමේ ස්කැනරය - Nikto-inspired Web Vulnerability Scanner
මෙම script එක මගින් වෙබ් සර්වර් වල පොදු දුර්වලතා සොයා බලයි.
"""

import os
import argparse
import requests
import socket
import ssl
import json
import csv
import sys
from urllib.parse import urlparse
from datetime import datetime

# Disable SSL warnings for self-signed certificates
requests.packages.urllib3.disable_warnings()

# Banner for the scanner
BANNER = """
\033[1;33m
 ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗██╗ ██████╗ 
██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝██║██╔═══██╗
██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ ██║██║   ██║
██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ ██║██║   ██║
╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗██║╚██████╔╝
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ 
\033[1;32m   A N A L Y Z E R\033[0m          \033[1;33m|___/\033[0m

\033[1;36mAdvanced Web Application Vulnerability Scanner\033[0m
\033[1;31mCodexio Web New!\033[0m
"""

def clear_screen():
    """Clear the terminal screen"""
    os.system('clear' if os.name == 'posix' else 'cls')

def display_banner():
    """Display the tool banner"""
    clear_screen()
    print(BANNER)

def is_valid_url(url):
    """Check if the provided URL is valid"""
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

class Scanner:
    def __init__(self, target, output_format=None, output_file=None, 
                 use_ssl=False, port=None, timeout=10, user_agent=None):
        self.target = target
        self.output_format = output_format
        self.output_file = output_file
        self.use_ssl = use_ssl
        self.port = port
        self.timeout = timeout
        self.user_agent = user_agent or "RanKaranjaScanner/1.0"
        self.results = []
        self.session = requests.Session()
        self.session.verify = False  # Ignore SSL certificate verification
        
        # Set default port if not specified
        if not self.port:
            self.port = 443 if self.use_ssl else 80
        
        # Set the base URL
        scheme = "https" if self.use_ssl else "http"
        self.base_url = f"{scheme}://{self.target}:{self.port}"
        
        # Common security checks database (simplified)
        self.checks = [
            {"id": 1, "path": "/admin/", "description": "Admin directory"},
            {"id": 2, "path": "/phpinfo.php", "description": "PHPInfo file"},
            {"id": 3, "path": "/test/", "description": "Test directory"},
            {"id": 4, "path": "/backup/", "description": "Backup directory"},
            {"id": 5, "path": "/.git/", "description": "Git repository"},
            {"id": 6, "path": "/.env", "description": "Environment file"},
            {"id": 7, "path": "/wp-admin/", "description": "WordPress admin"},
            {"id": 8, "path": "/server-status", "description": "Server status"},
            {"id": 9, "path": "/.DS_Store", "description": "DS_Store file"},
            {"id": 10, "path": "/config.php", "description": "Configuration file"},
            {"id": 11, "path": "/robots.txt", "description": "Robots.txt file"},
            {"id": 12, "path": "/.htaccess", "description": "HTAccess file"},
            {"id": 13, "path": "/phpmyadmin/", "description": "phpMyAdmin"},
            {"id": 14, "path": "/mysql/", "description": "MySQL admin"},
            {"id": 15, "path": "/db/", "description": "Database directory"},
            {"id": 16, "path": "/backup.sql", "description": "Database backup"},
            {"id": 17, "path": "/upload/", "description": "Upload directory"},
            {"id": 18, "path": "/cgi-bin/", "description": "CGI bin directory"},
            {"id": 19, "path": "/admin/login.php", "description": "Admin login"},
            {"id": 20, "path": "/wp-login.php", "description": "WordPress login"},
        ]

    def get_server_info(self):
        """සර්වර් ගැන තොරතුරු ලබා ගනී"""
        try:
            headers = {'User-Agent': self.user_agent}
            response = self.session.get(self.base_url, headers=headers, timeout=self.timeout)
            server = response.headers.get('Server', 'Unknown')
            powered_by = response.headers.get('X-Powered-By', 'Not specified')
            return f"Server: {server}, Powered By: {powered_by}"
        except Exception as e:
            return f"Server information not available: {str(e)}"

    def check_ssl(self):
        """SSL certificate ගැන තොරතුරු ලබා ගනී"""
        if not self.use_ssl:
            return "Not using SSL"
        
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.target, self.port), timeout=self.timeout) as sock:
                with context.wrap_socket(sock, server_hostname=self.target) as ssock:
                    cert = ssock.getpeercert()
                    issuer = dict(x[0] for x in cert['issuer'])
                    subject = dict(x[0] for x in cert['subject'])
                    valid_from = cert.get('notBefore', 'Unknown')
                    valid_to = cert.get('notAfter', 'Unknown')
                    return f"SSL Certificate: Issuer: {issuer.get('organizationName', 'Unknown')}, " \
                           f"Subject: {subject.get('commonName', 'Unknown')}, " \
                           f"Valid From: {valid_from}, Valid To: {valid_to}"
        except Exception as e:
            return f"SSL Error: {str(e)}"

    def run_checks(self):
        """සියලුම security checks run කරයි"""
        print(f"\n\033[1;33m[*] Scanning {self.target}:{self.port}\033[0m")
        print(f"\033[1;33m[*] {self.get_server_info()}\033[0m")
        print(f"\033[1;33m[*] {self.check_ssl()}\033[0m")
        print("\033[1;33m[*] Starting vulnerability checks...\033[0m")
        
        for check in self.checks:
            url = self.base_url + check["path"]
            try:
                headers = {'User-Agent': self.user_agent}
                response = self.session.get(url, headers=headers, timeout=self.timeout, allow_redirects=False)
                
                if response.status_code == 200:
                    result = {
                        "id": check["id"],
                        "url": url,
                        "description": check["description"],
                        "status": response.status_code,
                        "size": len(response.content)
                    }
                    self.results.append(result)
                    print(f"\033[1;32m[+] Found: {check['description']} at {url}\033[0m")
                elif response.status_code in [301, 302, 307, 308]:
                    result = {
                        "id": check["id"],
                        "url": url,
                        "description": f"{check['description']} (Redirects to {response.headers.get('Location', 'Unknown')})",
                        "status": response.status_code,
                        "size": len(response.content)
                    }
                    self.results.append(result)
                    print(f"\033[1;33m[~] Redirect: {check['description']} at {url}\033[0m")
                
            except requests.exceptions.RequestException as e:
                print(f"\033[1;31m[!] Error checking {url}: {str(e)}\033[0m")
        
        print(f"\033[1;33m[*] Scan completed. Found {len(self.results)} potential issues.\033[0m")

    def save_results(self):
        """ප්‍රතිඵල save කරයි"""
        if not self.output_file:
            return
        
        try:
            if self.output_format == "txt":
                with open(self.output_file, 'w') as f:
                    f.write(f"Scan Report for {self.target}\n")
                    f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
                    f.write("="*50 + "\n")
                    for result in self.results:
                        f.write(f"[{result['id']}] {result['description']}\n")
                        f.write(f"URL: {result['url']}\n")
                        f.write(f"Status: {result['status']}, Size: {result['size']} bytes\n\n")
            
            elif self.output_format == "json":
                with open(self.output_file, 'w') as f:
                    json.dump({
                        "target": self.target,
                        "timestamp": datetime.now().isoformat(),
                        "results": self.results
                    }, f, indent=2)
            
            elif self.output_format == "csv":
                with open(self.output_file, 'w', newline='') as f:
                    writer = csv.writer(f)
                    writer.writerow(['ID', 'URL', 'Description', 'Status', 'Size'])
                    for result in self.results:
                        writer.writerow([
                            result['id'],
                            result['url'],
                            result['description'],
                            result['status'],
                            result['size']
                        ])
            
            print(f"\033[1;32m[*] Results saved to {self.output_file} in {self.output_format} format\033[0m")
        
        except Exception as e:
            print(f"\033[1;31m[!] Error saving results: {str(e)}\033[0m")

def main():
    display_banner()
    
    parser = argparse.ArgumentParser(description="රන් කිරීමේ ස්කැනරය - Nikto-inspired Web Vulnerability Scanner")
    parser.add_argument("-u", "--url", help="Target URL to scan (e.g., http://example.com)")
    parser.add_argument("-H", "--host", help="Target host to scan")
    parser.add_argument("-p", "--port", type=int, help="Port to scan (default: 80 or 443)")
    parser.add_argument("-s", "--ssl", action="store_true", help="Use SSL/TLS")
    parser.add_argument("-o", "--output", help="Output file name")
    parser.add_argument("-f", "--format", choices=["txt", "json", "csv"], 
                       help="Output format (default: txt)")
    parser.add_argument("-t", "--timeout", type=int, default=10, 
                       help="Timeout in seconds (default: 10)")
    parser.add_argument("-a", "--user-agent", help="Custom User-Agent string")
    
    # If no arguments provided, show help
    if len(sys.argv) == 1:
        parser.print_help()
        print("\n\033[1;36mInteractive mode:\033[0m")
        url = input("\n\033[1;37mEnter the target URL (e.g., http://example.com) or 'q' to quit: \033[0m")
        
        if url.lower() == 'q':
            print("\n\033[1;31mExiting Codexio Analyzer...\033[0m")
            return
            
        if not is_valid_url(url):
            print("\033[1;31mInvalid URL format. Please include http:// or https://\033[0m")
            return
        
        parsed_url = urlparse(url)
        host = parsed_url.netloc
        use_ssl = parsed_url.scheme == 'https'
        port = parsed_url.port if parsed_url.port else (443 if use_ssl else 80)
        
        output = input("\n\033[1;37mEnter output file name (or press Enter to skip): \033[0m")
        if output:
            format_choice = input("\n\033[1;37mEnter output format (txt, json, csv) [txt]: \033[0m") or "txt"
        else:
            format_choice = None
        
        scanner = Scanner(
            target=host,
            output_format=format_choice,
            output_file=output,
            use_ssl=use_ssl,
            port=port,
            timeout=10
        )
    else:
        args = parser.parse_args()
        
        # Determine target host
        if args.url:
            if not is_valid_url(args.url):
                print("\033[1;31mInvalid URL format. Please include http:// or https://\033[0m")
                return
            parsed_url = urlparse(args.url)
            host = parsed_url.netloc
            use_ssl = parsed_url.scheme == 'https'
            port = parsed_url.port if parsed_url.port else (443 if use_ssl else 80)
        elif args.host:
            host = args.host
            use_ssl = args.ssl
            port = args.port
        else:
            print("\033[1;31mYou must specify either a URL with -u/--url or a host with -H/--host\033[0m")
            return
        
        # Set default port if not specified
        if not port:
            port = 443 if use_ssl else 80
        
        # Set default format if output is specified but format is not
        if args.output and not args.format:
            args.format = "txt"
        
        scanner = Scanner(
            target=host,
            output_format=args.format,
            output_file=args.output,
            use_ssl=use_ssl,
            port=port,
            timeout=args.timeout,
            user_agent=args.user_agent
        )
    
    try:
        scanner.run_checks()
        if scanner.output_file:
            scanner.save_results()
    except KeyboardInterrupt:
        print("\n\033[1;31m[!] Scan interrupted by user\033[0m")
        sys.exit(1)
    except Exception as e:
        print(f"\033[1;31m[!] Error: {str(e)}\033[0m")
        sys.exit(1)

if __name__ == "__main__":
    main()
