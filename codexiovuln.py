#!/usr/bin/env python3

import os
import subprocess
import time
import requests
import socket
import ssl
import argparse
from urllib.parse import urlparse, urljoin
from datetime import datetime

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
\033[1;31mNow with OWASP ZAP, XSStrike, Nuclei, Subdomain Enumeration & More!\033[0m
"""

class SimpleNikto:
    def __init__(self, target_url):
        self.target_url = target_url if target_url.startswith(('http://', 'https://')) else f'http://{target_url}'
        self.parsed_url = urlparse(self.target_url)
        self.host = self.parsed_url.netloc
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.114 Safari/537.36'
        })
        self.results = []
        
    def print_banner(self):
        print("\n\033[1;33m[+] Running Custom Nikto-like Scanner\033[0m")
        
    def check_server_info(self):
        """Check server information and headers"""
        try:
            response = self.session.get(self.target_url, timeout=10)
            server = response.headers.get('Server', 'Not detected')
            powered_by = response.headers.get('X-Powered-By', 'Not detected')
            
            self.log_result('INFO', f"HTTP Status: {response.status_code}")
            self.log_result('INFO', f"Server: {server}")
            self.log_result('INFO', f"X-Powered-By: {powered_by}")
            
            # Check for missing security headers
            security_headers = {
                'X-Frame-Options': 'Missing X-Frame-Options header (clickjacking protection)',
                'X-XSS-Protection': 'Missing X-XSS-Protection header (XSS protection)',
                'X-Content-Type-Options': 'Missing X-Content-Type-Options header (MIME sniffing protection)',
                'Strict-Transport-Security': 'Missing HSTS header (SSL/TLS enforcement)',
                'Content-Security-Policy': 'Missing Content-Security-Policy header (XSS protection)'
            }
            
            for header, message in security_headers.items():
                if header not in response.headers:
                    self.log_result('MEDIUM', message)
            
            return response
        except Exception as e:
            self.log_result('ERROR', f"Failed to retrieve server info: {str(e)}")
            return None
    
    def check_ssl(self):
        """Check SSL certificate details"""
        try:
            context = ssl.create_default_context()
            with socket.create_connection((self.host, 443), timeout=10) as sock:
                with context.wrap_socket(sock, server_hostname=self.host) as ssock:
                    cert = ssock.getpeercert()
                    
                    # Check certificate expiration
                    expire_date = datetime.strptime(cert['notAfter'], '%b %d %H:%M:%S %Y %Z')
                    days_until_expire = (expire_date - datetime.now()).days
                    
                    self.log_result('INFO', f"SSL Certificate Issuer: {cert['issuer']}")
                    self.log_result('INFO', f"SSL Certificate Expires: {expire_date} ({days_until_expire} days)")
                    
                    if days_until_expire < 30:
                        self.log_result('HIGH', f"SSL Certificate expires soon: {days_until_expire} days")
        except Exception as e:
            self.log_result('INFO', f"No SSL certificate or SSL error: {str(e)}")
    
    def test_common_files(self):
        """Test for common sensitive files and directories"""
        common_paths = [
            '/admin/', '/wp-admin/', '/administrator/', '/backup/', '/phpinfo.php',
            '/test.php', '/info.php', '/robots.txt', '/.git/', '/.env', '/.htaccess',
            '/backup.zip', '/database.sql', '/config.php', '/login.php', '/admin.php'
        ]
        
        for path in common_paths:
            full_url = urljoin(self.target_url, path)
            try:
                response = self.session.get(full_url, timeout=5)
                if response.status_code == 200:
                    self.log_result('LOW', f"Found accessible path: {full_url}")
                elif response.status_code == 403:
                    self.log_result('INFO', f"Restricted access: {full_url}")
            except:
                pass
    
    def test_http_methods(self):
        """Test for potentially dangerous HTTP methods"""
        methods = ['OPTIONS', 'TRACE', 'PUT', 'DELETE']
        try:
            for method in methods:
                response = self.session.request(method, self.target_url, timeout=5)
                if response.status_code < 400:
                    self.log_result('MEDIUM', f"HTTP method allowed: {method}")
        except:
            pass
    
    def test_directory_traversal(self):
        """Test for directory traversal vulnerabilities"""
        traversal_patterns = [
            '../etc/passwd', '..\\..\\..\\windows\\system32\\drivers\\etc\\hosts',
            '....//....//....//etc/passwd', '%2e%2e%2fetc%2fpasswd'
        ]
        
        for pattern in traversal_patterns:
            test_url = urljoin(self.target_url, f"?file={pattern}")
            try:
                response = self.session.get(test_url, timeout=5)
                if "root:" in response.text or "[boot loader]" in response.text:
                    self.log_result('HIGH', f"Possible directory traversal: {test_url}")
            except:
                pass
    
    def log_result(self, level, message):
        """Log results with severity level"""
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"  [{timestamp}] [{level}] {message}")
        self.results.append((level, message))
    
    def generate_report(self):
        """Generate a simple scan report"""
        report = "\n\033[1;35m  === CUSTOM NIKTO SCAN RESULTS ===\033[0m\n"
        
        high_count = sum(1 for level, _ in self.results if level == 'HIGH')
        medium_count = sum(1 for level, _ in self.results if level == 'MEDIUM')
        low_count = sum(1 for level, _ in self.results if level == 'LOW')
        
        report += f"  High severity findings: {high_count}\n"
        report += f"  Medium severity findings: {medium_count}\n"
        report += f"  Low severity findings: {low_count}\n"
        report += f"  Total findings: {len(self.results)}\n"
        
        if high_count > 0:
            report += "\n  High severity issues:\n"
            for level, message in self.results:
                if level == 'HIGH':
                    report += f"    - {message}\n"
        
        return report
    
    def run_scan(self):
        """Run the complete security scan"""
        self.print_banner()
        
        # Run various security checks
        self.check_server_info()
        self.check_ssl()
        self.test_common_files()
        self.test_http_methods()
        self.test_directory_traversal()
        
        # Generate report
        return self.generate_report()

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def display_banner():
    clear_screen()
    print(BANNER)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme, result.netloc])
    except ValueError:
        return False

def is_wordpress(url):
    try:
        response = subprocess.run(['curl', '-s', '-I', f'{url}/wp-admin/'], 
                                capture_output=True, text=True)
        return 'wp-admin' in response.stdout
    except:
        return False

def is_joomla(url):
    try:
        response = subprocess.run(['curl', '-s', f'{url}/administrator/'], 
                                capture_output=True, text=True)
        return 'joomla' in response.stdout.lower()
    except:
        return False

def run_nikto_scan(url):
    print(f"\n\033[1;34m[+] Running Nikto scan on {url}\033[0m")
    try:
        result = subprocess.run(['nikto', '-h', url], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Nikto not found. Please install it with 'sudo apt install nikto'"

def run_nmap_scan(url):
    print(f"\033[1;34m[+] Running Nmap scan on {url}\033[0m")
    try:
        result = subprocess.run(['nmap', '-sV', '--script=vulners', urlparse(url).netloc], 
                             capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Nmap not found. Please install it with 'sudo apt install nmap'"

def run_dirb_scan(url):
    print(f"\033[1;34m[+] Running directory brute-force scan on {url}\033[0m")
    try:
        result = subprocess.run(['dirb', url], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "DIRB not found. Please install it with 'sudo apt install dirb'"

def run_sqlmap_scan(url):
    print(f"\033[1;34m[+] Running SQL injection scan on {url}\033[0m")
    try:
        result = subprocess.run(['sqlmap', '-u', url, '--batch', '--crawl=1', '--level=2', '--risk=2'], 
                              capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "SQLmap not found. Please install it with 'sudo apt install sqlmap'"

def run_wpscan(url):
    print(f"\033[1;34m[+] Running WordPress vulnerability scan on {url}\033[0m")
    try:
        result = subprocess.run(['wpscan', '--url', url, '--enumerate', 'vp', '--plugins-detection', 'mixed'], 
                              capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "WPScan not found. Please install it with 'sudo apt install wpscan'"

def run_owasp_zap_scan(url):
    print(f"\n\033[1;34m[+] Running OWASP ZAP scan on {url}\033[0m")
    try:
        result = subprocess.run(['zap-cli', 'quick-scan', '--self-contained', '--start-options', '-config api.key=12345', url], 
                             capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "OWASP ZAP not found. Install with 'sudo apt install zaproxy && pip install zapcli'"

def run_xsstrike_scan(url):
    print(f"\n\033[1;34m[+] Running XSStrike scan on {url}\033[0m")
    try:
        result = subprocess.run(['python3', 'XSStrike/xsstrike.py', '-u', url, '--timeout', '10'], 
                             capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "XSStrike not found. Clone from GitHub: 'git clone https://github.com/s0md3v/XSStrike'"

def run_nuclei_scan(url):
    print(f"\n\033[1;34m[+] Running Nuclei scan on {url}\033[0m")
    try:
        result = subprocess.run(['nuclei', '-u', url, '-t', '~/nuclei-templates'], 
                             capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Nuclei not found. Install with 'go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest'"

def run_subdomain_scan(domain):
    print(f"\n\033[1;34m[+] Running Subdomain scan on {domain}\033[0m")
    try:
        result = subprocess.run(['sublist3r', '-d', domain, '-o', 'subdomains.txt'], 
                             capture_output=True, text=True)
        with open("subdomains.txt", "r") as f:
            return f.read()
    except FileNotFoundError:
        return "Sublist3r not found. Install with 'sudo apt install sublist3r'"

def run_ssl_scan(url):
    print(f"\n\033[1;34m[+] Running SSL/TLS scan on {url}\033[0m")
    try:
        domain = urlparse(url).netloc
        result = subprocess.run(['testssl.sh', domain], 
                             capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "testssl.sh not found. Download from GitHub."

def run_joomscan(url):
    print(f"\n\033[1;34m[+] Running JoomScan on {url}\033[0m")
    try:
        result = subprocess.run(['perl', 'joomscan/joomscan.pl', '-u', url], 
                             capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "JoomScan not found. Install from GitHub: 'git clone https://github.com/rezasp/joomscan'"

def run_custom_nikto_scan(url):
    """Run our custom Nikto-like scanner"""
    scanner = SimpleNikto(url)
    return scanner.run_scan()

def generate_report(url, scan_results):
    report = f"""
\033[1;35m
=============================================
        VULNERABILITY SCAN REPORT
=============================================
Target URL: {url}
Scan Date: {time.strftime("%Y-%m-%d %H:%M:%S")}
WordPress Detected: {'Yes' if scan_results['is_wp'] else 'No'}
Joomla Detected: {'Yes' if scan_results['is_joomla'] else 'No'}
=============================================
\033[0m"""

    for scan_name, result in scan_results.items():
        if scan_name not in ['is_wp', 'is_joomla'] and result:
            report += f"""
\033[1;32m
=== {scan_name.upper().replace('_', ' ')} RESULTS ===
\033[0m
{result}"""

    report += """
\033[1;31m
=== SCAN COMPLETE ===
\033[0m
"""
    return report

def main():
    display_banner()
    
    while True:
        url = input("\n\033[1;37mEnter the target URL (e.g., http://example.com) or 'q' to quit: \033[0m")
        
        if url.lower() == 'q':
            print("\n\033[1;31mExiting Codexio Analyzer...\033[0m")
            break
            
        if not is_valid_url(url):
            print("\033[1;31mInvalid URL format. Please include http:// or https://\033[0m")
            continue
            
        print(f"\n\033[1;33mStarting advanced scan on {url}...\033[0m")
        
        scan_results = {
            'is_wp': is_wordpress(url),
            'is_joomla': is_joomla(url),
            'nikto_scan': run_nikto_scan(url),
            'custom_nikto_scan': run_custom_nikto_scan(url),
            'nmap_scan': run_nmap_scan(url),
            'dirb_scan': run_dirb_scan(url),
            'sqlmap_scan': run_sqlmap_scan(url),
            'owasp_zap_scan': run_owasp_zap_scan(url),
            'xsstrike_scan': run_xsstrike_scan(url),
            'nuclei_scan': run_nuclei_scan(url),
            'subdomain_scan': run_subdomain_scan(urlparse(url).netloc),
            'ssl_scan': run_ssl_scan(url)
        }
        
        if scan_results['is_wp']:
            scan_results['wpscan'] = run_wpscan(url)
        if scan_results['is_joomla']:
            scan_results['joomscan'] = run_joomscan(url)
        
        report = generate_report(url, scan_results)
        print(report)
        
        save = input("\n\033[1;37mDo you want to save the report to a file? (y/n): \033[0m")
        if save.lower() == 'y':
            filename = f"scan_report_{urlparse(url).netloc}_{time.strftime('%Y%m%d_%H%M%S')}.txt"
            with open(filename, 'w') as f:
                f.write(report)
            print(f"\033[1;32mReport saved as {filename}\033[0m")
        
        input("\nPress Enter to continue scanning or Ctrl+C to exit...")
        display_banner()

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n\033[1;31mScan interrupted. Exiting...\033[0m")
    except Exception as e:
        print(f"\n\033[1;31mAn error occurred: {str(e)}\033[0m")
