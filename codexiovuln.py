#!/usr/bin/env python3

import os
import subprocess
import time
from urllib.parse import urlparse

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
