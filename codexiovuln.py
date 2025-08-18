#!/usr/bin/env python3

import os
import subprocess
import time
from urllib.parse import urlparse
import sys
import signal

BANNER = """
\033[1;33m
  ____      _     _ _       _          _   _              
 / ___|___ | | __| (_) ___ (_)______ _| |_(_)_ __   __ _ 
| |   / _ \| |/ _` | |/ _ \| |_  / _` | __| | '_ \ / _` |
| |__| (_) | | (_| | | (_) | |/ / (_| | |_| | | | | (_| |
 \____\___/|_|\__,_|_|\___/|_/___\__,_|\__|_|_| |_|\__, |
\033[1;32m   C O D E X I O\033[0m          \033[1;33m|___/\033[0m

\033[1;36mAdvanced Web Vulnerability Scanner\033[0m
"""

def signal_handler(sig, frame):
    print("\n\033[1;31m[!] Scan interrupted by user. Exiting...\033[0m")
    sys.exit(0)

def clear_screen():
    os.system('clear' if os.name == 'posix' else 'cls')

def display_banner():
    clear_screen()
    print(BANNER)

def is_valid_url(url):
    try:
        result = urlparse(url)
        return all([result.scheme in ('http', 'https'), result.netloc])
    except ValueError:
        return False

def check_dependencies():
    required_tools = ['nikto', 'nmap', 'dirb', 'sqlmap', 'wpscan']
    missing = []
    
    for tool in required_tools:
        try:
            subprocess.run([tool, '--version'], 
                         stdout=subprocess.DEVNULL,
                         stderr=subprocess.DEVNULL)
        except FileNotFoundError:
            missing.append(tool)
    
    if missing:
        print("\033[1;31m[!] Missing dependencies:\033[0m")
        for tool in missing:
            print(f"- {tool} (install with: sudo apt install {tool})")
        return False
    return True

def run_scan(command, scan_type):
    try:
        print(f"\033[1;34m[+] Starting {scan_type} scan...\033[0m")
        process = subprocess.Popen(command,
                                stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE,
                                text=True)
        
        while True:
            output = process.stdout.readline()
            if output == '' and process.poll() is not None:
                break
            if output:
                print(f"\033[1;36m[+] {scan_type}: \033[0m{output.strip()}")
        
        return f"{scan_type} scan completed successfully"
    except Exception as e:
        return f"{scan_type} scan failed: {str(e)}"

def generate_html_report(url, results):
    timestamp = time.strftime("%Y-%m-%d %H:%M:%S")
    filename = f"report_{urlparse(url).netloc}_{time.strftime('%Y%m%d_%H%M%S')}.html"
    
    html = f"""
<!DOCTYPE html>
<html>
<head>
    <title>Scan Report for {url}</title>
    <style>
        body {{ font-family: Arial, sans-serif; line-height: 1.6; }}
        h1, h2 {{ color: #2c3e50; }}
        .vulnerability {{ background: #f8d7da; padding: 10px; margin: 5px 0; }}
        .success {{ background: #d4edda; padding: 10px; margin: 5px 0; }}
        pre {{ background: #f8f9fa; padding: 15px; border-radius: 5px; }}
    </style>
</head>
<body>
    <h1>Vulnerability Scan Report</h1>
    <p><strong>Target URL:</strong> {url}</p>
    <p><strong>Scan Date:</strong> {timestamp}</p>
    
    <h2>Scan Results</h2>
    <div class="results">
"""

    for scan_type, result in results.items():
        html += f"""
        <h3>{scan_type}</h3>
        <pre>{result}</pre>
        <hr>
"""

    html += """
    </div>
</body>
</html>
"""
    
    with open(filename, 'w') as f:
        f.write(html)
    
    return filename

def main():
    signal.signal(signal.SIGINT, signal_handler)
    display_banner()
    
    if not check_dependencies():
        print("\n\033[1;31m[!] Please install missing dependencies first.\033[0m")
        sys.exit(1)
    
    while True:
        url = input("\n\033[1;37mEnter target URL (e.g., https://example.com) or 'q' to quit: \033[0m").strip()
        
        if url.lower() == 'q':
            print("\n\033[1;32m[+] Thank you for using Codexio Scanner!\033[0m")
            break
            
        if not is_valid_url(url):
            print("\033[1;31m[!] Invalid URL format. Please include http:// or https://\033[0m")
            continue
        
        print(f"\n\033[1;33m[~] Initializing scan on {url}...\033[0m")
        
        # Run scans
        scan_results = {
            'Nikto Scan': run_scan(['nikto', '-h', url, '-nointeractive'], 'Nikto'),
            'Nmap Scan': run_scan(['nmap', '-sV', '--script=vulners', urlparse(url).netloc], 'Nmap'),
            'Directory Scan': run_scan(['dirb', url], 'Directory'),
            'SQL Injection Scan': run_scan(['sqlmap', '-u', url, '--batch', '--crawl=1'], 'SQL Injection')
        }
        
        # Generate report
        report_file = generate_html_report(url, scan_results)
        print(f"\n\033[1;32m[+] Scan completed! Report saved as {report_file}\033[0m")
        
        another = input("\n\033[1;37mScan another target? (y/n): \033[0m").lower()
        if another != 'y':
            print("\n\033[1;32m[+] Thank you for using Codexio Scanner!\033[0m")
            break
            
        display_banner()

if __name__ == "__main__":
    main()
