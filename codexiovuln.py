#!/usr/bin/env python3

import os
import subprocess
import time
from urllib.parse import urlparse

BANNER = """
\033[1;33m
  ____      _     _ _       _          _   _              
 / ___|___ | | __| (_) ___ (_)______ _| |_(_)_ __   __ _ 
| |   / _ \| |/ _` | |/ _ \| |_  / _` | __| | '_ \ / _` |
| |__| (_) | | (_| | | (_) | |/ / (_| | |_| | | | | (_| |
 \____\___/|_|\__,_|_|\___/|_/___\__,_|\__|_|_| |_|\__, |
\033[1;32m   A N A L Y Z E R\033[0m          \033[1;33m|___/\033[0m

\033[1;36mAdvanced Web Application Vulnerability Scanner\033[0m
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
    """Check if the target is a WordPress site"""
    try:
        response = subprocess.run(['curl', '-s', '-I', f'{url}/wp-admin/'], 
                                capture_output=True, text=True)
        return 'wp-admin' in response.stdout
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

def generate_report(url, nikto_result, nmap_result, dirb_result, sqlmap_result, wpscan_result, is_wp):
    report = f"""
\033[1;35m
=============================================
        VULNERABILITY SCAN REPORT
=============================================
Target URL: {url}
Scan Date: {time.strftime("%Y-%m-%d %H:%M:%S")}
WordPress Detected: {'Yes' if is_wp else 'No'}
=============================================
\033[0m

\033[1;32m
=== NIKTO SCAN RESULTS ===
\033[0m
{nikto_result}

\033[1;32m
=== NMAP SCAN RESULTS ===
\033[0m
{nmap_result}

\033[1;32m
=== DIRECTORY BRUTE-FORCE RESULTS ===
\033[0m
{dirb_result}

\033[1;32m
=== SQL INJECTION SCAN RESULTS ===
\033[0m
{sqlmap_result}
"""

    if is_wp:
        report += f"""
\033[1;32m
=== WORDPRESS VULNERABILITY SCAN RESULTS ===
\033[0m
{wpscan_result}
"""

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
            
        print(f"\n\033[1;33mStarting scan on {url}...\033[0m")
        
        # Check if WordPress
        is_wp = is_wordpress(url)
        
        # Run scans
        nikto_result = run_nikto_scan(url)
        nmap_result = run_nmap_scan(url)
        dirb_result = run_dirb_scan(url)
        sqlmap_result = run_sqlmap_scan(url)
        wpscan_result = run_wpscan(url) if is_wp else "WordPress not detected - Skipping WPScan"
        
        report = generate_report(url, nikto_result, nmap_result, dirb_result, 
                               sqlmap_result, wpscan_result, is_wp)
        
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