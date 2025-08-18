#!/usr/bin/env python3
import os
import subprocess
import time
import json
import requests
from urllib.parse import urlparse
import re
from colorama import Fore, Style, init

# Initialize colorama
init(autoreset=True)

# DeepSeek API Configuration
DEEPSEEK_API_KEY = "sk-fd3205437c744dbfbce3cb20c72026e5"  # Replace with your actual API key
DEEPSEEK_API_URL = "https://api.deepseek.com/v1/chat/completions"

BANNER = """
\033[1;33m
 ██████╗ ██████╗ ██████╗ ███████╗██╗  ██╗██╗ ██████╗ 
██╔════╝██╔═══██╗██╔══██╗██╔════╝╚██╗██╔╝██║██╔═══██╗
██║     ██║   ██║██║  ██║█████╗   ╚███╔╝ ██║██║   ██║
██║     ██║   ██║██║  ██║██╔══╝   ██╔██╗ ██║██║   ██║
╚██████╗╚██████╔╝██████╔╝███████╗██╔╝ ██╗██║╚██████╔╝
 ╚═════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝  ╚═╝╚═╝ ╚═════╝ 
\033[1;32m   A N A L Y Z E R\033[0m          \033[1;33m|___/\033[0m

\033[1;36mAdvanced Web Vulnerability Scanner with AI Remediation\033[0m
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

def run_nikto_scan(url):
    print(f"\n{Fore.YELLOW}[+] Running Nikto scan on {url}{Style.RESET_ALL}")
    try:
        result = subprocess.run(['nikto', '-h', url], capture_output=True, text=True)
        return result.stdout
    except FileNotFoundError:
        return "Nikto not found. Please install it with 'sudo apt install nikto'"

def parse_nikto_output(nikto_output):
    """Improved Nikto output parser with vulnerability categorization"""
    vulnerabilities = []
    critical_signatures = [
        ('XSS', r'XSS'),
        ('SQLi', r'SQL injection'),
        ('RCE', r'OSVDB-\d+.*command execution'),
        ('SSL', r'SSL.*weak'),
        ('Directory Listing', r'Directory listing found')
    ]
    
    for line in nikto_output.split('\n'):
        if '+ ' in line:
            for vuln_type, pattern in critical_signatures:
                if re.search(pattern, line, re.IGNORECASE):
                    vulnerabilities.append({
                        'type': vuln_type,
                        'description': line.strip(),
                        'severity': 'High' if vuln_type in ['SQLi', 'RCE'] else 'Medium'
                    })
                    break
            else:
                vulnerabilities.append({
                    'type': 'Info',
                    'description': line.strip(),
                    'severity': 'Low'
                })
    return vulnerabilities

def query_deepseek_for_remediation(vulnerability):
    """Query DeepSeek API for vulnerability remediation"""
    prompt = f"""
    As a cybersecurity expert, provide specific remediation for:
    {vulnerability['description']}
    
    Include:
    1. Short problem summary
    2. Step-by-step solution
    3. Relevant terminal commands
    4. Configuration changes needed
    
    Format as markdown.
    """
    
    headers = {
        "Authorization": f"Bearer {DEEPSEEK_API_KEY}",
        "Content-Type": "application/json"
    }
    payload = {
        "model": "deepseek-chat",
        "messages": [{"role": "user", "content": prompt}],
        "temperature": 0.5
    }
    
    try:
        response = requests.post(DEEPSEEK_API_URL, headers=headers, json=payload)
        response.raise_for_status()
        return response.json()["choices"][0]["message"]["content"]
    except Exception as e:
        return f"API Error: {str(e)}"

def display_results(url, vulnerabilities):
    """Display vulnerabilities and AI-powered solutions"""
    print(f"\n{Fore.CYAN}══════════════════════════════════════════════════")
    print(f" Scan Results for: {url}")
    print(f"══════════════════════════════════════════════════{Style.RESET_ALL}")
    
    for idx, vuln in enumerate(vulnerabilities, 1):
        print(f"\n{Fore.YELLOW}⚠️ Vulnerability #{idx}: {vuln['type']} ({vuln['severity']})")
        print(f"{Fore.WHITE}{vuln['description']}")
        
        # Get AI-powered solution
        print(f"\n{Fore.GREEN}🛡️ DeepSeek AI Recommendation:")
        solution = query_deepseek_for_remediation(vuln)
        print(f"{Fore.CYAN}{solution}")
        
        print(f"{Fore.CYAN}──────────────────────────────────────────────────")

def main():
    display_banner()
    url = input(f"\n{Fore.WHITE}Enter target URL (e.g., http://example.com): ")
    
    if not is_valid_url(url):
        print(f"{Fore.RED}Invalid URL format! Please include http:// or https://")
        return
    
    print(f"\n{Fore.YELLOW}Starting scan on {url}...{Style.RESET_ALL}")
    
    # Run Nikto scan
    nikto_output = run_nikto_scan(url)
    
    # Parse vulnerabilities
    vulnerabilities = parse_nikto_output(nikto_output)
    
    if not vulnerabilities:
        print(f"{Fore.GREEN}No vulnerabilities found!{Style.RESET_ALL}")
        return
    
    # Display results with AI solutions
    display_results(url, vulnerabilities)
    
    # Save report
    timestamp = time.strftime("%Y%m%d_%H%M%S")
    report_file = f"nikto_scan_{urlparse(url).netloc}_{timestamp}.txt"
    with open(report_file, 'w') as f:
        f.write(f"Scan Report for {url}\n")
        f.write(f"Generated at: {time.strftime('%Y-%m-%d %H:%M:%S')}\n\n")
        for vuln in vulnerabilities:
            f.write(f"== {vuln['type']} ({vuln['severity']}) ==\n")
            f.write(f"{vuln['description']}\n\n")
    
    print(f"\n{Fore.GREEN}Report saved to {report_file}{Style.RESET_ALL}")

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Scan interrupted by user.{Style.RESET_ALL}")
    except Exception as e:
        print(f"\n{Fore.RED}Error: {str(e)}{Style.RESET_ALL}")
