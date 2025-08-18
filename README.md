# Codexio Vulnerability Scanner 🔍

![Codexio Banner](https://i.imgur.com/JKQmZ7P.png)

**Advanced Automated Web Application Security Scanner**  
*Combining the power of multiple security tools into one unified interface*

## Table of Contents
- [Features](#features)
- [Included Tools](#included-tools)
- [Installation](#installation)
- [Usage](#usage)
- [Screenshots](#screenshots)
- [Contributing](#contributing)
- [License](#license)
- [Disclaimer](#disclaimer)

## Features ✨

- **Automated Security Scanning** - Run comprehensive tests with one command
- **CMS Detection** - Auto-detects WordPress, Joomla, and other platforms
- **Multiple Tool Integration** - 10+ security tools in one interface
- **Detailed Reporting** - Generate structured vulnerability reports
- **User-Friendly Interface** - Simple terminal-based workflow

## Included Tools 🛠️

| Tool | Purpose |
|------|---------|
| Nikto | Web server vulnerability scanning |
| Nmap | Network exploration and security auditing |
| Dirb | Directory brute-forcing |
| SQLMap | SQL injection detection and exploitation |
| WPScan | WordPress vulnerability scanning |
| OWASP ZAP | Web application security testing |
| XSStrike | Advanced XSS detection |
| Nuclei | Fast vulnerability scanning using templates |
| Sublist3r | Subdomain enumeration |
| testssl.sh | SSL/TLS configuration testing |

## Installation 💻

### Prerequisites
- Linux (Kali Linux recommended)
- Python 3.6+
- Git

### Installation Steps

```bash
# Clone the repository
git clone https://github.com/TDEMX/Codexio-Vuln-Scanner.git
cd Codexio-Vuln-Scanner

# Install dependencies
sudo apt update && sudo apt install -y python3 python3-pip git curl wget perl nmap nikto dirb sqlmap wpscan sublist3r golang zaproxy

# Install Python requirements
pip3 install -r requirements.txt

# Install additional tools
./install_tools.sh
