<div align="center">
  <h1>🔒 Codexio Vulnerability Scanner</h1>
  <p>Advanced Web Application Security Scanner</p>
  
  <div>
    <img src="https://img.shields.io/badge/Python-3.x-blue?logo=python" alt="Python">
    <img src="https://img.shields.io/badge/License-MIT-green" alt="License">
    <img src="https://img.shields.io/github/last-commit/codexio/main-tool" alt="Last Commit">
  </div>
</div>

---

## 🚀 Features
<div style="display: flex; flex-wrap: wrap; gap: 10px;">
  <div style="background: #2d3748; padding: 10px; border-radius: 5px; flex: 1; min-width: 200px;">
    <h3>🛡️ Automated Scanning</h3>
    <p>Detects SQLi, XSS, misconfigurations and more</p>
  </div>
  <div style="background: #2d3748; padding: 10px; border-radius: 5px; flex: 1; min-width: 200px;">
    <h3>🔍 WordPress Analysis</h3>
    <p>Checks for vulnerable plugins/themes</p>
  </div>
  <div style="background: #2d3748; padding: 10px; border-radius: 5px; flex: 1; min-width: 200px;">
    <h3>📂 Directory Bruteforce</h3>
    <p>Finds hidden files with Dirb</p>
  </div>
</div>

---

## 🛠️ Installation
```bash

sudo apt update && sudo apt upgrade -y

sudo apt install -y python3 python3-pip git curl wget perl nmap nikto dirb sqlmap wpscan sublist3r golang zaproxy

pip3 install --user zapcli

git clone https://github.com/s0md3v/XSStrike.git
cd XSStrike && pip3 install -r requirements.txt && cd ..

go install -v github.com/projectdiscovery/nuclei/v2/cmd/nuclei@latest
echo 'export PATH=$PATH:~/go/bin' >> ~/.bashrc
source ~/.bashrc
git clone https://github.com/projectdiscovery/nuclei-templates.git ~/nuclei-templates

git clone https://github.com/rezasp/joomscan.git
cd joomscan && chmod +x joomscan.pl && cd ..

git clone --depth 1 https://github.com/drwetter/testssl.sh.git
ln -s $(pwd)/testssl.sh/testssl.sh /usr/local/bin/testssl.sh

git clone https://github.com/TDEMX/Codexio-Vuln-Scanner.git
cd Codexio-Vuln-Scanner
chmod +x codexio.py
pip3 install -r requirements.txt

echo -e "\n\033[1;32mInstallation complete!\033[0m"
echo -e "Run the scanner with: \033[1;33mcd Codexio-Vuln-Scanner && ./codexio.py\033[0m"
