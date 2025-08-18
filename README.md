<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Codexio Vulnerability Scanner</title>
    <style>
        :root {
            --primary: #2c3e50;
            --secondary: #3498db;
            --accent: #e74c3c;
            --light: #ecf0f1;
            --dark: #2c3e50;
            --success: #2ecc71;
            --warning: #f39c12;
            --code-bg: #f8f9fa;
        }
        
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
        }
        
        body {
            background-color: #f5f7fa;
            color: var(--dark);
            line-height: 1.6;
        }
        
        .container {
            max-width: 1200px;
            margin: 0 auto;
            padding: 0 20px;
        }
        
        header {
            background: linear-gradient(135deg, var(--primary), var(--secondary));
            color: white;
            padding: 3rem 0;
            text-align: center;
            margin-bottom: 2rem;
            position: relative;
            overflow: hidden;
        }
        
        header::after {
            content: "";
            position: absolute;
            bottom: -50px;
            left: 0;
            right: 0;
            height: 100px;
            background: #f5f7fa;
            transform: skewY(-2deg);
            z-index: 1;
        }
        
        .header-content {
            position: relative;
            z-index: 2;
        }
        
        h1 {
            font-size: 2.8rem;
            margin-bottom: 1rem;
            font-weight: 700;
        }
        
        .tagline {
            font-size: 1.3rem;
            opacity: 0.9;
            max-width: 800px;
            margin: 0 auto;
        }
        
        .card {
            background: white;
            border-radius: 10px;
            padding: 2rem;
            margin-bottom: 2rem;
            box-shadow: 0 5px 15px rgba(0,0,0,0.05);
            position: relative;
            z-index: 2;
        }
        
        h2 {
            color: var(--primary);
            margin-bottom: 1.5rem;
            font-size: 1.8rem;
            position: relative;
            padding-bottom: 0.5rem;
        }
        
        h2::after {
            content: "";
            position: absolute;
            bottom: 0;
            left: 0;
            width: 60px;
            height: 3px;
            background: var(--secondary);
        }
        
        .tool-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(300px, 1fr));
            gap: 1.5rem;
            margin-top: 1.5rem;
        }
        
        .tool-card {
            background: var(--light);
            padding: 1.5rem;
            border-radius: 8px;
            border-left: 4px solid var(--secondary);
            transition: all 0.3s ease;
            box-shadow: 0 2px 5px rgba(0,0,0,0.05);
        }
        
        .tool-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 10px 20px rgba(0,0,0,0.1);
        }
        
        .tool-name {
            font-weight: 700;
            color: var(--primary);
            margin-bottom: 0.8rem;
            font-size: 1.2rem;
        }
        
        .features {
            margin: 2rem 0;
        }
        
        .feature-list {
            list-style-type: none;
        }
        
        .feature-list li {
            padding: 0.8rem 0;
            position: relative;
            padding-left: 2rem;
            border-bottom: 1px solid #eee;
        }
        
        .feature-list li:last-child {
            border-bottom: none;
        }
        
        .feature-list li::before {
            content: "✓";
            color: var(--success);
            position: absolute;
            left: 0;
            font-weight: bold;
            font-size: 1.1rem;
        }
        
        .usage {
            background: var(--code-bg);
            padding: 1.5rem;
            border-radius: 8px;
            font-family: 'Courier New', Courier, monospace;
            overflow-x: auto;
            margin: 1.5rem 0;
            border-left: 4px solid var(--secondary);
        }
        
        .usage p {
            margin-bottom: 0.5rem;
            white-space: pre;
        }
        
        .warning {
            background-color: #fff3f3;
            border-left: 4px solid var(--accent);
            padding: 1.5rem;
            margin: 2rem 0;
            border-radius: 8px;
        }
        
        .warning h2::after {
            background: var(--accent);
        }
        
        .btn {
            display: inline-block;
            background: var(--secondary);
            color: white;
            padding: 1rem 2rem;
            border-radius: 5px;
            text-decoration: none;
            font-weight: 600;
            margin-top: 1rem;
            transition: all 0.3s ease;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        
        .btn:hover {
            background: var(--primary);
            transform: translateY(-2px);
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
        }
        
        .btn-container {
            text-align: center;
            margin: 2rem 0;
        }
        
        footer {
            text-align: center;
            margin-top: 3rem;
            padding: 2rem;
            color: #7f8c8d;
            background: white;
            border-top: 1px solid #eee;
        }
        
        /* Responsive Design */
        @media (max-width: 768px) {
            h1 {
                font-size: 2rem;
            }
            
            .tagline {
                font-size: 1.1rem;
            }
            
            .tool-grid {
                grid-template-columns: 1fr;
            }
            
            .card {
                padding: 1.5rem;
            }
        }
    </style>
</head>
<body>
    <header>
        <div class="container header-content">
            <h1>Codexio Vulnerability Scanner</h1>
            <p class="tagline">Advanced Automated Web Application Security Assessment Tool</p>
        </div>
    </header>
    
    <main class="container">
        <section class="card">
            <h2>About Codexio Scanner</h2>
            <p>The Codexio Vulnerability Scanner is a comprehensive security tool that combines multiple penetration testing utilities into a single, automated workflow. Designed for security professionals and developers, it helps identify vulnerabilities in web applications, servers, and networks while following OWASP security standards.</p>
        </section>
        
        <section class="card">
            <h2>Integrated Security Tools</h2>
            <div class="tool-grid">
                <div class="tool-card">
                    <div class="tool-name">Nikto</div>
                    <p>Comprehensive web server scanner that checks for 6700+ potentially dangerous files/CGIs, outdated server software, and version-specific problems.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">Nmap</div>
                    <p>Network exploration tool and security auditor that discovers hosts and services on a computer network.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">Dirb</div>
                    <p>Web content scanner that brute-forces directories and files names in web servers.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">SQLMap</div>
                    <p>Automates the process of detecting and exploiting SQL injection flaws and taking over database servers.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">WPScan</div>
                    <p>Black box WordPress vulnerability scanner that checks for vulnerable plugins, themes, and configurations.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">OWASP ZAP</div>
                    <p>Integrated penetration testing tool for finding vulnerabilities in web applications with automated scanners and various tools.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">XSStrike</div>
                    <p>Advanced Cross Site Scripting detection and exploitation suite with powerful fuzzing engine.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">Nuclei</div>
                    <p>Fast and customizable vulnerability scanner based on simple YAML templates.</p>
                </div>
                <div class="tool-card">
                    <div class="tool-name">Sublist3r</div>
                    <p>Fast subdomains enumeration tool for penetration testers with multiple data sources.</p>
                </div>
            </div>
        </section>
        
        <section class="card">
            <h2>Key Features</h2>
            <div class="features">
                <ul class="feature-list">
                    <li><strong>Automated Security Scanning</strong> - Run comprehensive security tests with a single command</li>
                    <li><strong>Detailed Reporting</strong> - Generate structured reports in multiple formats for analysis</li>
                    <li><strong>CMS-Specific Scans</strong> - Automatic detection and specialized scanning for WordPress, Joomla, and other CMS platforms</li>
                    <li><strong>Integrated Toolchain</strong> - Unified interface for 10+ security tools with coordinated workflow</li>
                    <li><strong>User-Friendly Interface</strong> - Simple terminal-based UI with progress indicators and clear output</li>
                    <li><strong>Customizable Scans</strong> - Configure scan depth, intensity, and specific test types</li>
                </ul>
            </div>
        </section>
        
        <section class="card">
            <h2>Installation & Usage</h2>
            <div class="usage">
                <p># Clone the repository</p>
                <p>git clone https://github.com/TDEMX/Codexio-Vuln-Scanner.git</p>
                <p>cd Codexio-Vuln-Scanner</p>
                <p># Make the script executable</p>
                <p>chmod +x codexio.py</p>
                <p># Run the scanner</p>
                <p>./codexio.py</p>
            </div>
            <p>After launching, enter the target URL (e.g., http://example.com) when prompted. The scanner will automatically run appropriate tests based on the target configuration.</p>
        </section>
        
        <section class="warning">
            <h2>Important Legal Notice</h2>
            <p>Codexio Vulnerability Scanner is designed for legitimate security testing purposes only. Unauthorized scanning of computer systems is illegal in many jurisdictions. Always obtain proper authorization before scanning any systems you don't own. The developers assume no liability and are not responsible for any misuse or damage caused by this program.</p>
        </section>
        
        <div class="btn-container">
            <a href="https://github.com/TDEMX/Codexio-Vuln-Scanner" class="btn">View Project on GitHub</a>
        </div>
    </main>
    
    <footer>
        <p>© 2023 Codexio Vulnerability Scanner | Ethical Hacking Tool</p>
        <p>Use responsibly and only with proper authorization</p>
    </footer>
</body>
</html>
