# ParamBuster v7.0

**Production-Ready Advanced Parameter Detection and Vulnerability Scanner for Web Applications**

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Security](https://img.shields.io/badge/Security-Production--Ready-green.svg)]()

ParamBuster is a comprehensive, production-ready security tool designed for professional bug bounty hunters and security researchers. It features a unique **two-phase workflow**: first extracting parameters from every possible source, then allowing users to interactively choose which vulnerabilities to scan.

## 🚀 Key Features

### ⚡ High-Performance Architecture
- **Concurrent Discovery**: Multi-threaded parameter discovery using `ThreadPoolExecutor`.
- **Parallel Scanning**: Payload-level parallelization for lightning-fast vulnerability checks.
- **Performance Levels**: Switch between `low`, `medium`, and `high` performance modes.
- **Adaptive Rate Limiting**: Intelligent request throttling to avoid WAF blocks.

### 🔍 Advanced Multi-Source Parameter Extraction
ParamBuster extracts parameters from **15+ different sources**:

- **URL Parameters**: `extractURLParams()` - Query strings and hash fragments
- **DOM Elements**: `extractDOMURLParams()` - Links, images, forms, scripts with URLs
- **Browser Storage**: `extractCookies()`, `extractLocalStorage()`, `extractSessionStorage()`
- **Form Fields**: `extractFormFields()`, `extractHiddenInputs()` - All input types
- **Page Content**: `extractMetaTags()`, `extractInlineConfigs()` - Meta tags and JSON
- **JavaScript**: `extractJSVariables()` - Variable assignments and AJAX calls
- **Network**: Passive interception of fetch/XHR requests (browser mode)

### 🛡️ Interactive Vulnerability Scanning
**Two-Phase Workflow**:
1. **Parameter Discovery**: Extract and display all parameters with their states
2. **Vulnerability Testing**: User selects which vuln types to scan (1,2,3 or 'all')

**9 Vulnerability Types**:
- XSS (Cross-Site Scripting)
- SQLi (SQL Injection)
- SSRF (Server-Side Request Forgery)
- Open Redirect
- IDOR (Insecure Direct Object References)
- Path Traversal
- LFI (Local File Inclusion)
- Command Injection
- RCE (Remote Code Execution)
- **HPP (HTTP Parameter Pollution)**: Detects vulnerabilities arising from parameter duplication.
- **Context-Aware Reflection**: Identifies reflection in HTML, Attributes, Scripts, JSON, and XML.

### ⚡ Production-Ready Features
- **High Performance**: Optimized threading, 5-second timeouts, connection pooling
- **Smart Logging**: Clean console output + detailed file logging
- **Progress Tracking**: Real-time updates during scanning
- **Error Recovery**: Graceful failure handling and resource cleanup
- **Browser Automation**: Selenium-powered headless Chrome for modern apps

### 🎯 Unique Capabilities
- **Parameter State Analysis**: Shows reflection status, DOM sinks, and danger levels
- **Reflection Detection**: Multi-context parameter reflection analysis
- **Sink Analysis**: Identifies dangerous JavaScript sinks (innerHTML, eval, etc.)
- **Real-time Monitoring**: Continuous scanning for SPAs and dynamic content
- **Active Testing**: Browser-based payload injection into forms and cookies
- **Multi-format Export**: JSON, CSV, HTML reports with rich metadata

## 📋 Table of Contents

- [Installation](#installation)
- [Quick Start](#quick-start)
- [Two-Phase Workflow](#two-phase-workflow)
- [Usage Examples](#usage-examples)
- [Command Line Options](#command-line-options)
- [Parameter Sources](#parameter-sources)
- [Output Formats](#output-formats)
- [Configuration](#configuration)
- [Docker](#docker)
- [API Reference](#api-reference)
- [Contributing](#contributing)
- [Security](#security)
- [License](#license)

## 🛠️ Installation

### Prerequisites
- Python 3.8 or higher
- Chrome browser (for browser mode)
- pip package manager

### Install from Source
```bash
git clone https://github.com/LifeJiggy/ParamBuster.git
cd ParamBuster
pip install -r requirements.txt
```

### Docker Installation
```bash
docker build -t parambuster .
docker run -it parambuster -u https://example.com
```

## 🚀 Quick Start

### Basic Parameter Discovery
```bash
python ParamBuster.py -u https://example.com --performance high
```
**Output**: Extracts parameters, displays their states, asks for vulnerability scanning choice.

### Full Security Assessment
```bash
python ParamBuster.py -u https://target.com --browser --threads 20 --waf-bypass -o results.json
```

### With Detailed Logging
```bash
python ParamBuster.py -u https://target.com --verbose --log-file scan.log
```

## 🔄 Two-Phase Workflow

### Phase 1: Parameter Extraction
```
[+] Starting Parameter Extraction...

[INFO] - Starting parameter detection on https://target.com

[+] Found 15 parameters:
============================================================
Parameter: id
  Source: url_params_js
  Reflection: Yes (via body)
  DOM Sink: Yes
  Dangerous Sink: Yes

Parameter: session
  Source: cookies
  Reflection: No (via head)
  DOM Sink: No
  Dangerous Sink: No
```

### Phase 2: Interactive Vulnerability Selection
```
[+] Found 15 parameters to test for vulnerabilities

Select vulnerability types to scan:
1. XSS (Cross-Site Scripting)
2. SQLi (SQL Injection)
3. SSRF (Server-Side Request Forgery)
4. Open Redirect
5. IDOR (Insecure Direct Object References)
6. Path Traversal
7. LFI (Local File Inclusion)
8. Command Injection
9. RCE (Remote Code Execution)
all. Scan all vulnerability types
skip. Skip vulnerability scanning

Enter your choice (e.g., 1,2,3 or 'all' or 'skip'): 1,2,3
```

## 📖 Usage Examples

### Basic Parameter Discovery
```bash
python ParamBuster.py -u https://httpbin.org
```

### Browser Mode (Enhanced Extraction)
```bash
python ParamBuster.py -u https://example.com --browser
# Extracts from DOM, cookies, localStorage, sessionStorage
```

### Enterprise Security Assessment
```bash
python ParamBuster.py \
  -u https://enterprise-app.com \
  --browser \
  --threads 30 \
  --delay 0.1 \
  --waf-bypass \
  --payload-dir ./custom_payloads/ \
  --wordlist-dir ./enterprise_params/ \
  -o enterprise_scan.json \
  -f json
```

### Bug Bounty Hunting
```bash
python ParamBuster.py \
  -u https://bugbounty-target.com \
  --browser \
  --realtime 300 \
  --threads 10 \
  --waf-bypass \
  -o continuous_scan.log
```

### API Endpoint Testing
```bash
python ParamBuster.py \
  -u https://api.example.com/endpoint \
  -m POST \
  --browser \
  --threads 5 \
  -o api_params.csv \
  -f csv
```

### Verbose Mode with Logging
```bash
python ParamBuster.py \
  -u https://target.com \
  --verbose \
  --log-file detailed_scan.log \
  --browser
```

## 🎛️ Command Line Options

| Option | Description | Default | Example |
|--------|-------------|---------|---------|
| `-u, --url` | Target URL (required) | - | `https://example.com` |
| `-m, --method` | HTTP method | GET | `POST`, `JSON`, `XML` |
| `-t, --threads` | Concurrent threads | 50 | `100` |
| `--performance`| Performance level | medium | `low`, `medium`, `high` |
| `-d, --delay` | Delay between requests | 0 | `0.5` |
| `-p, --proxy` | Proxy URL | - | `http://127.0.0.1:8080` |
| `-o, --output` | Output file | - | `results.json` |
| `-f, --format` | Output format | json | `csv`, `html` |
| `--waf-bypass` | Enable WAF bypass | False | - |
| `--payload-dir` | Payload directory | lists/ | `./custom/` |
| `--wordlist-dir` | Wordlist directory | strong_wordlist/ | `./words/` |
| `--browser` | Browser automation | False | - |
| `--realtime` | Real-time interval | - | `60` |
| `--max-requests` | Max requests | 1000 | `5000` |
| `-v, --verbose` | Verbose console output | False | - |
| `--log-file` | Detailed log file | - | `scan.log` |

## 🔍 Parameter Sources

ParamBuster extracts parameters from these sources:

### URL-Based
- **Query Parameters**: `?id=123&user=admin`
- **Hash Fragments**: `#param=value`
- **JavaScript URLs**: `javascript:alert(1)`

### DOM-Based
- **Links**: `<a href="/page?id=123">`
- **Images**: `<img src="/image?id=456">`
- **Forms**: `<form action="/submit">` + inputs
- **Scripts**: `<script src="/api?token=abc">`

### Browser Storage
- **Cookies**: `document.cookie`
- **localStorage**: Browser local storage
- **sessionStorage**: Browser session storage

### Content-Based
- **Form Fields**: `<input name="username">`
- **Hidden Inputs**: `<input type="hidden" name="csrf">`
- **Meta Tags**: `<meta name="param" content="value">`
- **JSON Configs**: `{"api_key": "secret"}`
- **JavaScript Variables**: `var userId = "123"`

## 📊 Output Formats

### JSON Output
```json
{
  "scan_info": {
    "url": "https://example.com",
    "start_time": "2025-10-10T15:30:00Z",
    "duration": 45.2,
    "parameters_found": 15,
    "vulnerabilities_found": 3
  },
  "parameters": {
    "id": {
      "source": "url_params_js",
      "reflected": true,
      "critical": true,
      "vulnerabilities": {
        "sqli": {"severity": "Critical", "payload": "' OR 1=1 --"}
      }
    }
  }
}
```

### CSV Output
```csv
Parameter,Source,Reflected,Critical,Vulnerabilities
id,url_params_js,true,true,sqli: Critical
user,form_fields,false,false,
session,cookies,true,false,xss: High
```

### HTML Report
Interactive web report with filtering and charts.

## ⚙️ Configuration

### Custom Wordlists
```
strong_wordlist/
├── params.txt
├── params_big.txt
└── custom_params.txt
```

### Custom Payloads
```
lists/
├── xss.txt      # XSS payloads
├── sqli.txt     # SQL injection payloads
├── ssrf.txt     # SSRF payloads
└── rce.txt      # RCE payloads
```

## 🐳 Docker

### Build and Run
```bash
# Build image
docker build -t parambuster .

# Run interactive
docker run -it parambuster -u https://example.com

# Run with volume mounts
docker run -it \
  -v $(pwd)/output:/app/output \
  -v $(pwd)/custom_payloads:/app/custom_payloads \
  parambuster -u https://target.com -o /app/output/results.json
```

### Docker Compose
```bash
# Quick scan
docker-compose up parambuster

# Interactive mode
docker-compose run parambuster-interactive
```

## 🔧 API Reference

### ParamBuster Class

```python
from ParamBuster import ParamBuster

# Initialize
scanner = ParamBuster(
    url="https://example.com",
    method="GET",
    threads=20,
    browser_mode=True
)

# Run scan
results = scanner.run()

# Export results
scanner.save_report("results.json", "json")
```

### Key Methods

- `extract_hidden_parameters()`: Extract parameters from response
- `detect_parameters()`: Perform parameter discovery
- `print_summary()`: Display parameter states
- `interactive_vuln_selection()`: User vuln type selection
- `scan_selected_vulnerabilities()`: Scan chosen vuln types
- `analyze_sinks()`: Analyze dangerous JavaScript sinks

## 🤝 Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

### Development Setup
```bash
git clone https://github.com/LifeJiggy/ParamBuster.git
cd ParamBuster
pip install -r requirements-dev.txt
python -m pytest tests/
```

## 🔒 Security

### Responsible Disclosure
- Only test on systems you own or have explicit permission to test
- Respect robots.txt and rate limiting
- Do not perform unauthorized security testing

### Security Features
- SSL/TLS verification enabled by default
- Duplicate request detection and prevention
- Configurable request rate limiting
- Memory usage monitoring and limits
- Secure session management with retries

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is intended for authorized security testing and research purposes only. Users are responsible for complying with applicable laws and regulations. The authors assume no liability for misuse of this software.

## 🙏 Credits

**Developed by**: ArkhAngelLifeJiggy
**GitHub**: [https://github.com/LifeJiggy](https://github.com/LifeJiggy)

### Acknowledgments
- Inspired by ParamSpider, Arjun, and other parameter discovery tools
- Built with modern Python security libraries
- Tested on various web application frameworks

---

**Happy Hunting! 🐞⚡**