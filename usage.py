#!/usr/bin/env python3
"""
ParamBuster v7.0 - Usage Examples and Demonstrations

This file contains comprehensive usage examples for ParamBuster,
demonstrating the two-phase workflow and various scanning scenarios.

Run this file to see interactive examples:
    python usage.py

Or import specific functions:
    from usage import show_basic_usage, show_advanced_usage
"""

import os
import sys
import time
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

def print_header(title):
    """Print a formatted header."""
    print("\n" + "="*60)
    print(f" {title}")
    print("="*60)

# Handle Unicode encoding for Windows
import sys
if sys.platform == "win32":
    try:
        # Try to set console to UTF-8
        import subprocess
        subprocess.run(["chcp", "65001"], shell=True, capture_output=True)
    except:
        pass

def print_section(title):
    """Print a formatted section header."""
    print(f"\n{title}")
    print("-" * len(title))

def show_basic_usage():
    """Demonstrate basic parameter extraction."""
    print_header("🔍 BASIC PARAMETER EXTRACTION")

    print("""
# Basic parameter discovery - extracts from all sources
python ParamBuster.py -u https://bugcrowd.com

# Expected output:
# [+] Starting Parameter Extraction...
# [INFO] - Starting parameter detection on https://bugcrowd.com
#
# [+] Found 15 parameters:
# ================================================================
# Parameter: id
#   Source: url_params_js
#   Reflection: Yes (via body)
#   DOM Sink: Yes
#   Dangerous Sink: Yes
#
# Parameter: session
#   Source: cookies
#   Reflection: No (via head)
#   DOM Sink: No
#   Dangerous Sink: No
#
# [+] Found 15 parameters to test for vulnerabilities
#
# Select vulnerability types to scan:
# 1. XSS (Cross-Site Scripting)
# 2. SQLi (SQL Injection)
# 3. SSRF (Server-Side Request Forgery)
# 4. Open Redirect
# 5. IDOR (Insecure Direct Object References)
# 6. Path Traversal
# 7. LFI (Local File Inclusion)
# 8. Command Injection
# 9. RCE (Remote Code Execution)
# all. Scan all vulnerability types
# skip. Skip vulnerability scanning
#
# Enter your choice (e.g., 1,2,3 or 'all' or 'skip'):
    """)

def show_browser_mode():
    """Demonstrate browser mode for enhanced extraction."""
    print_header("🌐 BROWSER MODE - ENHANCED EXTRACTION")

    print("""
# Browser mode extracts from DOM, cookies, localStorage, sessionStorage
python ParamBuster.py -u https://example.com --browser

# Additional extraction methods in browser mode:
# - extractDOMURLParams(): Links, images, forms with URLs
# - extractCookies(): Browser cookies
# - extractLocalStorage(): localStorage keys
# - extractSessionStorage(): sessionStorage keys
# - Network interception: AJAX/fetch requests

# Example output with browser mode:
# [INFO] - Browser initialized for enhanced extraction
# [INFO] - extractDOMURLParams(): ['id', 'user', 'token']
# [INFO] - extractCookies(): ['session', 'csrf']
# [INFO] - extractLocalStorage(): ['user_pref', 'theme']
# [INFO] - extractSessionStorage(): ['temp_data']
    """)

def show_vulnerability_scanning():
    """Demonstrate vulnerability scanning options."""
    print_header("🛡️ VULNERABILITY SCANNING EXAMPLES")

    print_section("Interactive Selection Examples")

    print("""
# After parameter extraction, choose specific vulnerabilities:
# Enter your choice: 1,2,3
# Scans for XSS, SQLi, and SSRF

# Enter your choice: all
# Scans for all 9 vulnerability types

# Enter your choice: skip
# Skips vulnerability scanning, exits cleanly
    """)

    print_section("Direct Vulnerability Scanning")

    print("""
# Scan specific parameters for vulnerabilities (non-interactive)
python ParamBuster.py -u https://target.com --browser
# Then choose: 1,2,3 (XSS, SQLi, SSRF)

# Full security assessment
python ParamBuster.py \\
  -u https://target.com \\
  --browser \\
  --threads 20 \\
  --waf-bypass \\
  -o results.json

# Expected vulnerability output:
# [INFO] - Confirmed xss vulnerability in id with payload: <script>alert(1)</script> (Severity: High)
# [INFO] - Confirmed sqli vulnerability in user with payload: ' OR 1=1 -- (Severity: Critical)
    """)

def show_logging_examples():
    """Demonstrate logging capabilities."""
    print_header("📝 LOGGING AND OUTPUT EXAMPLES")

    print_section("Verbose Mode")

    print("""
# Verbose console output with detailed information
python ParamBuster.py -u https://target.com --verbose

# Shows DEBUG level information in console
# [DEBUG] - Testing parameter: id
# [INFO] - Detected parameter: id (Reflected: True)
# [DEBUG] - Request failed for user: Connection timeout
    """)

    print_section("File Logging")

    print("""
# Detailed logging to file (recommended for production)
python ParamBuster.py \\
  -u https://target.com \\
  --verbose \\
  --log-file scan_detailed.log

# Console: Clean, user-friendly messages
# Log file: DEBUG, WARNING, ERROR with full details
# [2025-10-10 15:30:00] DEBUG - Testing parameter id with value test123
# [2025-10-10 15:30:01] INFO - Parameter id reflected in response
# [2025-10-10 15:30:02] ERROR - Request timeout for parameter user
    """)

def show_output_formats():
    """Demonstrate different output formats."""
    print_header("📊 OUTPUT FORMAT EXAMPLES")

    print_section("JSON Output")

    print("""
python ParamBuster.py -u https://target.com -o results.json -f json

# Output structure:
{
  "scan_info": {
    "url": "https://target.com",
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
    """)

    print_section("CSV Output")

    print("""
python ParamBuster.py -u https://target.com -o results.csv -f csv

# CSV format:
Parameter,Source,Reflected,Critical,Vulnerabilities
id,url_params_js,true,true,sqli: Critical
user,form_fields,false,false,
session,cookies,true,false,xss: High
    """)

    print_section("HTML Report")

    print("""
python ParamBuster.py -u https://target.com -o report.html -f html

# Generates interactive HTML report with:
# - Parameter summary table
# - Vulnerability details
# - Charts and filtering
# - Professional styling
    """)

def show_advanced_scenarios():
    """Demonstrate advanced scanning scenarios."""
    print_header("🚀 ADVANCED SCANNING SCENARIOS")

    print_section("Enterprise Security Assessment")

    print("""
# Comprehensive enterprise scan
python ParamBuster.py \\
  -u https://enterprise-app.com \\
  --browser \\
  --threads 30 \\
  --delay 0.1 \\
  --waf-bypass \\
  --payload-dir ./custom_payloads/ \\
  --wordlist-dir ./enterprise_params/ \\
  -o enterprise_scan.json \\
  -f json \\
  --verbose \\
  --log-file enterprise_scan.log

# Features used:
# - Browser automation for modern SPAs
# - High thread count for speed
# - WAF bypass techniques
# - Custom payload/wordlist directories
# - Detailed logging and JSON output
    """)

    print_section("Bug Bounty Hunting")

    print("""
# Continuous monitoring for bug bounty targets
python ParamBuster.py \\
  -u https://bugbounty-target.com \\
  --browser \\
  --realtime 300 \\
  --threads 10 \\
  --waf-bypass \\
  -o continuous_scan.log \\
  --log-file bounty_detailed.log

# Features used:
# - Real-time scanning every 5 minutes
# - Browser mode for dynamic content
# - WAF bypass for protected targets
# - Continuous logging
    """)

    print_section("API Endpoint Testing")

    print("""
# API parameter discovery and testing
python ParamBuster.py \\
  -u https://api.example.com/endpoint \\
  -m POST \\
  --browser \\
  --threads 5 \\
  -o api_params.csv \\
  -f csv \\
  --verbose

# Features used:
# - POST method for API testing
# - Browser mode for JavaScript-heavy APIs
# - CSV output for easy analysis
# - Verbose output for debugging
    """)

def show_docker_usage():
    """Demonstrate Docker usage."""
    print_header("🐳 DOCKER USAGE EXAMPLES")

    print_section("Basic Docker Run")

    print("""
# Build and run with Docker
docker build -t parambuster .
docker run -it parambuster -u https://example.com

# Interactive scanning
docker run -it parambuster -u https://target.com --browser
    """)

    print_section("Docker with Volumes")

    print("""
# Mount volumes for persistent storage
docker run -it \\
  -v $(pwd)/output:/app/output \\
  -v $(pwd)/custom_payloads:/app/lists \\
  -v $(pwd)/custom_wordlists:/app/strong_wordlist \\
  parambuster \\
  -u https://target.com \\
  -o /app/output/results.json \\
  --browser \\
  --verbose
    """)

    print_section("Docker Compose")

    print("""
# Quick scan
docker-compose up parambuster

# Interactive mode
docker-compose run parambuster-interactive

# With custom volumes
docker-compose -f docker-compose.yml run parambuster-interactive
    """)

def show_parameter_sources():
    """Show all parameter extraction sources."""
    print_header("🔍 PARAMETER EXTRACTION SOURCES")

    print("""
ParamBuster extracts parameters from 15+ different sources:

🌐 URL-BASED EXTRACTION:
├── extractURLParams(): Query parameters (?id=123&user=admin)
├── extractHashFragments(): Hash parameters (#param=value)
└── extractJSURLs(): JavaScript URLs (javascript:alert(1))

🏗️ DOM-BASED EXTRACTION:
├── extractDOMURLParams(): Links, images, forms with URLs
├── extractFormFields(): <input name="username">
├── extractHiddenInputs(): <input type="hidden" name="csrf">
└── extractScripts(): <script> variables and URLs

🍪 BROWSER STORAGE EXTRACTION:
├── extractCookies(): document.cookie values
├── extractLocalStorage(): localStorage keys/values
└── extractSessionStorage(): sessionStorage keys/values

📄 CONTENT-BASED EXTRACTION:
├── extractMetaTags(): <meta name="param" content="value">
├── extractInlineConfigs(): JSON configurations
├── extractJSVariables(): var userId = "123"
└── extractAJAX(): AJAX/fetch request parameters

🔍 DETECTION METHODS:
├── Reflection Analysis: Parameter reflection in responses
├── Sink Analysis: Dangerous JavaScript sinks detection
└── Context Analysis: Multi-context parameter validation
    """)

def show_api_usage():
    """Demonstrate programmatic API usage."""
    print_header("🔧 PROGRAMMATIC API USAGE")

    print("""
# Import and use ParamBuster programmatically
from ParamBuster import ParamBuster

# Initialize scanner
scanner = ParamBuster(
    url="https://example.com",
    method="GET",
    threads=20,
    browser_mode=True,
    verbose=True
)

# Run parameter extraction only
scanner.detect_parameters()
scanner.print_summary()

# Interactive vulnerability selection
vuln_choice = scanner.interactive_vuln_selection()
if vuln_choice:
    scanner.scan_selected_vulnerabilities(vuln_choice)

# Export results
scanner.save_report("results.json", "json")

# Key API Methods:
# - extract_hidden_parameters(): Extract from response
# - detect_parameters(): Full parameter discovery
# - analyze_sinks(): Sink analysis
# - active_testing_stub(): Browser-based testing
    """)

def show_troubleshooting():
    """Show troubleshooting tips."""
    print_header("🔧 TROUBLESHOOTING GUIDE")

    print_section("Common Issues")

    print("""
❌ Issue: "Browser mode requires selenium"
✅ Fix: pip install selenium webdriver-manager

❌ Issue: "Chrome driver not found"
✅ Fix: Ensure Chrome browser is installed

❌ Issue: Scan hangs indefinitely
✅ Fix: Tool now uses 5-second timeouts, check network connectivity

❌ Issue: No parameters found
✅ Fix: Try --browser mode for dynamic content

❌ Issue: WAF blocking requests
✅ Fix: Use --waf-bypass flag

❌ Issue: Memory errors
✅ Fix: Reduce --threads or increase system memory
    """)

    print_section("Performance Tips")

    print("""
🚀 FAST SCANNING:
- Use --threads 50 for maximum speed
- Set --delay 0 for no delays
- Use --browser for comprehensive extraction

🚀 STEALTH SCANNING:
- Use --delay 1-2 seconds between requests
- Enable --waf-bypass for protected targets
- Use proxy with --proxy

🚀 PRODUCTION SCANNING:
- Use --log-file for detailed logging
- Set --max-requests to limit scope
- Use --verbose for debugging
    """)

def interactive_demo():
    """Run an interactive demonstration."""
    print_header("🎮 INTERACTIVE DEMONSTRATION")

    print("""
This demonstration shows the two-phase ParamBuster workflow:

Phase 1: Parameter Extraction
- Extracts parameters from all sources
- Displays parameter states and reflections
- Shows dangerous sinks and vulnerabilities

Phase 2: Vulnerability Scanning
- User selects which vulnerability types to scan
- Supports individual selection (1,2,3) or 'all'
- Can skip vulnerability scanning entirely

Example Workflow:
1. Run: python ParamBuster.py -u https://httpbin.org
2. Wait for parameter extraction to complete
3. Choose vulnerability types: "1,2,3" (XSS, SQLi, SSRF)
4. Review results and export if desired

Try it now with a test target!
    """)

def main():
    """Main demonstration function."""
    print_header("ParamBuster v7.0 - Usage Guide")
    print("""
Welcome to ParamBuster v7.0!

This tool features a unique two-phase workflow:
1. Parameter Extraction: Discover all parameters with their states
2. Vulnerability Scanning: Choose which vuln types to test

Choose a demonstration:
    """)

    options = {
        "1": ("Basic Usage", show_basic_usage),
        "2": ("Browser Mode", show_browser_mode),
        "3": ("Vulnerability Scanning", show_vulnerability_scanning),
        "4": ("Logging Examples", show_logging_examples),
        "5": ("Output Formats", show_output_formats),
        "6": ("Advanced Scenarios", show_advanced_scenarios),
        "7": ("Docker Usage", show_docker_usage),
        "8": ("Parameter Sources", show_parameter_sources),
        "9": ("API Usage", show_api_usage),
        "10": ("Troubleshooting", show_troubleshooting),
        "11": ("Interactive Demo", interactive_demo),
        "all": ("Show All", lambda: None),
    }

    # Print menu
    for key, (name, _) in options.items():
        if key != "all":
            print(f"    {key}. {name}")

    print("    all. Show All Demonstrations")
    print("    q. Quit")

    while True:
        try:
            choice = input("\nChoose an option (1-11, 'all', or 'q'): ").strip().lower()

            if choice == "q":
                print("\nHappy hunting! 🐞")
                break
            elif choice == "all":
                for key, (name, func) in options.items():
                    if key != "all":
                        func()
                break
            elif choice in options:
                options[choice][1]()
                input("\nPress Enter to continue...")
            else:
                print("Invalid choice. Please try again.")

        except KeyboardInterrupt:
            print("\n\nGoodbye! 🐞")
            break
        except Exception as e:
            print(f"Error: {e}")

if __name__ == "__main__":
    main()