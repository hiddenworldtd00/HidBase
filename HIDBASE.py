#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
╔═══════════════════════════════════════════════════════════════════════════════╗
║                                                                               ║
║   ██╗  ██╗██╗██████╗ ██████╗  █████╗ ███████╗███████╗                        ║
║   ██║  ██║██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝                        ║
║   ███████║██║██║  ██║██████╔╝███████║███████╗█████╗                          ║
║   ██╔══██║██║██║  ██║██╔══██╗██╔══██║╚════██║██╔══╝                          ║
║   ██║  ██║██║██████╔╝██████╔╝██║  ██║███████║███████╗                        ║
║   ╚═╝  ╚═╝╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝                        ║
║                                                                               ║
║   Database Discovery & Analysis Tool                                          ║
║   Version: 1.0.0                                                              ║
║   Developed by: HiddenWorld - Informaticien Tchadien 🇹🇩                       ║
║                                                                               ║
╚═══════════════════════════════════════════════════════════════════════════════╝

HIDBASE - Outil d'analyse et de découverte des bases de données d'un site web.
Détecte les types de BDD, les endpoints API, les injections potentielles,
les fichiers de configuration, et génère un rapport complet.
"""

import sys
import os
import re
import json
import time
import argparse
import urllib.request
import urllib.parse
import urllib.error
import ssl
from urllib.parse import urljoin, urlparse, parse_qs
from html.parser import HTMLParser

# ═══════════════════════════════════════════════════════════════════════════════
# COULEURS TERMINAL
# ═══════════════════════════════════════════════════════════════════════════════
class C:
    G = '\033[92m'   # Green
    Y = '\033[93m'   # Yellow
    R = '\033[91m'   # Red
    B = '\033[94m'   # Blue
    C = '\033[96m'   # Cyan
    M = '\033[95m'   # Magenta
    W = '\033[97m'   # White
    D = '\033[2m'    # Dim
    BD = '\033[1m'   # Bold
    UL = '\033[4m'   # Underline
    END = '\033[0m'  # Reset

def g(t): return f"{C.G}{t}{C.END}"
def y(t): return f"{C.Y}{t}{C.END}"
def r(t): return f"{C.R}{t}{C.END}"
def b(t): return f"{C.B}{t}{C.END}"
def c(t): return f"{C.C}{t}{C.END}"
def m(t): return f"{C.M}{t}{C.END}"
def w(t): return f"{C.W}{t}{C.END}"
def bd(t): return f"{C.BD}{t}{C.END}"

# ═══════════════════════════════════════════════════════════════════════════════
# BARRE DE PROGRESSION
# ═══════════════════════════════════════════════════════════════════════════════
def progress_bar(label, current, total, width=50):
    pct = int((current / total) * 100) if total > 0 else 100
    filled = int((current / total) * width) if total > 0 else width
    bar = f"{'█' * filled}{'░' * (width - filled)}"
    sys.stdout.write(f"\r{g(f'[{bar}]')} {c(f'{pct:3d}%')} {C.D}{label}{C.END}")
    sys.stdout.flush()

def progress_full(label, duration=2.0):
    print(f"\n{c(f'[OPERATION] {label}')}")
    print(f"{b('─' * 70)}")
    for i in range(1, 101):
        filled = int(i / 2)
        bar = f"{'█' * filled}{'░' * (50 - filled)}"
        sys.stdout.write(f"\r{g(f'[{bar}]')} {c(f'{i:3d}%')}")
        sys.stdout.flush()
        time.sleep(duration / 100)
    print()
    print(f"{b('─' * 70)}")

def ok(msg): print(f"{g('[✓ SUCCESS]')} {y(msg)}\n")
def ko(msg): print(f"{r('[✗ FAILED]')} {y(msg)}\n")
def info(msg): print(f"{b('[INFO]')} {msg}")
def warn(msg): print(f"{y('[WARNING]')} {msg}")
def err(msg): print(f"{r('[ERROR]')} {msg}")
def detail(lbl, val): print(f"{c(f'[{lbl}]')} {y(val)}")

# ═══════════════════════════════════════════════════════════════════════════════
# CONFIGURATION SSL
# ═══════════════════════════════════════════════════════════════════════════════
ctx = ssl.create_default_context()
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE

# ═══════════════════════════════════════════════════════════════════════════════
# BASES DE DONNÉES CONNUES ET LEURS SIGNATURES
# ═══════════════════════════════════════════════════════════════════════════════
DATABASE_SIGNATURES = {
    'MySQL': {
        'error_signatures': [
            r"MySQL.*error",
            r"mysql_.*\(",
            r"#HY000",
            r"Can't connect to MySQL",
            r"Warning: mysql_",
            r"MySQL server has gone away",
            r"You have an error in your SQL syntax",
            r"Unknown column",
            r"Table .* doesn't exist",
        ],
        'file_extensions': ['.sql', '.mysql', '.frm', '.ibd', '.myd', '.myi'],
        'config_files': ['my.cnf', 'my.ini', '.my.cnf', 'config/database.yml'],
        'default_ports': [3306],
        'connection_strings': [r"mysql://", r"mysqli://", r"pdo_mysql"],
    },
    'PostgreSQL': {
        'error_signatures': [
            r"PostgreSQL.*error",
            r"PG::Error",
            r"psql:.*error",
            r"ERROR:\s*",
            r"FATAL:\s*",
            r"warning:.*postgresql",
        ],
        'file_extensions': ['.sql', '.pgsql', '.dump', '.backup'],
        'config_files': ['pg_hba.conf', 'postgresql.conf', '.pgpass'],
        'default_ports': [5432],
        'connection_strings': [r"postgres://", r"postgresql://", r"pdo_pgsql"],
    },
    'MongoDB': {
        'error_signatures': [
            r"MongoDB.*error",
            r"MongoConnectionException",
            r"mongod.*failed",
            r"E11000 duplicate key",
            r"failed to connect to server",
        ],
        'file_extensions': ['.bson', '.mongodb', '.ns', '.0', '.1'],
        'config_files': ['mongod.conf', 'mongo.conf'],
        'default_ports': [27017, 27018, 27019],
        'connection_strings': [r"mongodb://", r"mongodb+srv://"],
    },
    'SQLite': {
        'error_signatures': [
            r"SQLite.*error",
            r"sqlite3.OperationalError",
            r"SQLITE_ERROR",
            r"SQLITE_MISUSE",
            r"no such table",
            r"database is locked",
        ],
        'file_extensions': ['.db', '.sqlite', '.sqlite3', '.db3', '.s3db'],
        'config_files': [],
        'default_ports': [],
        'connection_strings': [r"sqlite://"],
    },
    'Microsoft SQL Server': {
        'error_signatures': [
            r"Microsoft.*ODBC.*SQL",
            r"\[SQL Server\]",
            r"OLE DB.*SQL Server",
            r"SqlException",
            r"mssql_.*\(",
            r"Unclosed quotation mark",
            r"Incorrect syntax near",
        ],
        'file_extensions': ['.mdf', '.ndf', '.ldf', '.bak', '.trn'],
        'config_files': [],
        'default_ports': [1433, 1434],
        'connection_strings': [r"sqlserver://", r"mssql://", r"odbc:.*SQL"],
    },
    'Oracle': {
        'error_signatures': [
            r"ORA-\d{5}",
            r"Oracle.*error",
            r"OracleException",
            r"PLS-\d{5}",
            r"TNS:.*error",
        ],
        'file_extensions': ['.dbf', '.ora', '.dmp'],
        'config_files': ['tnsnames.ora', 'listener.ora'],
        'default_ports': [1521, 1526],
        'connection_strings': [r"oracle://", r"oci:"],
    },
    'Redis': {
        'error_signatures': [
            r"Redis.*error",
            r"ERR .*",
            r"WRONGTYPE",
            r"MOVED \d+",
        ],
        'file_extensions': ['.rdb', '.aof'],
        'config_files': ['redis.conf'],
        'default_ports': [6379],
        'connection_strings': [r"redis://", r"rediss://"],
    },
    'Elasticsearch': {
        'error_signatures': [
            r"Elasticsearch.*error",
            r"index_not_found_exception",
            r"search_phase_execution_exception",
        ],
        'file_extensions': [],
        'config_files': ['elasticsearch.yml'],
        'default_ports': [9200, 9300],
        'connection_strings': [r"elasticsearch://"],
    },
    'Firebase': {
        'error_signatures': [
            r"Firebase.*error",
            r"Permission denied",
            r"FirebaseException",
        ],
        'file_extensions': [],
        'config_files': ['google-services.json', 'GoogleService-Info.plist'],
        'default_ports': [],
        'connection_strings': [r"firebase://", r"firestore://"],
    },
    'DynamoDB': {
        'error_signatures': [
            r"DynamoDB.*error",
            r"ResourceNotFoundException",
            r"ConditionalCheckFailedException",
        ],
        'file_extensions': [],
        'config_files': [],
        'default_ports': [],
        'connection_strings': [r"dynamodb://"],
    },
    'Cassandra': {
        'error_signatures': [
            r"Cassandra.*error",
            r"InvalidQueryException",
        ],
        'file_extensions': [],
        'config_files': ['cassandra.yaml'],
        'default_ports': [9042],
        'connection_strings': [r"cassandra://"],
    },
    'Neo4j': {
        'error_signatures': [
            r"Neo\.DatabaseError",
            r"Neo\.ClientError",
        ],
        'file_extensions': ['.db', '.store'],
        'config_files': ['neo4j.conf'],
        'default_ports': [7474, 7687],
        'connection_strings': [r"neo4j://", r"bolt://"],
    },
    'CouchDB': {
        'error_signatures': [
            r"CouchDB.*error",
            r"bad_request",
            r"not_found",
        ],
        'file_extensions': [],
        'config_files': ['local.ini', 'default.ini'],
        'default_ports': [5984],
        'connection_strings': [r"couchdb://"],
    },
    'MariaDB': {
        'error_signatures': [
            r"MariaDB.*error",
        ],
        'file_extensions': ['.sql', '.frm', '.ibd'],
        'config_files': ['my.cnf'],
        'default_ports': [3306],
        'connection_strings': [r"mariadb://"],
    },
}

# ═══════════════════════════════════════════════════════════════════════════════
# PAYLOADS DE TEST POUR DÉTECTION D'INJECTION SQL
# ═══════════════════════════════════════════════════════════════════════════════
SQLI_PAYLOADS = [
    "'",
    "''",
    "' OR '1'='1",
    "' OR '1'='1' --",
    "' OR '1'='1' /*",
    "' OR 1=1",
    "' OR 1=1 --",
    "' OR 1=1 #",
    "1' ORDER BY 1--",
    "1' ORDER BY 2--",
    "1' UNION SELECT NULL--",
    "1' UNION SELECT NULL,NULL--",
    "1 AND 1=1",
    "1 AND 1=2",
    "1' AND '1'='1",
    "1' AND '1'='2",
    "' UNION SELECT @@version--",
    "' UNION SELECT database()--",
    "'; DROP TABLE users; --",
    "1' WAITFOR DELAY '0:0:5'--",
    "1' AND SLEEP(5)--",
    "1' AND pg_sleep(5)--",
]

# ═══════════════════════════════════════════════════════════════════════════════
# ENDPOINTS API COURANTS À TESTER
# ═══════════════════════════════════════════════════════════════════════════════
API_ENDPOINTS = [
    '/api/',
    '/api/v1/',
    '/api/v2/',
    '/api/users',
    '/api/login',
    '/api/register',
    '/api/auth',
    '/api/data',
    '/api/db',
    '/api/database',
    '/api/query',
    '/api/search',
    '/api/admin',
    '/api/config',
    '/api/status',
    '/api/health',
    '/api/docs',
    '/api/swagger',
    '/api/openapi',
    '/api/graphql',
    '/graphql',
    '/rest/',
    '/rest/v1/',
    '/wp-json/',
    '/wp-json/wp/v2/',
    '/json/',
    '/xml/',
    '/soap/',
    '/rpc/',
    '/ajax/',
    '/ajax.php',
    '/data.php',
    '/query.php',
    '/search.php',
    '/api.php',
    '/db.php',
    '/config.php',
    '/connect.php',
    '/database.php',
    '/mysqli.php',
    '/pdo.php',
    '/db_connect.php',
    '/connection.php',
    '/includes/db.php',
    '/includes/database.php',
    '/includes/config.php',
    '/inc/db.php',
    '/inc/database.php',
    '/lib/db.php',
    '/libs/db.php',
    '/classes/db.php',
    '/models/db.php',
    '/config/database.php',
    '/config/db.php',
    '/.env',
    '/.env.local',
    '/.env.production',
    '/.env.development',
    '/config.json',
    '/config.xml',
    '/config.yaml',
    '/config.yml',
    '/settings.json',
    '/settings.php',
    '/database.yml',
    '/database.json',
    '/db.json',
    '/secrets.json',
    '/credentials.json',
    '/backup.sql',
    '/dump.sql',
    '/database.sql',
    '/db.sql',
    '/backup/',
    '/backups/',
    '/db/',
    '/database/',
    '/sql/',
    '/phpmyadmin/',
    '/pma/',
    '/adminer/',
    '/adminer.php',
    '/mysql/',
    '/mysql-admin/',
    '/pgadmin/',
    '/mongo-express/',
    '/redis/',
    '/elasticsearch/',
    '/kibana/',
    '/_db/',
    '/_api/',
    '/internal/',
    '/private/',
    '/debug/',
    '/test/',
    '/dev/',
    '/staging/',
    '/phpinfo.php',
    '/info.php',
    '/server-status',
    '/server-info',
    '/.git/config',
    '/.svn/entries',
    '/.hg/',
    '/Dockerfile',
    '/docker-compose.yml',
    '/docker-compose.yaml',
    '/package.json',
    '/composer.json',
    '/composer.lock',
    '/Gemfile',
    '/Gemfile.lock',
    '/requirements.txt',
    '/Pipfile',
    '/yarn.lock',
    '/package-lock.json',
    '/webpack.config.js',
    '/tsconfig.json',
    '/.htaccess',
    '/web.config',
    '/robots.txt',
    '/sitemap.xml',
    '/crossdomain.xml',
    '/clientaccesspolicy.xml',
    '/.well-known/',
    '/.well-known/security.txt',
]

# ═══════════════════════════════════════════════════════════════════════════════
# HEADERS DE SÉCURITÉ À VÉRIFIER
# ═══════════════════════════════════════════════════════════════════════════════
SECURITY_HEADERS = {
    'X-Frame-Options': 'Protection contre le clickjacking',
    'X-Content-Type-Options': 'Protection contre le MIME sniffing',
    'X-XSS-Protection': 'Protection XSS',
    'Content-Security-Policy': 'Politique de sécurité du contenu',
    'Strict-Transport-Security': 'HSTS - HTTPS forcé',
    'Referrer-Policy': 'Contrôle du referrer',
    'Permissions-Policy': 'Permissions du navigateur',
    'X-Permitted-Cross-Domain-Policies': 'Politique cross-domain',
}

# ═══════════════════════════════════════════════════════════════════════════════
# CLASSE PRINCIPALE HIDBASE
# ═══════════════════════════════════════════════════════════════════════════════
class HIDBASE:
    def __init__(self, target_url, depth=2, timeout=10):
        self.target = target_url.rstrip('/')
        self.parsed = urlparse(self.target)
        self.domain = self.parsed.netloc
        self.base_url = f"{self.parsed.scheme}://{self.domain}"
        self.depth = depth
        self.timeout = timeout
        
        self.pages = set()
        self.resources = []
        self.external_links = set()
        self.forms = []
        self.inputs = []
        self.scripts = []
        self.stylesheets = []
        self.apis = []
        self.endpoints_found = []
        self.error_pages = []
        self.headers_info = {}
        self.cookies_info = []
        self.meta_tags = {}
        self.technologies = []
        self.database_hints = {}
        self.sql_injection_tests = []
        self.config_files = []
        self.backup_files = []
        self.git_exposed = False
        self.env_exposed = False
        self.admin_panels = []
        self.user_details = {}
        
        self.session = None
    
    # ─────────────────────────────────────────────────────────────────────────
    # REQUÊTE HTTP
    # ─────────────────────────────────────────────────────────────────────────
    def fetch(self, url, method='GET', data=None, headers=None):
        """Effectue une requête HTTP et retourne la réponse."""
        default_headers = {
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.0',
            'Accept': 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8',
            'Accept-Language': 'en-US,en;q=0.5',
            'Accept-Encoding': 'identity',
            'Connection': 'keep-alive',
        }
        if headers:
            default_headers.update(headers)
        
        try:
            req = urllib.request.Request(url, method=method, headers=default_headers)
            if data:
                req.data = urllib.parse.urlencode(data).encode('utf-8')
            
            response = urllib.request.urlopen(req, timeout=self.timeout, context=ctx)
            
            return {
                'status': response.getcode(),
                'headers': dict(response.headers),
                'body': response.read().decode('utf-8', errors='replace'),
                'url': response.geturl(),
                'length': len(response.read()) if False else 0,
            }
        except urllib.error.HTTPError as e:
            return {
                'status': e.code,
                'headers': dict(e.headers) if e.headers else {},
                'body': e.read().decode('utf-8', errors='replace') if e.fp else '',
                'url': url,
                'error': str(e),
            }
        except Exception as e:
            return {'status': 0, 'headers': {}, 'body': '', 'url': url, 'error': str(e)}
    
    # ─────────────────────────────────────────────────────────────────────────
    # ANALYSE PRINCIPALE
    # ─────────────────────────────────────────────────────────────────────────
    def analyze(self):
        """Lance l'analyse complète du site."""
        print(f"\n{c(bd('═' * 79))}")
        print(f"{c(bd('  HIDBASE - DATABASE DISCOVERY & ANALYSIS'))}")
        print(f"{c(bd('  Target: '))}{y(self.target)}")
        print(f"{c(bd('  Domain: '))}{y(self.domain)}")
        print(f"{c(bd('═' * 79))}\n")
        
        # Étape 1: Page principale
        progress_full("Analyse de la page principale", 2.0)
        self._analyze_main_page()
        
        # Étape 2: Crawl des pages
        progress_full("Crawl des pages internes", 3.0)
        self._crawl_pages()
        
        # Étape 3: Analyse des ressources
        progress_full("Analyse des ressources", 2.0)
        self._analyze_resources()
        
        # Étape 4: Détection des technologies
        progress_full("Détection des technologies", 2.0)
        self._detect_technologies()
        
        # Étape 5: Détection des bases de données
        progress_full("Détection des bases de données", 3.0)
        self._detect_databases()
        
        # Étape 6: Test des endpoints API
        progress_full("Test des endpoints API", 3.0)
        self._test_api_endpoints()
        
        # Étape 7: Test d'injection SQL
        progress_full("Test d'injection SQL", 4.0)
        self._test_sql_injection()
        
        # Étape 8: Recherche de fichiers sensibles
        progress_full("Recherche de fichiers sensibles", 3.0)
        self._find_sensitive_files()
        
        # Étape 9: Analyse des headers de sécurité
        progress_full("Analyse des headers de sécurité", 1.5)
        self._analyze_security_headers()
        
        # Étape 10: Analyse des formulaires
        progress_full("Analyse des formulaires", 2.0)
        self._analyze_forms_deep()
        
        return True
    
    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_main_page(self):
        """Analyse la page principale."""
        resp = self.fetch(self.target)
        self.main_response = resp
        
        if resp['status'] == 200:
            ok(f"Page principale accessible - Status {resp['status']}")
            self.pages.add(self.target)
            
            # Extraire les liens
            self._extract_links(resp['body'], self.target)
            
            # Extraire les formulaires
            self._extract_forms(resp['body'])
            
            # Extraire les scripts
            self._extract_scripts(resp['body'])
            
            # Extraire les CSS
            self._extract_stylesheets(resp['body'])
            
            # Extraire les meta tags
            self._extract_meta_tags(resp['body'])
            
            # Analyser les headers
            self._analyze_headers(resp['headers'])
            
            # Analyser les cookies
            self._analyze_cookies(resp['headers'])
        else:
            ko(f"Page principale - Status {resp['status']}")
    
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_links(self, html, base_url):
        """Extrait tous les liens du HTML."""
        # Liens href
        href_pattern = re.compile(r'href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in href_pattern.finditer(html):
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if self.domain in full_url:
                self.pages.add(full_url)
            else:
                self.external_links.add(full_url)
        
        # Liens src
        src_pattern = re.compile(r'src=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in src_pattern.finditer(html):
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if self.domain in full_url:
                self.resources.append({'url': full_url, 'type': 'resource'})
        
        # Liens action
        action_pattern = re.compile(r'action=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in action_pattern.finditer(html):
            url = match.group(1)
            full_url = urljoin(base_url, url)
            if self.domain in full_url:
                self.pages.add(full_url)
        
        # URLs dans le JavaScript
        url_pattern = re.compile(r'["\']((?:/[^"\']*)|(?:https?://[^"\']+))["\']')
        for match in url_pattern.finditer(html):
            url = match.group(1)
            if url.startswith('/'):
                full_url = self.base_url + url
                if any(ext in url for ext in ['.php', '.asp', '.aspx', '.jsp', '.json', '.xml', '.api']):
                    self.apis.append(full_url)
    
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_forms(self, html):
        """Extrait les formulaires du HTML."""
        form_pattern = re.compile(r'<form[^>]*>(.*?)</form>', re.DOTALL | re.IGNORECASE)
        input_pattern = re.compile(r'<input[^>]*>', re.IGNORECASE)
        
        for form_match in form_pattern.finditer(html):
            form_html = form_match.group(0)
            
            # Action du formulaire
            action_match = re.search(r'action=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            action = action_match.group(1) if action_match else ''
            
            # Méthode
            method_match = re.search(r'method=["\']([^"\']*)["\']', form_html, re.IGNORECASE)
            method = method_match.group(1).upper() if method_match else 'GET'
            
            # Inputs
            inputs = []
            for input_match in input_pattern.finditer(form_html):
                input_html = input_match.group(0)
                
                name_match = re.search(r'name=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                type_match = re.search(r'type=["\']([^"\']*)["\']', input_html, re.IGNORECASE)
                
                if name_match:
                    inputs.append({
                        'name': name_match.group(1),
                        'type': type_match.group(1) if type_match else 'text',
                    })
            
            self.forms.append({
                'action': action,
                'method': method,
                'inputs': inputs,
            })
    
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_scripts(self, html):
        """Extrait les scripts du HTML."""
        script_pattern = re.compile(r'<script[^>]*src=["\']([^"\']+)["\'][^>]*>', re.IGNORECASE)
        for match in script_pattern.finditer(html):
            self.scripts.append(match.group(1))
        
        # Scripts inline
        inline_pattern = re.compile(r'<script[^>]*>(.*?)</script>', re.DOTALL | re.IGNORECASE)
        for match in inline_pattern.finditer(html):
            script_content = match.group(1)
            # Chercher des références à des BDD
            for db_name, sigs in DATABASE_SIGNATURES.items():
                for conn_str in sigs['connection_strings']:
                    if re.search(conn_str, script_content, re.IGNORECASE):
                        if db_name not in self.database_hints:
                            self.database_hints[db_name] = []
                        self.database_hints[db_name].append('Référence dans script inline')
    
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_stylesheets(self, html):
        """Extrait les feuilles de style."""
        css_pattern = re.compile(r'<link[^>]*rel=["\']stylesheet["\'][^>]*href=["\']([^"\']+)["\']', re.IGNORECASE)
        for match in css_pattern.finditer(html):
            self.stylesheets.append(match.group(1))
    
    # ─────────────────────────────────────────────────────────────────────────
    def _extract_meta_tags(self, html):
        """Extrait les meta tags."""
        meta_pattern = re.compile(r'<meta[^>]*>', re.IGNORECASE)
        for match in meta_pattern.finditer(html):
            meta_html = match.group(0)
            
            name_match = re.search(r'name=["\']([^"\']*)["\']', meta_html, re.IGNORECASE)
            content_match = re.search(r'content=["\']([^"\']*)["\']', meta_html, re.IGNORECASE)
            
            if name_match and content_match:
                self.meta_tags[name_match.group(1)] = content_match.group(1)
    
    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_headers(self, headers):
        """Analyse les headers HTTP."""
        self.headers_info = {
            'server': headers.get('Server', 'Non détecté'),
            'powered_by': headers.get('X-Powered-By', 'Non détecté'),
            'content_type': headers.get('Content-Type', 'Non détecté'),
            'all_headers': headers,
        }
    
    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_cookies(self, headers):
        """Analyse les cookies."""
        set_cookie = headers.get('Set-Cookie', '')
        if set_cookie:
            cookies = set_cookie.split(',')
            for cookie in cookies:
                self.cookies_info.append({
                    'raw': cookie.strip(),
                    'secure': 'secure' in cookie.lower(),
                    'httponly': 'httponly' in cookie.lower(),
                    'samesite': 'samesite' in cookie.lower(),
                })
    
    # ─────────────────────────────────────────────────────────────────────────
    def _crawl_pages(self):
        """Crawl les pages internes."""
        to_visit = list(self.pages)[:20]  # Limiter à 20 pages
        visited = set()
        
        for i, page in enumerate(to_visit):
            if page in visited:
                continue
            visited.add(page)
            
            progress_bar("Crawl en cours", i + 1, len(to_visit))
            
            resp = self.fetch(page)
            if resp['status'] == 200:
                self._extract_links(resp['body'], page)
        
        print()
        ok(f"{len(visited)} pages crawlées")
    
    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_resources(self):
        """Analyse les ressources trouvées."""
        resource_types = {}
        for res in self.resources:
            ext = os.path.splitext(urlparse(res['url']).path)[1].lower()
            if ext:
                resource_types[ext] = resource_types.get(ext, 0) + 1
        
        info(f"Ressources trouvées: {len(self.resources)}")
        for ext, count in sorted(resource_types.items()):
            detail(f"  {ext}", str(count))
    
    # ─────────────────────────────────────────────────────────────────────────
    def _detect_technologies(self):
        """Détecte les technologies utilisées."""
        techs = []
        
        # Serveur
        server = self.headers_info.get('server', '')
        if 'apache' in server.lower():
            techs.append('Apache')
        elif 'nginx' in server.lower():
            techs.append('Nginx')
        elif 'iis' in server.lower():
            techs.append('IIS')
        elif 'lighttpd' in server.lower():
            techs.append('Lighttpd')
        
        # X-Powered-By
        powered = self.headers_info.get('powered_by', '')
        if 'php' in powered.lower():
            techs.append('PHP')
        elif 'asp.net' in powered.lower():
            techs.append('ASP.NET')
        elif 'python' in powered.lower():
            techs.append('Python')
        elif 'node' in powered.lower():
            techs.append('Node.js')
        
        # Frameworks depuis les meta tags
        generator = self.meta_tags.get('generator', '')
        if 'wordpress' in generator.lower():
            techs.append('WordPress')
        elif 'drupal' in generator.lower():
            techs.append('Drupal')
        elif 'joomla' in generator.lower():
            techs.append('Joomla')
        
        # Depuis les scripts
        for script in self.scripts:
            if 'jquery' in script.lower():
                techs.append('jQuery')
            elif 'react' in script.lower():
                techs.append('React')
            elif 'vue' in script.lower():
                techs.append('Vue.js')
            elif 'angular' in script.lower():
                techs.append('Angular')
        
        self.technologies = list(set(techs))
        ok(f"Technologies détectées: {', '.join(self.technologies) if self.technologies else 'Aucune'}")
    
    # ─────────────────────────────────────────────────────────────────────────
    def _detect_databases(self):
        """Détecte les bases de données potentielles."""
        detected = {}
        
        # 1. Vérifier les erreurs dans les pages
        for page in list(self.pages)[:5]:
            resp = self.fetch(page + "'")  # Test d'erreur
            body = resp.get('body', '')
            
            for db_name, sigs in DATABASE_SIGNATURES.items():
                for sig in sigs['error_signatures']:
                    if re.search(sig, body, re.IGNORECASE):
                        if db_name not in detected:
                            detected[db_name] = {'confidence': 0, 'reasons': []}
                        detected[db_name]['confidence'] += 30
                        detected[db_name]['reasons'].append(f"Erreur détectée sur {page}")
        
        # 2. Vérifier les extensions de fichiers
        for res in self.resources:
            url = res['url']
            for db_name, sigs in DATABASE_SIGNATURES.items():
                for ext in sigs['file_extensions']:
                    if ext in url.lower():
                        if db_name not in detected:
                            detected[db_name] = {'confidence': 0, 'reasons': []}
                        detected[db_name]['confidence'] += 20
                        detected[db_name]['reasons'].append(f"Extension {ext} trouvée")
        
        # 3. Vérifier les technologies
        for tech in self.technologies:
            tech_db_map = {
                'WordPress': 'MySQL',
                'Drupal': 'MySQL',
                'Joomla': 'MySQL',
                'PHP': 'MySQL',
                'Python': ['MySQL', 'PostgreSQL', 'SQLite', 'MongoDB'],
                'Node.js': ['MongoDB', 'MySQL', 'PostgreSQL'],
                'ASP.NET': 'Microsoft SQL Server',
            }
            if tech in tech_db_map:
                dbs = tech_db_map[tech]
                if isinstance(dbs, str):
                    dbs = [dbs]
                for db in dbs:
                    if db not in detected:
                        detected[db] = {'confidence': 0, 'reasons': []}
                    detected[db]['confidence'] += 15
                    detected[db]['reasons'].append(f"Technologie {tech} détectée")
        
        # 4. Vérifier les meta tags et headers
        for db_name, sigs in DATABASE_SIGNATURES.items():
            for conn_str in sigs['connection_strings']:
                # Chercher dans le contenu des pages
                for page in list(self.pages)[:3]:
                    resp = self.fetch(page)
                    body = resp.get('body', '')
                    if re.search(conn_str, body, re.IGNORECASE):
                        if db_name not in detected:
                            detected[db_name] = {'confidence': 0, 'reasons': []}
                        detected[db_name]['confidence'] += 25
                        detected[db_name]['reasons'].append("Chaîne de connexion trouvée dans le code")
        
        self.database_hints = detected
        
        if detected:
            ok(f"{len(detected)} base(s) de données potentielle(s) détectée(s)")
            for db, info in sorted(detected.items(), key=lambda x: x[1]['confidence'], reverse=True):
                confidence = min(info['confidence'], 100)
                color = g if confidence >= 70 else y if confidence >= 40 else r
                detail(f"  {db}", f"{color(f'{confidence}%')} confiance")
        else:
            warn("Aucune base de données détectée avec certitude")
    
    # ─────────────────────────────────────────────────────────────────────────
    def _test_api_endpoints(self):
        """Teste les endpoints API courants."""
        found = []
        
        for i, endpoint in enumerate(API_ENDPOINTS):
            progress_bar("Test endpoints API", i + 1, len(API_ENDPOINTS))
            
            url = self.base_url + endpoint
            resp = self.fetch(url)
            
            if resp['status'] in [200, 401, 403, 405]:
                found.append({
                    'url': url,
                    'status': resp['status'],
                    'size': len(resp.get('body', '')),
                })
        
        print()
        self.endpoints_found = found
        ok(f"{len(found)} endpoints API/accessibles trouvés")
        
        for ep in found[:10]:
            status_color = g if ep['status'] == 200 else y if ep['status'] == 401 else r
            detail(f"  [{status_color(str(ep['status']))}]", ep['url'])
    
    # ─────────────────────────────────────────────────────────────────────────
    def _test_sql_injection(self):
        """Teste les points d'injection SQL."""
        results = []
        
        # Tester sur les formulaires
        test_urls = []
        for form in self.forms:
            if form['action']:
                action_url = urljoin(self.target, form['action'])
                test_urls.append((action_url, form['method'], form['inputs']))
        
        # Tester sur les paramètres URL
        for page in list(self.pages)[:5]:
            if '?' in page:
                test_urls.append((page, 'GET', []))
        
        for i, (url, method, inputs) in enumerate(test_urls[:10]):
            progress_bar("Test injection SQL", i + 1, min(len(test_urls), 10))
            
            for payload in SQLI_PAYLOADS[:5]:  # Limiter les payloads
                try:
                    if method == 'POST' and inputs:
                        data = {inp['name']: payload for inp in inputs if inp['name']}
                        resp = self.fetch(url, method='POST', data=data)
                    else:
                        separator = '&' if '?' in url else '?'
                        test_url = f"{url}{separator}test={urllib.parse.quote(payload)}"
                        resp = self.fetch(test_url)
                    
                    body = resp.get('body', '')
                    
                    # Vérifier les erreurs SQL
                    for db_name, sigs in DATABASE_SIGNATURES.items():
                        for sig in sigs['error_signatures']:
                            if re.search(sig, body, re.IGNORECASE):
                                results.append({
                                    'url': url,
                                    'payload': payload,
                                    'database': db_name,
                                    'status': resp['status'],
                                })
                                break
                except:
                    pass
        
        print()
        self.sql_injection_tests = results
        
        if results:
            ko(f"{len(results)} potentielles vulnérabilités SQL injection trouvées!")
            for vuln in results[:5]:
                detail(f"  [{r('SQLi')}]", f"{vuln['url']} -> {vuln['database']}")
        else:
            ok("Aucune vulnérabilité SQL injection détectée")
    
    # ─────────────────────────────────────────────────────────────────────────
    def _find_sensitive_files(self):
        """Recherche des fichiers sensibles."""
        sensitive_paths = [
            '/.env', '/.env.local', '/.env.production',
            '/config.php', '/database.php', '/db.php',
            '/wp-config.php', '/configuration.php',
            '/config.json', '/config.xml',
            '/backup.sql', '/dump.sql', '/database.sql',
            '/.git/config', '/.svn/entries',
            '/phpinfo.php', '/info.php',
            '/admin/', '/administrator/', '/wp-admin/',
            '/phpmyadmin/', '/pma/', '/adminer.php',
        ]
        
        found = []
        for i, path in enumerate(sensitive_paths):
            progress_bar("Recherche fichiers sensibles", i + 1, len(sensitive_paths))
            
            url = self.base_url + path
            resp = self.fetch(url)
            
            if resp['status'] == 200:
                found.append({'url': url, 'type': 'accessible', 'size': len(resp.get('body', ''))})
                if '.git' in path:
                    self.git_exposed = True
                if '.env' in path:
                    self.env_exposed = True
            elif resp['status'] in [301, 302, 403]:
                found.append({'url': url, 'type': 'protected', 'status': resp['status']})
        
        print()
        self.config_files = found
        ok(f"{len(found)} fichiers/répertoires sensibles trouvés")
        
        for f in found[:10]:
            if f['type'] == 'accessible':
                detail(f"  [{g('EXPOSE')}]", f['url'])
            else:
                detail(f"  [{y('PROTÉGÉ')}]", f['url'])
    
    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_security_headers(self):
        """Analyse les headers de sécurité."""
        headers = self.main_response.get('headers', {})
        missing = []
        present = []
        
        for header, description in SECURITY_HEADERS.items():
            if header in headers:
                present.append({'header': header, 'value': headers[header], 'desc': description})
            else:
                missing.append({'header': header, 'desc': description})
        
        if present:
            ok(f"{len(present)} headers de sécurité présents")
            for h in present:
                detail(f"  {h['header']}", h['value'])
        
        if missing:
            warn(f"{len(missing)} headers de sécurité manquants")
            for h in missing:
                detail(f"  {r('MANQUANT')}", f"{h['header']} - {h['desc']}")
    
    # ─────────────────────────────────────────────────────────────────────────
    def _analyze_forms_deep(self):
        """Analyse approfondie des formulaires."""
        if not self.forms:
            warn("Aucun formulaire trouvé")
            return
        
        ok(f"{len(self.forms)} formulaire(s) trouvé(s)")
        
        for i, form in enumerate(self.forms, 1):
            print(f"\n  {c(f'Formulaire #{i}')}")
            detail("    Action", form['action'] or 'Self')
            detail("    Méthode", form['method'])
            detail("    Inputs", str(len(form['inputs'])))
            
            for inp in form['inputs']:
                sensitive = inp['name'].lower() in ['password', 'pass', 'pwd', 'email', 'user', 'username', 'login', 'credit_card', 'cc', 'ssn']
                color = r if sensitive else y
                detail(f"      - {color(inp['name'])}", f"Type: {inp['type']}")
    
    # ═════════════════════════════════════════════════════════════════════════
    # GÉNÉRATION DU RAPPORT
    # ═════════════════════════════════════════════════════════════════════════
    def generate_report(self, output_dir="reports"):
        """Génère le rapport complet."""
        progress_full("Génération du rapport", 2.0)
        
        os.makedirs(output_dir, exist_ok=True)
        timestamp = time.strftime("%Y%m%d_%H%M%S")
        report_file = os.path.join(output_dir, f"HIDBASE_{self.domain}_{timestamp}.html")
        
        html = self._build_html_report()
        
        with open(report_file, 'w', encoding='utf-8') as f:
            f.write(html)
        
        ok(f"Rapport généré: {report_file}")
        return report_file
    
    def _build_html_report(self):
        """Construit le rapport HTML."""
        db_section = ""
        for db, info in sorted(self.database_hints.items(), key=lambda x: x[1]['confidence'], reverse=True):
            confidence = min(info['confidence'], 100)
            color_class = 'high' if confidence >= 70 else 'medium' if confidence >= 40 else 'low'
            reasons = '<br>'.join(info['reasons'][:3])
            db_section += f"""
            <div class="db-item {color_class}">
                <h3>{db} <span class="confidence">{confidence}% confiance</span></h3>
                <p class="reasons">{reasons}</p>
            </div>"""
        
        sqli_section = ""
        for vuln in self.sql_injection_tests[:10]:
            sqli_section += f"""
            <tr>
                <td>{vuln['url']}</td>
                <td><code>{vuln['payload']}</code></td>
                <td>{vuln['database']}</td>
                <td>{vuln['status']}</td>
            </tr>"""
        
        endpoint_section = ""
        for ep in self.endpoints_found[:20]:
            status_class = 'ok' if ep['status'] == 200 else 'warn' if ep['status'] == 401 else 'error'
            endpoint_section += f"""
            <tr class="{status_class}">
                <td>{ep['url']}</td>
                <td>{ep['status']}</td>
                <td>{ep['size']} bytes</td>
            </tr>"""
        
        sensitive_section = ""
        for f in self.config_files[:15]:
            ftype = f.get('type', 'unknown')
            status_class = 'exposed' if ftype == 'accessible' else 'protected'
            sensitive_section += f"""
            <tr class="{status_class}">
                <td>{f['url']}</td>
                <td>{ftype.upper()}</td>
                <td>{f.get('status', '200') if ftype == 'protected' else f.get('size', 'N/A')}</td>
            </tr>"""
        
        return f"""<!DOCTYPE html>
<html lang="fr">
<head>
    <meta charset="UTF-8">
    <title>HIDBASE Report - {self.domain}</title>
    <style>
        * {{ margin: 0; padding: 0; box-sizing: border-box; }}
        body {{ font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0a0a0a; color: #e0e0e0; line-height: 1.6; }}
        .container {{ max-width: 1200px; margin: 0 auto; padding: 20px; }}
        header {{ text-align: center; padding: 40px 20px; background: linear-gradient(135deg, #1a1a2e 0%, #16213e 100%); border-radius: 10px; margin-bottom: 30px; }}
        header h1 {{ font-size: 3em; color: #00ff88; text-shadow: 0 0 20px rgba(0,255,136,0.3); }}
        header .subtitle {{ color: #888; margin-top: 10px; }}
        header .author {{ color: #ffaa00; margin-top: 5px; font-size: 0.9em; }}
        .section {{ background: #1a1a2e; border-radius: 10px; padding: 25px; margin-bottom: 20px; border: 1px solid #2a2a4e; }}
        .section h2 {{ color: #00ff88; border-bottom: 2px solid #00ff88; padding-bottom: 10px; margin-bottom: 20px; }}
        .stats-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px; margin-bottom: 20px; }}
        .stat-card {{ background: #16213e; padding: 20px; border-radius: 8px; text-align: center; border: 1px solid #2a2a4e; }}
        .stat-card .number {{ font-size: 2em; color: #00ff88; font-weight: bold; }}
        .stat-card .label {{ color: #888; margin-top: 5px; }}
        .db-item {{ background: #16213e; padding: 15px; border-radius: 8px; margin-bottom: 10px; border-left: 4px solid; }}
        .db-item.high {{ border-left-color: #ff4444; }}
        .db-item.medium {{ border-left-color: #ffaa00; }}
        .db-item.low {{ border-left-color: #00ff88; }}
        .db-item h3 {{ color: #fff; }}
        .db-item .confidence {{ float: right; color: #ffaa00; font-size: 0.9em; }}
        .db-item .reasons {{ color: #888; margin-top: 10px; font-size: 0.9em; }}
        table {{ width: 100%; border-collapse: collapse; margin-top: 15px; }}
        th, td {{ padding: 12px; text-align: left; border-bottom: 1px solid #2a2a4e; }}
        th {{ background: #16213e; color: #00ff88; font-weight: 600; }}
        tr:hover {{ background: #1a1a3e; }}
        tr.ok td {{ color: #00ff88; }}
        tr.warn td {{ color: #ffaa00; }}
        tr.error td {{ color: #ff4444; }}
        tr.exposed td {{ color: #ff4444; font-weight: bold; }}
        tr.protected td {{ color: #ffaa00; }}
        code {{ background: #0a0a1a; padding: 2px 6px; border-radius: 3px; font-family: monospace; color: #ffaa00; }}
        .alert {{ padding: 15px; border-radius: 8px; margin: 10px 0; }}
        .alert-danger {{ background: rgba(255,68,68,0.1); border: 1px solid #ff4444; color: #ff4444; }}
        .alert-warning {{ background: rgba(255,170,0,0.1); border: 1px solid #ffaa00; color: #ffaa00; }}
        .alert-success {{ background: rgba(0,255,136,0.1); border: 1px solid #00ff88; color: #00ff88; }}
        .tech-list {{ display: flex; flex-wrap: wrap; gap: 10px; }}
        .tech-tag {{ background: #16213e; padding: 8px 15px; border-radius: 20px; border: 1px solid #00ff88; color: #00ff88; }}
        footer {{ text-align: center; padding: 30px; color: #555; margin-top: 30px; border-top: 1px solid #2a2a4e; }}
        footer .hiddenworld {{ color: #ffaa00; font-weight: bold; }}
    </style>
</head>
<body>
    <div class="container">
        <header>
            <h1>🔍 HIDBASE</h1>
            <p class="subtitle">Database Discovery & Analysis Report</p>
            <p class="author">Développé par HiddenWorld - Informaticien Tchadien 🇹🇩</p>
            <p style="color:#666;margin-top:10px;">Cible: <strong>{self.target}</strong> | Date: {time.strftime('%Y-%m-%d %H:%M:%S')}</p>
        </header>
        
        <div class="section">
            <h2>📊 Statistiques Générales</h2>
            <div class="stats-grid">
                <div class="stat-card"><div class="number">{len(self.pages)}</div><div class="label">Pages Découvertes</div></div>
                <div class="stat-card"><div class="number">{len(self.resources)}</div><div class="label">Ressources</div></div>
                <div class="stat-card"><div class="number">{len(self.forms)}</div><div class="label">Formulaires</div></div>
                <div class="stat-card"><div class="number">{len(self.endpoints_found)}</div><div class="label">Endpoints API</div></div>
                <div class="stat-card"><div class="number">{len(self.database_hints)}</div><div class="label">BDD Potentielles</div></div>
                <div class="stat-card"><div class="number">{len(self.sql_injection_tests)}</div><div class="label">Vulnérabilités SQLi</div></div>
            </div>
        </div>
        
        <div class="section">
            <h2>🗄️ Bases de Données Détectées</h2>
            {db_section if db_section else '<p class="alert alert-warning">Aucune base de données détectée avec certitude.</p>'}
        </div>
        
        <div class="section">
            <h2>⚠️ Vulnérabilités SQL Injection</h2>
            {f'<table><tr><th>URL</th><th>Payload</th><th>Base de Données</th><th>Status</th></tr>{sqli_section}</table>' if sqli_section else '<p class="alert alert-success">Aucune vulnérabilité SQL injection détectée.</p>'}
        </div>
        
        <div class="section">
            <h2>🔌 Endpoints API Découverts</h2>
            {f'<table><tr><th>URL</th><th>Status</th><th>Taille</th></tr>{endpoint_section}</table>' if endpoint_section else '<p>Aucun endpoint trouvé.</p>'}
        </div>
        
        <div class="section">
            <h2>🔐 Fichiers Sensibles</h2>
            {f'<table><tr><th>URL</th><th>Type</th><th>Info</th></tr>{sensitive_section}</table>' if sensitive_section else '<p>Aucun fichier sensible trouvé.</p>'}
            {f'<div class="alert alert-danger">⚠️ .git exposé! Le code source peut être téléchargé.</div>' if self.git_exposed else ''}
            {f'<div class="alert alert-danger">⚠️ .env exposé! Les credentials peuvent être compromis.</div>' if self.env_exposed else ''}
        </div>
        
        <div class="section">
            <h2>💻 Technologies Détectées</h2>
            <div class="tech-list">
                {''.join(f'<span class="tech-tag">{t}</span>' for t in self.technologies) if self.technologies else '<p>Aucune technologie détectée.</p>'}
            </div>
        </div>
        
        <div class="section">
            <h2>📝 Formulaires</h2>
            {f'<p>{len(self.forms)} formulaire(s) trouvé(s)</p>' if self.forms else '<p>Aucun formulaire trouvé.</p>'}
        </div>
        
        <div class="section">
            <h2>🔗 Liens Externes</h2>
            <p>{len(self.external_links)} liens externes découverts</p>
        </div>
        
        <footer>
            <p>Généré par <span class="hiddenworld">HIDBASE v1.0.0</span></p>
            <p>Développé par HiddenWorld - Informaticien Tchadien 🇹🇩</p>
            <p style="margin-top:10px;color:#333;">© 2024 HiddenWorld. Tous droits réservés.</p>
        </footer>
    </div>
</body>
</html>"""


# ═══════════════════════════════════════════════════════════════════════════════
# FONCTION PRINCIPALE
# ═══════════════════════════════════════════════════════════════════════════════
def main():
    parser = argparse.ArgumentParser(description='HIDBASE - Database Discovery & Analysis Tool')
    parser.add_argument('url', nargs='?', help='URL du site web à analyser')
    parser.add_argument('-d', '--depth', type=int, default=2, help='Profondeur de crawl (1-5)')
    parser.add_argument('-o', '--output', default='reports', help='Dossier de sortie')
    parser.add_argument('-t', '--timeout', type=int, default=10, help='Timeout des requêtes (secondes)')
    
    args = parser.parse_args()
    
    # Bannière
    print(f"""
{c(bd('╔═══════════════════════════════════════════════════════════════════════════════╗'))}
{c(bd('║'))}                                                                               {c(bd('║'))}
{c(bd('║'))}   {g(bd('██╗  ██╗██╗██████╗ ██████╗  █████╗ ███████╗███████╗'))}                        {c(bd('║'))}
{c(bd('║'))}   {g(bd('██║  ██║██║██╔══██╗██╔══██╗██╔══██╗██╔════╝██╔════╝'))}                        {c(bd('║'))}
{c(bd('║'))}   {g(bd('███████║██║██║  ██║██████╔╝███████║███████╗█████╗  '))}                        {c(bd('║'))}
{c(bd('║'))}   {g(bd('██╔══██║██║██║  ██║██╔══██╗██╔══██║╚════██║██╔══╝  '))}                        {c(bd('║'))}
{c(bd('║'))}   {g(bd('██║  ██║██║██████╔╝██████╔╝██║  ██║███████║███████╗'))}                        {c(bd('║'))}
{c(bd('║'))}   {g(bd('╚═╝  ╚═╝╚═╝╚═════╝ ╚═════╝ ╚═╝  ╚═╝╚══════╝╚══════╝'))}                        {c(bd('║'))}
{c(bd('║'))}                                                                               {c(bd('║'))}
{c(bd('║'))}   {y('Database Discovery & Analysis Tool')}                                          {c(bd('║'))}
{c(bd('║'))}   {b('Version: 1.0.0')}                                                              {c(bd('║'))}
{c(bd('║'))}   {m('Developed by: HiddenWorld - Informaticien Tchadien 🇹🇩')}                       {c(bd('║'))}
{c(bd('║'))}                                                                               {c(bd('║'))}
{c(bd('╚═══════════════════════════════════════════════════════════════════════════════╝'))}
""")
    
    # Demander l'URL
    if not args.url:
        args.url = input(f"\n{y('Entrez l\'URL du site web: ')}{C.END}").strip()
    
    if not args.url:
        err("Aucune URL fournie. Arrêt.")
        sys.exit(1)
    
    # Normaliser l'URL
    if not args.url.startswith(('http://', 'https://')):
        args.url = 'https://' + args.url
    
    info(f"Cible: {bd(args.url)}")
    info(f"Profondeur: {args.depth}")
    info(f"Timeout: {args.timeout}s")
    
    # Lancer l'analyse
    hidbase = HIDBASE(args.url, depth=args.depth, timeout=args.timeout)
    
    try:
        hidbase.analyze()
        report_file = hidbase.generate_report(args.output)
        
        print(f"\n{c(bd('═' * 79))}")
        print(f"{c(bd('  ANALYSE TERMINÉE AVEC SUCCÈS'))}")
        print(f"{c(bd('═' * 79))}\n")
        
        detail("Site analysé", hidbase.target)
        detail("Pages découvertes", str(len(hidbase.pages)))
        detail("Bases de données potentielles", str(len(hidbase.database_hints)))
        detail("Vulnérabilités SQLi", str(len(hidbase.sql_injection_tests)))
        detail("Endpoints API", str(len(hidbase.endpoints_found)))
        detail("Fichiers sensibles", str(len(hidbase.config_files)))
        detail("Rapport généré", report_file)
        
        print(f"\n{g('Merci d\'utiliser HIDBASE - HiddenWorld 🇹🇩')}\n")
        
    except KeyboardInterrupt:
        print(f"\n\n{y('Analyse interrompue par l\'utilisateur.')}")
        sys.exit(0)
    except Exception as e:
        err(f"Erreur: {str(e)}")
        sys.exit(1)


if __name__ == "__main__":
    main()
