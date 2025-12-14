#!/usr/bin/env python3
"""
OSINT-NG - Framework profesional de Inteligencia de Fuentes Abiertas
Autor: Rodrigo Lopez
Versión: 3.0.0
Licencia: MIT
"""

import argparse
import asyncio
import csv
import hashlib
import json
import logging
import os
import re
import sqlite3
import sys
import time
import urllib.parse
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Tuple
from enum import Enum
import configparser
import pickle
import platform

# Importaciones de terceros
try:
    import aiohttp
    import colorama
    import dns.resolver
    import requests
    import whois
    from bs4 import BeautifulSoup
    from rich.console import Console
    from rich.table import Table
    from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
    from rich.panel import Panel
    from rich.layout import Layout
    from rich.live import Live
    from rich.tree import Tree
    from rich.syntax import Syntax
    from rich import box
    from rich.text import Text
except ImportError as e:
    print(f"Error: Falta instalar dependencias. Ejecuta: pip install -r requirements.txt")
    print(f"Dependencia faltante: {e}")
    sys.exit(1)

# Inicializar colorama para Windows
colorama.init()

# Configuración de logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('osint-ng.log'),
        logging.StreamHandler()
    ]
)
logger = logging.getLogger(__name__)


# ============================================================================
# CONFIGURACIÓN Y CONSTANTES
# ============================================================================

class Config:
    """Clase de configuración del framework"""

    def __init__(self):
        self.home_dir = os.path.expanduser("~")
        self.config_dir = os.path.join(self.home_dir, ".config", "osint-ng")
        self.data_dir = os.path.join(self.home_dir, ".local", "share", "osint-ng")
        self.cache_dir = os.path.join(self.data_dir, "cache")
        self.plugins_dir = os.path.join(self.data_dir, "plugins")

        # Crear directorios si no existen
        for directory in [self.config_dir, self.data_dir, self.cache_dir, self.plugins_dir]:
            os.makedirs(directory, exist_ok=True)

        self.config_file = os.path.join(self.config_dir, "config.ini")
        self.database_file = os.path.join(self.data_dir, "osint.db")
        self.api_keys_file = os.path.join(self.config_dir, "api_keys.json")

        # Configuración por defecto
        self.default_config = {
            'general': {
                'language': 'es',
                'theme': 'dark',
                'max_threads': '10',
                'timeout': '30',
                'user_agent': 'OSINT-NG/3.0.0'
            },
            'modules': {
                'whois_enabled': 'true',
                'dns_enabled': 'true',
                'subdomain_enabled': 'true',
                'email_enabled': 'true',
                'social_enabled': 'true'
            },
            'api': {
                'virustotal_key': '',
                'shodan_key': '',
                'hunterio_key': '',
                'haveibeenpwned_key': ''
            }
        }

        self.config = configparser.ConfigParser()
        self._load_config()

    def _load_config(self):
        """Cargar configuración desde archivo"""
        if os.path.exists(self.config_file):
            self.config.read(self.config_file)
        else:
            self.config.read_dict(self.default_config)
            self._save_config()

    def _save_config(self):
        """Guardar configuración en archivo"""
        with open(self.config_file, 'w') as f:
            self.config.write(f)

    def get(self, section: str, key: str, default: Any = None) -> Any:
        """Obtener valor de configuración"""
        try:
            return self.config.get(section, key)
        except (configparser.NoSectionError, configparser.NoOptionError):
            return default

    def set(self, section: str, key: str, value: Any):
        """Establecer valor de configuración"""
        if not self.config.has_section(section):
            self.config.add_section(section)
        self.config.set(section, key, str(value))
        self._save_config()


# Instancia global de configuración
CONFIG = Config()


# ============================================================================
# UTILIDADES
# ============================================================================

class ConsoleManager:
    """Gestor de la consola con Rich"""

    def __init__(self):
        self.console = Console()
        self.live = None
        self.progress = None

    def print_banner(self):
        """Mostrar banner del programa"""
        from rich.panel import Panel
        from rich.text import Text
        
        self.console.clear()

        banner = """
╔══════════════════════════════════════════════════════════════════════════════╗
║  ██████╗ ███████╗██╗███╗   ██╗████████╗    ███╗   ██╗ ██████╗                ║
║ ██╔═══██╗██╔════╝██║████╗  ██║╚══██╔══╝    ████╗  ██║██╔════╝                ║
║ ██║   ██║███████╗██║██╔██╗ ██║   ██║       ██╔██╗ ██║██║  ███╗               ║
║ ██║   ██║╚════██║██║██║╚██╗██║   ██║       ██║╚██╗██║██║   ██║               ║
║ ╚██████╔╝███████║██║██║ ╚████║   ██║       ██║ ╚████║╚██████╔╝               ║
║  ╚═════╝ ╚══════╝╚═╝╚═╝  ╚═══╝   ╚═╝       ╚═╝  ╚═══╝ ╚═════╝                ║
║                                                                              ║
║                     Framework de Inteligencia de Fuentes                     ║
║                               Versión 3.0.0                                  ║
╚══════════════════════════════════════════════════════════════════════════════╝
        """
        
        # Crear un texto con estilo rojo
        text = Text(banner, style="red")
        
        # Mostrar el banner con un borde rojo
        self.console.print(Panel(
            text,
            border_style="red",
            padding=(1, 2),
            expand=False
        ))
        self.console.print(f"[dim]Directorio de datos: {CONFIG.data_dir}[/]")
        self.console.print(f"[dim]Directorio de configuración: {CONFIG.config_dir}[/]\n")

    def print_success(self, message: str):
        """Mostrar mensaje de éxito"""
        self.console.print(f"[green]✓[/] [bold]{message}[/]")

    def print_error(self, message: str):
        """Mostrar mensaje de error"""
        self.console.print(f"[red]✗[/] [bold]{message}[/]")

    def print_warning(self, message: str):
        """Mostrar mensaje de advertencia"""
        self.console.print(f"[yellow]⚠[/] [bold]{message}[/]")

    def print_info(self, message: str):
        """Mostrar mensaje informativo"""
        self.console.print(f"[blue]ℹ[/] [bold]{message}[/]")

    def print_table(self, title: str, data: List[Dict], columns: List[str]):
        """Mostrar tabla de datos"""
        table = Table(title=title, box=box.ROUNDED)

        for column in columns:
            table.add_column(column, style="cyan")

        for row in data:
            table.add_row(*[str(row.get(col, "")) for col in columns])

        self.console.print(table)

    def start_progress(self, description: str = "Procesando..."):
        """Iniciar barra de progreso"""
        self.progress = Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            console=self.console
        )
        self.live = Live(self.progress, console=self.console, refresh_per_second=10)
        self.live.__enter__()
        self.task_id = self.progress.add_task(description, total=100)
        return self.task_id

    def update_progress(self, task_id: int, advance: int = 1):
        """Actualizar progreso"""
        if self.progress:
            self.progress.update(task_id, advance=advance)

    def stop_progress(self):
        """Detener barra de progreso"""
        if self.live:
            self.live.__exit__(None, None, None)
            self.live = None
            self.progress = None


# Instancia global de consola
console = ConsoleManager()


# ============================================================================
# BASE DE DATOS
# ============================================================================

class Database:
    """Gestor de base de datos SQLite"""

    def __init__(self):
        self.db_path = CONFIG.database_file
        self.conn = None
        self.cursor = None
        self._connect()
        self._create_tables()

    def _connect(self):
        """Conectar a la base de datos"""
        try:
            self.conn = sqlite3.connect(self.db_path, timeout=30)
            self.conn.row_factory = sqlite3.Row
            self.cursor = self.conn.cursor()
            # Optimizaciones
            self.cursor.execute("PRAGMA journal_mode=WAL")
            self.cursor.execute("PRAGMA synchronous=NORMAL")
            self.cursor.execute("PRAGMA cache_size=10000")
            self.cursor.execute("PRAGMA foreign_keys=ON")
        except sqlite3.Error as e:
            console.print_error(f"Error conectando a la base de datos: {e}")
            sys.exit(1)

    def _create_tables(self):
        """Crear tablas si no existen"""
        tables = [
            # Dominios
            """
            CREATE TABLE IF NOT EXISTS domains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain TEXT UNIQUE NOT NULL,
                registrar TEXT,
                creation_date TEXT,
                expiration_date TEXT,
                updated_date TEXT,
                name_servers TEXT,
                status TEXT,
                emails TEXT,
                organization TEXT,
                address TEXT,
                city TEXT,
                state TEXT,
                country TEXT,
                phone TEXT,
                fax TEXT,
                raw_data TEXT,
                last_scanned TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,

            # Subdominios
            """
            CREATE TABLE IF NOT EXISTS subdomains (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                domain_id INTEGER NOT NULL,
                subdomain TEXT NOT NULL,
                ip_address TEXT,
                cname TEXT,
                status_code INTEGER,
                title TEXT,
                server TEXT,
                technology TEXT,
                ports TEXT,
                discovered_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (domain_id) REFERENCES domains(id) ON DELETE CASCADE,
                UNIQUE(domain_id, subdomain)
            )
            """,

            # Emails
            """
            CREATE TABLE IF NOT EXISTS emails (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                domain TEXT,
                first_name TEXT,
                last_name TEXT,
                position TEXT,
                department TEXT,
                linkedin TEXT,
                twitter TEXT,
                phone TEXT,
                source TEXT,
                verified BOOLEAN DEFAULT FALSE,
                disposable BOOLEAN DEFAULT FALSE,
                breach_count INTEGER DEFAULT 0,
                last_verified TIMESTAMP,
                discovered_date TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,

            # Personas
            """
            CREATE TABLE IF NOT EXISTS persons (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                full_name TEXT,
                username TEXT UNIQUE,
                email_id INTEGER,
                phone TEXT,
                company TEXT,
                position TEXT,
                location TEXT,
                linkedin TEXT,
                twitter TEXT,
                github TEXT,
                facebook TEXT,
                instagram TEXT,
                other_social TEXT,
                notes TEXT,
                confidence INTEGER DEFAULT 0,
                last_updated TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                FOREIGN KEY (email_id) REFERENCES emails(id) ON DELETE SET NULL
            )
            """,

            # Resultados de escaneo
            """
            CREATE TABLE IF NOT EXISTS scan_results (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                module TEXT NOT NULL,
                target TEXT NOT NULL,
                data TEXT NOT NULL,
                success BOOLEAN DEFAULT TRUE,
                error_message TEXT,
                execution_time REAL,
                timestamp TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
            """,

            # API Cache
            """
            CREATE TABLE IF NOT EXISTS api_cache (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                api_name TEXT NOT NULL,
                query TEXT NOT NULL,
                response TEXT NOT NULL,
                expires_at TIMESTAMP,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                UNIQUE(api_name, query)
            )
            """
        ]

        indices = [
            "CREATE INDEX IF NOT EXISTS idx_domains_domain ON domains(domain)",
            "CREATE INDEX IF NOT EXISTS idx_subdomains_domain ON subdomains(domain_id)",
            "CREATE INDEX IF NOT EXISTS idx_emails_domain ON emails(domain)",
            "CREATE INDEX IF NOT EXISTS idx_emails_email ON emails(email)",
            "CREATE INDEX IF NOT EXISTS idx_persons_username ON persons(username)",
            "CREATE INDEX IF NOT EXISTS idx_scan_results_target ON scan_results(target)",
            "CREATE INDEX IF NOT EXISTS idx_scan_results_module ON scan_results(module)",
            "CREATE INDEX IF NOT EXISTS idx_api_cache_query ON api_cache(query)"
        ]

        try:
            with self.conn:
                # Crear tablas
                for table_sql in tables:
                    self.cursor.execute(table_sql)

                # Crear índices
                for index_sql in indices:
                    self.cursor.execute(index_sql)

                # Crear tabla de estadísticas si no existe
                self.cursor.execute("""
                    CREATE TABLE IF NOT EXISTS stats (
                        id INTEGER PRIMARY KEY AUTOINCREMENT,
                        stat_name TEXT UNIQUE NOT NULL,
                        stat_value INTEGER DEFAULT 0,
                        updated_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
                    )
                """)

        except sqlite3.Error as e:
            console.print_error(f"Error creando tablas: {e}")
            sys.exit(1)

    def execute(self, query: str, params: tuple = None, fetch_all: bool = True):
        """Ejecutar consulta SQL"""
        try:
            with self.conn:
                if params:
                    self.cursor.execute(query, params)
                else:
                    self.cursor.execute(query)

                if query.strip().upper().startswith("SELECT"):
                    if fetch_all:
                        return self.cursor.fetchall()
                    else:
                        return self.cursor.fetchone()

                return self.cursor.rowcount
        except sqlite3.Error as e:
            console.print_error(f"Error en consulta SQL: {e}")
            return None

    def insert_domain(self, domain_data: Dict) -> int:
        """Insertar o actualizar dominio"""
        query = """
        INSERT OR REPLACE INTO domains (
            domain, registrar, creation_date, expiration_date, updated_date,
            name_servers, status, emails, organization, address, city, state,
            country, phone, fax, raw_data
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """

        params = (
            domain_data.get('domain'),
            domain_data.get('registrar'),
            domain_data.get('creation_date'),
            domain_data.get('expiration_date'),
            domain_data.get('updated_date'),
            json.dumps(domain_data.get('name_servers', [])),
            json.dumps(domain_data.get('status', [])),
            json.dumps(domain_data.get('emails', [])),
            domain_data.get('organization'),
            domain_data.get('address'),
            domain_data.get('city'),
            domain_data.get('state'),
            domain_data.get('country'),
            domain_data.get('phone'),
            domain_data.get('fax'),
            domain_data.get('raw_data', '')
        )

        result = self.execute(query, params, fetch_all=False)
        if result:
            return self.cursor.lastrowid
        return None

    def close(self):
        """Cerrar conexión a la base de datos"""
        if self.conn:
            self.conn.close()


# ============================================================================
# MÓDULOS BASE
# ============================================================================

class OSINTModule(ABC):
    """Clase base para todos los módulos OSINT"""

    def __init__(self, name: str, description: str, version: str = "1.0.0"):
        self.name = name
        self.description = description
        self.version = version
        self.db = Database()
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': CONFIG.get('general', 'user_agent'),
            'Accept': 'application/json',
            'Accept-Language': 'en-US,en;q=0.9'
        })
        self.timeout = int(CONFIG.get('general', 'timeout', 30))

    @abstractmethod
    def run(self, target: str) -> Dict:
        """Método principal que debe implementar cada módulo"""
        pass

    def validate_target(self, target: str) -> bool:
        """Validar el objetivo"""
        return bool(target and len(target.strip()) > 0)

    def save_result(self, target: str, data: Dict, success: bool = True, error: str = None):
        """Guardar resultado en la base de datos"""
        query = """
        INSERT INTO scan_results (module, target, data, success, error_message, execution_time)
        VALUES (?, ?, ?, ?, ?, ?)
        """

        params = (
            self.name,
            target,
            json.dumps(data),
            success,
            error,
            getattr(self, 'execution_time', 0)
        )

        self.db.execute(query, params)

    def get_cached_data(self, api_name: str, query: str) -> Optional[Dict]:
        """Obtener datos cacheados"""
        result = self.db.execute(
            "SELECT response FROM api_cache WHERE api_name = ? AND query = ? AND (expires_at IS NULL OR expires_at > datetime('now'))",
            (api_name, query),
            fetch_all=False
        )

        if result:
            return json.loads(result['response'])
        return None

    def cache_data(self, api_name: str, query: str, data: Dict, ttl_hours: int = 24):
        """Almacenar datos en caché"""
        expires_at = datetime.now() + timedelta(hours=ttl_hours) if ttl_hours > 0 else None

        self.db.execute(
            """
            INSERT OR REPLACE INTO api_cache (api_name, query, response, expires_at)
            VALUES (?, ?, ?, ?)
            """,
            (api_name, query, json.dumps(data), expires_at)
        )


# ============================================================================
# MÓDULOS IMPLEMENTADOS
# ============================================================================

class WhoisModule(OSINTModule):
    """Módulo para consultas WHOIS"""

    def __init__(self):
        super().__init__("whois", "Consulta información WHOIS de dominios", "2.0.0")

    def run(self, domain: str) -> Dict:
        """Ejecutar consulta WHOIS"""
        start_time = time.time()

        if not self.validate_target(domain):
            return {"error": "Dominio inválido"}

        console.print_info(f"Consultando WHOIS para: {domain}")

        try:
            # Consultar WHOIS
            w = whois.whois(domain)

            # Procesar datos
            domain_data = {
                'domain': domain,
                'registrar': w.registrar,
                'creation_date': str(w.creation_date) if w.creation_date else None,
                'expiration_date': str(w.expiration_date) if w.expiration_date else None,
                'updated_date': str(w.updated_date) if w.updated_date else None,
                'name_servers': list(w.name_servers) if w.name_servers else [],
                'status': list(w.status) if w.status else [],
                'emails': list(w.emails) if w.emails else [],
                'organization': w.org if hasattr(w, 'org') else w.organization,
                'address': w.address,
                'city': w.city,
                'state': w.state,
                'country': w.country,
                'phone': w.phone,
                'fax': w.fax,
                'raw_data': str(w.text) if w.text else '',
                'dnssec': w.dnssec if hasattr(w, 'dnssec') else None
            }

            # Guardar en base de datos
            domain_id = self.db.insert_domain(domain_data)

            self.execution_time = time.time() - start_time
            self.save_result(domain, domain_data)

            console.print_success(f"WHOIS completado para {domain}")

            return {
                'success': True,
                'data': domain_data,
                'execution_time': self.execution_time,
                'domain_id': domain_id
            }

        except Exception as e:
            error_msg = f"Error en consulta WHOIS: {e}"
            console.print_error(error_msg)
            self.save_result(domain, {}, success=False, error=error_msg)
            return {'success': False, 'error': error_msg}


class DNSModule(OSINTModule):
    """Módulo para consultas DNS"""

    def __init__(self):
        super().__init__("dns", "Consulta registros DNS", "2.0.0")
        self.resolver = dns.resolver.Resolver()
        self.resolver.timeout = self.timeout
        self.resolver.lifetime = self.timeout

    def run(self, domain: str) -> Dict:
        """Ejecutar consultas DNS"""
        start_time = time.time()

        if not self.validate_target(domain):
            return {"error": "Dominio inválido"}

        console.print_info(f"Consultando DNS para: {domain}")

        results = {}

        try:
            # Consultar diferentes tipos de registros DNS
            record_types = ['A', 'AAAA', 'MX', 'NS', 'TXT', 'SOA', 'CNAME', 'SRV']

            for record_type in record_types:
                try:
                    answers = self.resolver.resolve(domain, record_type)
                    results[record_type] = [str(rdata) for rdata in answers]
                except (dns.resolver.NoAnswer, dns.resolver.NXDOMAIN, dns.exception.Timeout):
                    results[record_type] = []
                except Exception as e:
                    console.print_warning(f"Error consultando {record_type} para {domain}: {e}")
                    results[record_type] = []

            # Consulta especial para SPF, DMARC, DKIM
            try:
                txt_records = self.resolver.resolve(domain, 'TXT')
                for record in txt_records:
                    txt_data = str(record)
                    if 'v=spf1' in txt_data:
                        results['SPF'] = txt_data
                    if 'v=DMARC1' in txt_data:
                        results['DMARC'] = txt_data
            except:
                pass

            self.execution_time = time.time() - start_time

            # Guardar resultados
            dns_data = {
                'domain': domain,
                'records': results,
                'timestamp': datetime.now().isoformat()
            }

            self.save_result(domain, dns_data)
            console.print_success(f"Consulta DNS completada para {domain}")

            return {
                'success': True,
                'data': dns_data,
                'execution_time': self.execution_time
            }

        except Exception as e:
            error_msg = f"Error en consulta DNS: {e}"
            console.print_error(error_msg)
            self.save_result(domain, {}, success=False, error=error_msg)
            return {'success': False, 'error': error_msg}


class SubdomainModule(OSINTModule):
    """Módulo para enumeración de subdominios"""

    def __init__(self):
        super().__init__("subdomains", "Enumeración de subdominios", "2.0.0")
        self.wordlist_path = os.path.join(CONFIG.data_dir, "wordlists", "subdomains.txt")
        self._load_wordlist()

    def _load_wordlist(self):
        """Cargar lista de subdominios comunes"""
        default_wordlist = [
            'www', 'mail', 'ftp', 'webmail', 'smtp', 'pop', 'pop3', 'imap',
            'blog', 'news', 'dev', 'test', 'staging', 'api', 'secure',
            'admin', 'portal', 'cdn', 'support', 'shop', 'store', 'forum',
            'wiki', 'docs', 'help', 'status', 'monitor', 'stats', 'analytics',
            'app', 'apps', 'mobile', 'm', 'web', 'static', 'media', 'img',
            'images', 'assets', 'cdn', 'cloud', 'server', 'ns1', 'ns2',
            'dns', 'db', 'database', 'backup', 'backups', 'beta', 'alpha'
        ]

        os.makedirs(os.path.dirname(self.wordlist_path), exist_ok=True)

        if not os.path.exists(self.wordlist_path):
            with open(self.wordlist_path, 'w') as f:
                f.write('\n'.join(default_wordlist))

        with open(self.wordlist_path, 'r') as f:
            self.wordlist = [line.strip() for line in f if line.strip()]

    def run(self, domain: str) -> Dict:
        """Enumerar subdominios"""
        start_time = time.time()

        if not self.validate_target(domain):
            return {"error": "Dominio inválido"}

        console.print_info(f"Buscando subdominios para: {domain}")

        subdomains_found = []
        progress_task = None

        try:
            # Obtener ID del dominio principal
            domain_result = self.db.execute(
                "SELECT id FROM domains WHERE domain = ?",
                (domain,),
                fetch_all=False
            )

            domain_id = domain_result['id'] if domain_result else None

            # Usar wordlist
            progress_task = console.start_progress(f"Escaneando {len(self.wordlist)} subdominios...")

            for i, sub in enumerate(self.wordlist):
                subdomain = f"{sub}.{domain}"

                try:
                    # Intentar resolver
                    answers = dns.resolver.resolve(subdomain, 'A')
                    ips = [str(rdata) for rdata in answers]

                    if ips:
                        # Intentar HTTP
                        try:
                            response = self.session.get(f"http://{subdomain}", timeout=5)
                            status_code = response.status_code
                            soup = BeautifulSoup(response.text, 'html.parser')
                            title = soup.title.string if soup.title else "Sin título"
                            server = response.headers.get('Server', 'Desconocido')
                        except:
                            status_code = None
                            title = None
                            server = None

                        subdomain_data = {
                            'subdomain': subdomain,
                            'ip_address': ips[0] if ips else None,
                            'status_code': status_code,
                            'title': title,
                            'server': server,
                            'discovered_date': datetime.now().isoformat()
                        }

                        # Guardar en base de datos
                        if domain_id:
                            self.db.execute(
                                """
                                INSERT OR IGNORE INTO subdomains 
                                (domain_id, subdomain, ip_address, status_code, title, server)
                                VALUES (?, ?, ?, ?, ?, ?)
                                """,
                                (domain_id, subdomain, ips[0], status_code, title, server)
                            )

                        subdomains_found.append(subdomain_data)
                        console.print_info(f"Encontrado: {subdomain} -> {ips[0]}")

                except (dns.resolver.NXDOMAIN, dns.resolver.NoAnswer):
                    # Subdominio no existe
                    pass
                except Exception as e:
                    # Otro error
                    console.print_warning(f"Error en {subdomain}: {e}")

                # Actualizar progreso
                if progress_task:
                    console.update_progress(progress_task, advance=100 / len(self.wordlist))

            # También consultar API de VirusTotal si hay clave
            vt_key = CONFIG.get('api', 'virustotal_key')
            if vt_key:
                vt_subdomains = self._query_virustotal(domain, vt_key)
                subdomains_found.extend(vt_subdomains)

            self.execution_time = time.time() - start_time

            if progress_task:
                console.stop_progress()

            result_data = {
                'domain': domain,
                'subdomains_found': len(subdomains_found),
                'subdomains': subdomains_found,
                'wordlist_size': len(self.wordlist)
            }

            self.save_result(domain, result_data)
            console.print_success(f"Encontrados {len(subdomains_found)} subdominios para {domain}")

            return {
                'success': True,
                'data': result_data,
                'execution_time': self.execution_time
            }

        except Exception as e:
            if progress_task:
                console.stop_progress()

            error_msg = f"Error en enumeración de subdominios: {e}"
            console.print_error(error_msg)
            self.save_result(domain, {}, success=False, error=error_msg)
            return {'success': False, 'error': error_msg}

    def _query_virustotal(self, domain: str, api_key: str) -> List[Dict]:
        """Consultar VirusTotal para subdominios"""
        try:
            headers = {'x-apikey': api_key}
            url = f"https://www.virustotal.com/api/v3/domains/{domain}/subdomains"

            response = self.session.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                subdomains = []

                for item in data.get('data', []):
                    subdomain = item.get('id')
                    if subdomain:
                        subdomains.append({
                            'subdomain': subdomain,
                            'source': 'VirusTotal',
                            'last_analysis_stats': item.get('attributes', {}).get('last_analysis_stats', {})
                        })

                return subdomains

        except Exception as e:
            console.print_warning(f"Error consultando VirusTotal: {e}")

        return []


class EmailModule(OSINTModule):
    """Módulo para análisis de correos electrónicos"""

    def __init__(self):
        super().__init__("email", "Análisis de correos electrónicos", "2.0.0")

    def run(self, email: str) -> Dict:
        """Analizar correo electrónico"""
        start_time = time.time()

        if not self._validate_email(email):
            return {"error": "Email inválido"}

        console.print_info(f"Analizando email: {email}")

        analysis_results = {
            'email': email,
            'valid_format': True,
            'domain': email.split('@')[1],
            'checks': {}
        }

        try:
            # 1. Verificar formato
            analysis_results['checks']['format'] = self._check_email_format(email)

            # 2. Verificar dominio
            analysis_results['checks']['domain'] = self._check_domain(email.split('@')[1])

            # 3. Verificar si es desechable
            analysis_results['checks']['disposable'] = self._check_disposable(email)

            # 4. Consultar Have I Been Pwned si hay clave
            hibp_key = CONFIG.get('api', 'haveibeenpwned_key')
            if hibp_key:
                analysis_results['checks']['breaches'] = self._check_hibp(email, hibp_key)

            # 5. Consultar Hunter.io si hay clave
            hunter_key = CONFIG.get('api', 'hunterio_key')
            if hunter_key:
                analysis_results['checks']['hunter'] = self._check_hunter(email, hunter_key)

            # 6. Buscar en redes sociales
            analysis_results['checks']['social'] = self._search_social(email)

            # Guardar en base de datos
            self._save_email_to_db(email, analysis_results)

            self.execution_time = time.time() - start_time
            self.save_result(email, analysis_results)

            console.print_success(f"Análisis completado para {email}")

            return {
                'success': True,
                'data': analysis_results,
                'execution_time': self.execution_time
            }

        except Exception as e:
            error_msg = f"Error analizando email: {e}"
            console.print_error(error_msg)
            self.save_result(email, {}, success=False, error=error_msg)
            return {'success': False, 'error': error_msg}

    def _validate_email(self, email: str) -> bool:
        """Validar formato de email"""
        pattern = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
        return re.match(pattern, email) is not None

    def _check_email_format(self, email: str) -> Dict:
        """Verificar formato del email"""
        username, domain = email.split('@')

        return {
            'username_length': len(username),
            'username_has_numbers': any(c.isdigit() for c in username),
            'username_has_special': any(c in '._%+-' for c in username),
            'domain_tld': domain.split('.')[-1]
        }

    def _check_domain(self, domain: str) -> Dict:
        """Verificar dominio del email"""
        try:
            # Intentar resolver MX records
            mx_records = dns.resolver.resolve(domain, 'MX')
            mx_servers = [str(rdata.exchange) for rdata in mx_records]

            return {
                'has_mx': True,
                'mx_servers': mx_servers,
                'mx_count': len(mx_servers)
            }
        except:
            return {'has_mx': False, 'mx_servers': []}

    def _check_disposable(self, email: str) -> Dict:
        """Verificar si el email es desechable"""
        disposable_domains = [
            'tempmail.com', 'mailinator.com', 'guerrillamail.com',
            '10minutemail.com', 'throwawaymail.com', 'temp-mail.org'
        ]

        domain = email.split('@')[1]
        is_disposable = domain in disposable_domains

        return {
            'is_disposable': is_disposable,
            'domain': domain
        }

    def _check_hibp(self, email: str, api_key: str) -> Dict:
        """Consultar Have I Been Pwned"""
        try:
            headers = {'hibp-api-key': api_key}
            url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{urllib.parse.quote(email)}"

            response = self.session.get(url, headers=headers, timeout=self.timeout)

            if response.status_code == 200:
                breaches = response.json()
                return {
                    'breached': True,
                    'breach_count': len(breaches),
                    'breaches': breaches[:5]  # Primeros 5
                }
            elif response.status_code == 404:
                return {'breached': False, 'breach_count': 0}
            else:
                return {'error': f"HTTP {response.status_code}"}

        except Exception as e:
            return {'error': str(e)}

    def _check_hunter(self, email: str, api_key: str) -> Dict:
        """Consultar Hunter.io"""
        try:
            url = f"https://api.hunter.io/v2/email-verifier"
            params = {'email': email, 'api_key': api_key}

            response = self.session.get(url, params=params, timeout=self.timeout)

            if response.status_code == 200:
                data = response.json()
                result = data.get('data', {})

                return {
                    'valid': result.get('result') == 'deliverable',
                    'score': result.get('score'),
                    'sources': result.get('sources', []),
                    'first_name': result.get('first_name'),
                    'last_name': result.get('last_name')
                }

        except Exception as e:
            console.print_warning(f"Error consultando Hunter.io: {e}")

        return {}

    def _search_social(self, email: str) -> Dict:
        """Buscar email en redes sociales"""
        # Patrones comunes de búsqueda
        social_sites = {
            'linkedin': f"https://www.linkedin.com/search/results/all/?keywords={email}",
            'twitter': f"https://twitter.com/search?q={email}",
            'facebook': f"https://www.facebook.com/search/top/?q={email}"
        }

        results = {}

        for site, url in social_sites.items():
            try:
                response = self.session.get(url, timeout=10)
                if response.status_code == 200:
                    results[site] = {
                        'found': email in response.text,
                        'url': url
                    }
            except:
                results[site] = {'found': False, 'error': 'timeout'}

        return results

    def _save_email_to_db(self, email: str, analysis: Dict):
        """Guardar email en base de datos"""
        checks = analysis.get('checks', {})

        self.db.execute(
            """
            INSERT OR REPLACE INTO emails 
            (email, domain, first_name, last_name, verified, disposable, breach_count, source)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                email,
                analysis.get('domain'),
                checks.get('hunter', {}).get('first_name'),
                checks.get('hunter', {}).get('last_name'),
                checks.get('hunter', {}).get('valid', False),
                checks.get('disposable', {}).get('is_disposable', False),
                checks.get('breaches', {}).get('breach_count', 0),
                'osint-ng'
            )
        )


class SocialModule(OSINTModule):
    """Módulo para búsqueda en redes sociales"""

    def __init__(self):
        super().__init__("social", "Búsqueda en redes sociales", "2.0.0")

    def run(self, username: str) -> Dict:
        """Buscar usuario en redes sociales"""
        start_time = time.time()

        if not self.validate_target(username):
            return {"error": "Usuario inválido"}

        console.print_info(f"Buscando usuario: {username}")

        results = {
            'username': username,
            'platforms': {}
        }

        try:
            # Lista de plataformas a verificar
            platforms = {
                'GitHub': f'https://github.com/{username}',
                'Twitter': f'https://twitter.com/{username}',
                'Instagram': f'https://instagram.com/{username}',
                'Facebook': f'https://facebook.com/{username}',
                'LinkedIn': f'https://linkedin.com/in/{username}',
                'Reddit': f'https://reddit.com/user/{username}',
                'YouTube': f'https://youtube.com/@{username}',
                'Twitch': f'https://twitch.tv/{username}',
                'Pinterest': f'https://pinterest.com/{username}',
                'TikTok': f'https://tiktok.com/@{username}'
            }

            progress_task = console.start_progress(f"Verificando {len(platforms)} plataformas...")

            for i, (platform, url) in enumerate(platforms.items()):
                exists = self._check_profile_exists(url, username)
                results['platforms'][platform] = {
                    'url': url,
                    'exists': exists,
                    'profile_url': url if exists else None
                }

                if progress_task:
                    console.update_progress(progress_task, advance=100 / len(platforms))

            if progress_task:
                console.stop_progress()

            # Contar plataformas encontradas
            found_count = sum(1 for p in results['platforms'].values() if p['exists'])
            results['summary'] = {
                'total_checked': len(platforms),
                'found': found_count,
                'not_found': len(platforms) - found_count
            }

            # Guardar en base de datos si se encontraron perfiles
            if found_count > 0:
                self._save_to_database(username, results)

            self.execution_time = time.time() - start_time
            self.save_result(username, results)

            console.print_success(f"Encontrado en {found_count} plataformas")

            return {
                'success': True,
                'data': results,
                'execution_time': self.execution_time
            }

        except Exception as e:
            error_msg = f"Error en búsqueda social: {e}"
            console.print_error(error_msg)
            self.save_result(username, {}, success=False, error=error_msg)
            return {'success': False, 'error': error_msg}

    def _check_profile_exists(self, url: str, username: str) -> bool:
        """Verificar si un perfil existe"""
        try:
            response = self.session.get(url, timeout=10, allow_redirects=True)

            # Verificar códigos de estado
            if response.status_code == 200:
                # Verificar que no sea página genérica
                page_content = response.text.lower()

                # Patrones que indican que el perfil no existe
                not_found_patterns = [
                    'page not found',
                    'not found',
                    'does not exist',
                    'no existe',
                    '404',
                    'error',
                    f'user "{username}" not found'
                ]

                # Si encontramos algún patrón de "no encontrado", el perfil no existe
                for pattern in not_found_patterns:
                    if pattern in page_content:
                        return False

                # Si llegamos aquí, probablemente existe
                return True

            elif response.status_code == 404:
                return False

            # Para códigos 3xx (redirects), verificar si redirige a página de error
            elif 300 <= response.status_code < 400:
                final_url = response.url
                if 'error' in final_url.lower() or '404' in final_url:
                    return False
                return True

        except requests.exceptions.Timeout:
            console.print_warning(f"Timeout al verificar {url}")
        except Exception as e:
            console.print_warning(f"Error verificando {url}: {e}")

        return False

    def _save_to_database(self, username: str, results: Dict):
        """Guardar resultados en base de datos"""
        # Obtener email asociado si existe
        email_result = self.db.execute(
            "SELECT id FROM emails WHERE email LIKE ?",
            (f'%{username}%',),
            fetch_all=False
        )

        email_id = email_result['id'] if email_result else None

        # Preparar datos de redes sociales
        social_data = {}
        for platform, data in results['platforms'].items():
            if data['exists']:
                social_data[platform.lower()] = data['url']

        self.db.execute(
            """
            INSERT OR REPLACE INTO persons 
            (username, email_id, social_media)
            VALUES (?, ?, ?)
            """,
            (username, email_id, json.dumps(social_data))
        )


# ============================================================================
# GESTOR DE MÓDULOS
# ============================================================================

class ModuleManager:
    """Gestor de módulos OSINT"""

    def __init__(self):
        self.modules = {}
        self._load_modules()

    def _load_modules(self):
        """Cargar todos los módulos disponibles"""
        # Módulos integrados
        self.modules['whois'] = WhoisModule()
        self.modules['dns'] = DNSModule()
        self.modules['subdomains'] = SubdomainModule()
        self.modules['email'] = EmailModule()
        self.modules['social'] = SocialModule()

        # Cargar módulos personalizados desde plugins
        self._load_custom_modules()

    def _load_custom_modules(self):
        """Cargar módulos personalizados"""
        plugins_dir = CONFIG.plugins_dir

        if os.path.exists(plugins_dir):
            for filename in os.listdir(plugins_dir):
                if filename.endswith('.py') and filename != '__init__.py':
                    module_name = filename[:-3]
                    try:
                        # Aquí iría la lógica para cargar módulos dinámicos
                        # Por ahora solo es un placeholder
                        console.print_info(f"Módulo personalizado detectado: {module_name}")
                    except Exception as e:
                        console.print_warning(f"Error cargando módulo {module_name}: {e}")

    def list_modules(self) -> List[Dict]:
        """Listar todos los módulos disponibles"""
        module_list = []

        for name, module in self.modules.items():
            module_list.append({
                'name': name,
                'description': module.description,
                'version': module.version
            })

        return module_list

    def run_module(self, module_name: str, target: str) -> Dict:
        """Ejecutar un módulo específico"""
        if module_name not in self.modules:
            return {"error": f"Módulo '{module_name}' no encontrado"}

        module = self.modules[module_name]
        console.print_info(f"Ejecutando módulo: {module.name}")

        return module.run(target)

    def run_all(self, target: str, module_list: List[str] = None) -> Dict:
        """Ejecutar múltiples módulos"""
        results = {}

        modules_to_run = module_list if module_list else self.modules.keys()

        console.print_info(f"Ejecutando {len(modules_to_run)} módulos para: {target}")

        for module_name in modules_to_run:
            if module_name in self.modules:
                result = self.run_module(module_name, target)
                results[module_name] = result
            else:
                results[module_name] = {"error": "Módulo no encontrado"}

        return results


# ============================================================================
# INTERFAZ DE COMANDOS
# ============================================================================

class CommandHandler:
    """Manejador de comandos de línea de comandos"""

    def __init__(self):
        self.manager = ModuleManager()
        self.db = Database()

    def handle_domain(self, domain: str, options: argparse.Namespace):
        """Manejar comando de dominio"""
        console.print_banner()

        modules_to_run = []

        if options.whois or not any([options.whois, options.dns, options.subdomains]):
            modules_to_run.append('whois')

        if options.dns or not any([options.whois, options.dns, options.subdomains]):
            modules_to_run.append('dns')

        if options.subdomains:
            modules_to_run.append('subdomains')

        if not modules_to_run:
            modules_to_run = ['whois', 'dns']

        # Ejecutar módulos
        results = self.manager.run_all(domain, modules_to_run)

        # Mostrar resultados
        self._display_domain_results(domain, results)

        # Exportar si se especificó
        if options.output:
            self._export_results(results, options.output)

    def handle_email(self, email: str, options: argparse.Namespace):
        """Manejar comando de email"""
        console.print_banner()

        results = self.manager.run_module('email', email)

        if results.get('success'):
            self._display_email_results(email, results['data'])
        else:
            console.print_error(f"Error: {results.get('error', 'Desconocido')}")

        if options.output:
            self._export_results({'email': results}, options.output)

    def handle_social(self, username: str, options: argparse.Namespace):
        """Manejar comando de búsqueda social"""
        console.print_banner()

        results = self.manager.run_module('social', username)

        if results.get('success'):
            self._display_social_results(username, results['data'])
        else:
            console.print_error(f"Error: {results.get('error', 'Desconocido')}")

        if options.output:
            self._export_results({'social': results}, options.output)

    def handle_list(self):
        """Listar módulos disponibles"""
        console.print_banner()

        modules = self.manager.list_modules()

        table = Table(title="Módulos Disponibles", box=box.ROUNDED)
        table.add_column("Nombre", style="cyan")
        table.add_column("Descripción", style="green")
        table.add_column("Versión", style="yellow")

        for module in modules:
            table.add_row(module['name'], module['description'], module['version'])

        console.console.print(table)

    def handle_stats(self):
        """Mostrar estadísticas"""
        console.print_banner()

        stats = self._get_statistics()

        table = Table(title="Estadísticas OSINT-NG", box=box.ROUNDED)
        table.add_column("Métrica", style="cyan")
        table.add_column("Valor", style="green")

        for key, value in stats.items():
            table.add_row(key.replace('_', ' ').title(), str(value))

        console.console.print(table)

    def _display_domain_results(self, domain: str, results: Dict):
        """Mostrar resultados de análisis de dominio"""
        console.print_info(f"\nResultados para: [cyan]{domain}[/]")
        console.print_info("=" * 50)

        for module_name, result in results.items():
            if result.get('success'):
                data = result.get('data', {})

                if module_name == 'whois':
                    self._display_whois_results(data)
                elif module_name == 'dns':
                    self._display_dns_results(data)
                elif module_name == 'subdomains':
                    self._display_subdomain_results(data)
            else:
                console.print_error(f"{module_name}: {result.get('error')}")

    def _display_whois_results(self, data: Dict):
        """Mostrar resultados WHOIS"""
        console.print_success("\nInformación WHOIS:")

        info_table = Table(box=box.SIMPLE)
        info_table.add_column("Campo", style="cyan")
        info_table.add_column("Valor", style="white")

        fields = [
            ('Registrador', data.get('registrar')),
            ('Fecha creación', data.get('creation_date')),
            ('Fecha expiración', data.get('expiration_date')),
            ('Organización', data.get('organization')),
            ('País', data.get('country')),
            ('Servidores DNS', ', '.join(data.get('name_servers', []))[:50])
        ]

        for field, value in fields:
            if value:
                info_table.add_row(field, str(value))

        console.console.print(info_table)

    def _display_dns_results(self, data: Dict):
        """Mostrar resultados DNS"""
        console.print_success("\nRegistros DNS:")

        records = data.get('records', {})

        for record_type, values in records.items():
            if values:
                console.print_info(f"{record_type}:")
                for value in values:
                    console.console.print(f"  [dim]├─[/] {value}")

    def _display_subdomain_results(self, data: Dict):
        """Mostrar resultados de subdominios"""
        subdomains = data.get('subdomains', [])

        if subdomains:
            console.print_success(f"\nSubdominios encontrados ({len(subdomains)}):")

            table = Table(box=box.SIMPLE)
            table.add_column("Subdominio", style="cyan")
            table.add_column("IP", style="green")
            table.add_column("Estado", style="yellow")
            table.add_column("Título", style="white")

            for sub in subdomains[:10]:  # Mostrar solo primeros 10
                status = str(sub.get('status_code', 'N/A'))
                title = sub.get('title', 'N/A')[:30] + '...' if sub.get('title') and len(
                    sub.get('title')) > 30 else sub.get('title', 'N/A')
                table.add_row(
                    sub.get('subdomain', 'N/A'),
                    sub.get('ip_address', 'N/A'),
                    status,
                    title
                )

            console.console.print(table)

            if len(subdomains) > 10:
                console.print_info(f"... y {len(subdomains) - 10} más")
        else:
            console.print_warning("\nNo se encontraron subdominios")

    def _display_email_results(self, email: str, data: Dict):
        """Mostrar resultados de análisis de email"""
        console.print_success(f"\nAnálisis de: [cyan]{email}[/]")
        console.print_info("=" * 50)

        checks = data.get('checks', {})

        # Información básica
        info_table = Table(box=box.SIMPLE)
        info_table.add_column("Campo", style="cyan")
        info_table.add_column("Valor", style="white")

        info_table.add_row("Dominio", data.get('domain', 'N/A'))
        info_table.add_row("Formato válido", "Sí" if data.get('valid_format') else "No")

        # Verificación MX
        mx_info = checks.get('domain', {})
        if mx_info.get('has_mx'):
            info_table.add_row("Servidores MX", f"{mx_info.get('mx_count', 0)} servidores")
        else:
            info_table.add_row("Servidores MX", "[red]No encontrados[/]")

        # Email desechable
        disposable_info = checks.get('disposable', {})
        if disposable_info.get('is_disposable'):
            info_table.add_row("Tipo", "[yellow]Email desechable[/]")
        else:
            info_table.add_row("Tipo", "[green]Email regular[/]")

        # Breaches
        breach_info = checks.get('breaches', {})
        if breach_info.get('breached'):
            info_table.add_row("Filtraciones", f"[red]{breach_info.get('breach_count', 0)} encontradas[/]")
        else:
            info_table.add_row("Filtraciones", "[green]No encontradas[/]")

        console.console.print(info_table)

        # Información adicional de Hunter.io
        hunter_info = checks.get('hunter', {})
        if hunter_info:
            console.print_success("\nInformación adicional:")
            if hunter_info.get('first_name') or hunter_info.get('last_name'):
                console.print_info(f"Nombre: {hunter_info.get('first_name', '')} {hunter_info.get('last_name', '')}")
            if hunter_info.get('score'):
                console.print_info(f"Confianza: {hunter_info.get('score')}%")

    def _display_social_results(self, username: str, data: Dict):
        """Mostrar resultados de búsqueda social"""
        console.print_success(f"\nBúsqueda social para: [cyan]{username}[/]")
        console.print_info("=" * 50)

        platforms = data.get('platforms', {})
        summary = data.get('summary', {})

        table = Table(box=box.ROUNDED)
        table.add_column("Plataforma", style="cyan")
        table.add_column("Estado", style="green")
        table.add_column("URL", style="blue")

        for platform, info in platforms.items():
            if info['exists']:
                table.add_row(platform, "[green]✓ Encontrado[/]", info['url'])
            else:
                table.add_row(platform, "[dim]No encontrado[/]", "")

        console.console.print(table)

        console.print_info(f"\nResumen: {summary.get('found', 0)} de {summary.get('total_checked', 0)} plataformas")

    def _export_results(self, results: Dict, filename: str):
        """Exportar resultados a archivo"""
        try:
            if filename.endswith('.json'):
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                console.print_success(f"Resultados exportados a: {filename}")

            elif filename.endswith('.csv'):
                # Convertir resultados a formato CSV
                self._export_to_csv(results, filename)
                console.print_success(f"Resultados exportados a: {filename}")

            else:
                # Por defecto JSON
                filename = filename if filename.endswith('.json') else f"{filename}.json"
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump(results, f, indent=2, ensure_ascii=False)
                console.print_success(f"Resultados exportados a: {filename}")

        except Exception as e:
            console.print_error(f"Error exportando resultados: {e}")

    def _export_to_csv(self, results: Dict, filename: str):
        """Exportar resultados a CSV"""
        # Esta es una implementación básica
        # Se puede expandir según los tipos de datos
        with open(filename, 'w', newline='', encoding='utf-8') as f:
            writer = csv.writer(f)

            # Escribir encabezados
            writer.writerow(['Module', 'Target', 'Success', 'Data'])

            # Escribir datos
            for module_name, result in results.items():
                if isinstance(result, dict):
                    writer.writerow([
                        module_name,
                        result.get('target', ''),
                        result.get('success', False),
                        json.dumps(result.get('data', {}))
                    ])

    def _get_statistics(self) -> Dict:
        """Obtener estadísticas de la base de datos"""
        stats = {}

        try:
            # Contar dominios
            result = self.db.execute("SELECT COUNT(*) as count FROM domains", fetch_all=False)
            stats['total_domains'] = result['count'] if result else 0

            # Contar emails
            result = self.db.execute("SELECT COUNT(*) as count FROM emails", fetch_all=False)
            stats['total_emails'] = result['count'] if result else 0

            # Contar personas
            result = self.db.execute("SELECT COUNT(*) as count FROM persons", fetch_all=False)
            stats['total_persons'] = result['count'] if result else 0

            # Contar subdominios
            result = self.db.execute("SELECT COUNT(*) as count FROM subdomains", fetch_all=False)
            stats['total_subdomains'] = result['count'] if result else 0

            # Último escaneo
            result = self.db.execute(
                "SELECT MAX(timestamp) as last_scan FROM scan_results WHERE success = 1",
                fetch_all=False
            )
            stats['last_scan'] = result['last_scan'] if result and result['last_scan'] else 'Nunca'

            # Total de escaneos
            result = self.db.execute("SELECT COUNT(*) as count FROM scan_results", fetch_all=False)
            stats['total_scans'] = result['count'] if result else 0

            # Tasa de éxito
            result = self.db.execute(
                "SELECT COUNT(*) as total, SUM(CASE WHEN success = 1 THEN 1 ELSE 0 END) as successful FROM scan_results",
                fetch_all=False
            )

            if result and result['total'] > 0:
                success_rate = (result['successful'] / result['total']) * 100
                stats['success_rate'] = f"{success_rate:.1f}%"
            else:
                stats['success_rate'] = "0%"

        except Exception as e:
            console.print_error(f"Error obteniendo estadísticas: {e}")
            stats['error'] = str(e)

        return stats


def show_help():
    """Mostrar ayuda detallada sobre el uso de OSINT-NG"""
    help_text = """
[bold cyan]AYUDA DE OSINT-NG[/]
[bold]================[/]

[bold]1. Configuración Inicial[/]
[bold]---------------------[/]
[bold]Configurar API Keys:[/]
  osint-ng config --set api.virustotal_key=tu_clave_virustotal
  osint-ng config --set api.shodan_key=tu_clave_shodan
  osint-ng config --set api.hunterio_key=tu_clave_hunterio
  osint-ng config --set api.haveibeenpwned_key=tu_clave_hibp

[bold]Configuración General:[/]
  osint-ng config --set general.language=es  # 'es' para español, 'en' para inglés
  osint-ng config --set general.theme=dark   # 'dark' o 'light'
  osint-ng config --set general.timeout=30   # Tiempo de espera en segundos

[bold]2. Uso Básico[/]
[bold]------------[/]
[bold]Analizar un dominio:[/]
  osint-ng domain ejemplo.com
  osint-ng domain ejemplo.com --whois --dns --subdomains
  osint-ng domain ejemplo.com -o resultado.txt

[bold]Analizar un correo electrónico:[/]
  osint-ng email usuario@ejemplo.com
  osint-ng email usuario@ejemplo.com -o resultado.txt

[bold]Buscar en redes sociales:[/]
  osint-ng social nombreusuario
  osint-ng social nombreusuario -o resultado.txt

[bold]3. Comandos Adicionales[/]
[bold]----------------------[/]
[bold]Listar módulos disponibles:[/]
  osint-ng list

[bold]Mostrar estadísticas:[/]
  osint-ng stats

[bold]Mostrar todos los comandos:[/]
  osint-ng --commands

[bold]4. Exportación de Resultados[/]
[bold]--------------------------[/]
  # Exportar a archivo de texto
  osint-ng domain ejemplo.com -o resultado.txt

  # Exportar a JSON
  osint-ng domain ejemplo.com -o resultado.json

  # Exportar a CSV
  osint-ng domain ejemplo.com -o resultado.csv

[bold]5. Solución de Problemas[/]
[bold]-----------------------[/]
- Si ves errores de conexión, verifica tu conexión a Internet
- Para errores de API, verifica que las claves estén configuradas correctamente
- Usa --verbose para obtener más información de depuración

[bold]6. Ejemplos Completos[/]
[bold]---------------------[/]
# Análisis completo de un dominio
osint-ng domain ejemplo.com --whois --dns --subdomains -o resultado.txt

# Búsqueda en redes sociales
osint-ng social johndoe -o redes_sociales.txt

# Configuración de idioma
osint-ng config --set general.language=en

[bold]7. Obtener Ayuda[/]
[bold]---------------[/]
osint-ng --help       # Muestra ayuda básica
osint-ng --commands   # Muestra todos los comandos disponibles
osint-ng help         # Muestra esta ayuda detallada

[bold]8. Actualización[/]
[bold]--------------[/]
Para actualizar a la última versión:
  git pull origin main
  pip install -r requirements.txt
"""

    console.console.print(help_text)

def show_commands():
    """Mostrar todos los comandos y parámetros disponibles"""
    commands = {
        'domain': {
            'desc': 'Analizar un dominio',
            'args': {
                'domain': 'Dominio a analizar (requerido)',
                '-w, --whois': 'Obtener información WHOIS',
                '-d, --dns': 'Obtener registros DNS',
                '-s, --subdomains': 'Buscar subdominios',
                '-o, --output': 'Guardar resultados en archivo'
            }
        },
        'email': {
            'desc': 'Analizar un correo electrónico',
            'args': {
                'email': 'Correo a analizar (requerido)',
                '-o, --output': 'Guardar resultados en archivo'
            }
        },
        'social': {
            'desc': 'Buscar usuario en redes sociales',
            'args': {
                'username': 'Nombre de usuario a buscar (requerido)',
                '-o, --output': 'Guardar resultados en archivo'
            }
        },
        'list': {
            'desc': 'Listar módulos disponibles',
            'args': {}
        },
        'stats': {
            'desc': 'Mostrar estadísticas de uso',
            'args': {}
        },
        'config': {
            'desc': 'Configurar OSINT-NG',
            'args': {
                '--set KEY=VALUE': 'Establecer configuración',
                '--get KEY': 'Obtener valor de configuración',
                '--list': 'Listar toda la configuración'
            }
        }
    }

    console.console.print("\n[bold cyan]COMANDOS DISPONIBLES[/]")
    console.console.print("=" * 50)
    
    for cmd, data in commands.items():
        console.console.print(f"\n[bold green]{cmd}[/] - {data['desc']}")
        for arg, desc in data['args'].items():
            console.console.print(f"  [yellow]{arg: <25}[/] {desc}")
    
    console.console.print("\n[bold]Ejemplos:[/]")
    console.console.print("  osint-ng domain example.com --whois --dns")
    console.console.print("  osint-ng email user@example.com -o resultados.txt")
    console.console.print("  osint-ng config --set virustotal_key=tu_clave")
    console.console.print("  osint-ng --commands  # Muestra esta ayuda\n")

# ============================================================================
# FUNCIÓN PRINCIPAL
# ============================================================================

def main():
    """Función principal del programa"""
    # Mostrar banner y ayuda básica si no hay argumentos
    if len(sys.argv) == 1:
        console.print_banner()
        show_help()
        return

    # Verificación temprana de opciones especiales
    if '--commands' in sys.argv:
        console.print_banner()
        show_commands()
        return

    if '--help' in sys.argv or '-h' in sys.argv or 'help' in sys.argv:
        console.print_banner()
        show_help()
        return

    if '--version' in sys.argv or '-v' in sys.argv:
        console.print_banner()
        console.console.print(f"[bold]Versión:[/] {__version__}")
        return

    # Configuración del parser
    parser = argparse.ArgumentParser(
        description='OSINT-NG - Framework profesional de Inteligencia de Fuentes Abiertas',
        formatter_class=argparse.RawDescriptionHelpFormatter,
        add_help=False
    )

    # Opciones globales
    parser.add_argument('-h', '--help', action='store_true', help='Mostrar este mensaje de ayuda')
    parser.add_argument('-v', '--version', action='store_true', help='Mostrar versión')
    parser.add_argument('--verbose', action='store_true', help='Modo verboso')
    parser.add_argument('--commands', action='store_true', help='Mostrar todos los comandos disponibles')

    # Comandos principales
    subparsers = parser.add_subparsers(dest='command', help='Comandos disponibles')

    # Comando: domain
    domain_parser = subparsers.add_parser('domain', help='Analizar un dominio')
    domain_parser.add_argument('domain', help='Dominio a analizar')
    domain_parser.add_argument('-w', '--whois', action='store_true', help='Obtener información WHOIS')
    domain_parser.add_argument('-d', '--dns', action='store_true', help='Obtener registros DNS')
    domain_parser.add_argument('-s', '--subdomains', action='store_true', help='Buscar subdominios')
    domain_parser.add_argument('-o', '--output', help='Guardar resultados en archivo')

    # Comando: email
    email_parser = subparsers.add_parser('email', help='Analizar un correo electrónico')
    email_parser.add_argument('email', help='Correo electrónico a analizar')
    email_parser.add_argument('-o', '--output', help='Guardar resultados en archivo')

    # Comando: social
    social_parser = subparsers.add_parser('social', help='Buscar usuario en redes sociales')
    social_parser.add_argument('username', help='Nombre de usuario a buscar')
    social_parser.add_argument('-o', '--output', help='Guardar resultados en archivo')

    # Comando: list
    subparsers.add_parser('list', help='Listar módulos disponibles')

    # Comando: stats
    subparsers.add_parser('stats', help='Mostrar estadísticas')

    # Comando: config
    config_parser = subparsers.add_parser('config', help='Configurar OSINT-NG')
    config_parser.add_argument('--set', help='Establecer configuración: clave=valor')
    config_parser.add_argument('--get', help='Obtener valor de configuración')
    config_parser.add_argument('--list', action='store_true', help='Listar toda la configuración')
    
    # Comando: help
    subparsers.add_parser('help', help='Mostrar ayuda detallada')

    # Parsear argumentos
    try:
        args = parser.parse_args()
    except SystemExit:
        # Si hay un error en los argumentos, mostrar ayuda y salir
        console.print_banner()
        show_help()
        sys.exit(1)

    # Manejar opciones globales después del parseo
    if hasattr(args, 'help') and args.help:
        console.print_banner()
        show_help()
        return

    if hasattr(args, 'version') and args.version:
        console.print_banner()
        console.console.print(f"[bold]Versión:[/] {__version__}")
        return

    if hasattr(args, 'commands') and args.commands:
        console.print_banner()
        show_commands()
        return

    # Manejar comando help
    if hasattr(args, 'command') and args.command == 'help':
        console.print_banner()
        show_help()
        return

    # Si no se especificó ningún comando, mostrar ayuda
    if not hasattr(args, 'command') or args.command is None:
        console.print_banner()
        show_help()
        return

    # Configurar logging verboso
    if hasattr(args, 'verbose') and args.verbose:
        logging.getLogger().setLevel(logging.DEBUG)
        logger.debug("Modo verboso activado")

    # Manejar comandos
    handler = CommandHandler()

    try:
        if args.command == 'domain':
            handler.handle_domain(args.domain, args)
        elif args.command == 'email':
            handler.handle_email(args.email, args)
        elif args.command == 'social':
            handler.handle_social(args.username, args)
        elif args.command == 'list':
            handler.handle_list()
        elif args.command == 'stats':
            handler.handle_stats()
        elif args.command == 'config':
            if args.set:
                key, value = args.set.split('=', 1)
                section, option = key.split('.', 1) if '.' in key else ('general', key)
                CONFIG.set(section, option, value)
                console.print_success(f"Configuración actualizada: {key}={value}")
            elif args.get:
                section, option = args.get.split('.', 1) if '.' in args.get else ('general', args.get)
                value = CONFIG.get(section, option)
                console.print_info(f"{args.get} = {value}")
            elif args.list:
                console.print_info("Configuración actual:")
                for section in CONFIG.config.sections():
                    console.console.print(f"\n[{section}]", style="cyan")
                    for key, value in CONFIG.config.items(section):
                        console.console.print(f"  {key} = {value}")

    except KeyboardInterrupt:
        console.print_warning("\nOperación cancelada por el usuario")
        sys.exit(0)
    except Exception as e:
        console.print_error(f"Error: {e}")
        if hasattr(args, 'verbose') and args.verbose:
            import traceback
            traceback.print_exc()
        sys.exit(1)
    finally:
        # Cerrar conexiones
        handler.db.close()


if __name__ == '__main__':
    main()