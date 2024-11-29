#!/usr/bin/env python3
# dnsbrute 2.2.0
# por Gabs77u
# 2023-07-20

"""
DNSBrute - Ferramenta de descoberta de diretórios e subdomínios
Esta ferramenta pode ser usada para descobrir diretórios ocultos e subdomínios em aplicações web
através de ataques de força bruta.
"""

import requests
import logging
import re
import os
import json
import csv
import sys
import argparse
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException, ConnectionError, Timeout, HTTPError, TooManyRedirects
from typing import List, Dict, Union, Optional, Tuple, Any
from contextlib import contextmanager
from time import sleep
from collections import OrderedDict
import signal
import sqlite3
from pathlib import Path
from dataclasses import dataclass, asdict
from abc import ABC, abstractmethod
import ssl
import hashlib
import pickle
from functools import wraps
import time
import importlib.util

# Constantes globais
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "DNSBrute/2.1.0"
DEFAULT_DELAY = 0
DEFAULT_RETRIES = 3
VALID_STATUS_CODES = {200, 201, 202, 203, 204, 301, 302, 307, 308}
VALID_SCHEMES = {'http', 'https'}
VALID_MODES = {'directory', 'subdomain'}
MAX_CACHE_SIZE = 1000  # Limite do cache
MAX_FILE_SIZE = 10 * 1024 * 1024  # 10MB limite para wordlist

# Constantes adicionais
CONFIG_DIR = Path.home() / '.dnsbrute'
CONFIG_FILE = CONFIG_DIR / 'config.json'
HISTORY_DB = CONFIG_DIR / 'history.db'
PLUGINS_DIR = CONFIG_DIR / 'plugins'
BATCH_SIZE = 50
MAX_MEMORY_USAGE = 1024 * 1024 * 1024  # 1GB
RATE_LIMIT_REQUESTS = 100
RATE_LIMIT_PERIOD = 60  # segundos

@dataclass
class ScanHistory:
    """Registro de um scan realizado"""
    id: int
    url: str
    mode: str
    wordlist: str
    start_time: datetime
    end_time: datetime
    total_requests: int
    found_count: int
    config: Dict
    results: List[Dict]

class RateLimiter:
    """Implementa rate limiting para requisições"""
    def __init__(self, max_requests: int, period: int):
        self.max_requests = max_requests
        self.period = period
        self.requests = []
    
    def can_proceed(self) -> bool:
        """Verifica se pode fazer mais requisições"""
        now = time.time()
        # Remove requisições antigas
        self.requests = [req for req in self.requests if now - req < self.period]
        return len(self.requests) < self.max_requests
    
    def add_request(self):
        """Registra uma nova requisição"""
        self.requests.append(time.time())
        
    def wait_time(self) -> float:
        """Retorna o tempo de espera necessário"""
        if not self.requests:
            return 0
        now = time.time()
        oldest = min(self.requests)
        return max(0, self.period - (now - oldest))

class HistoryManager:
    """Gerencia o histórico de scans"""
    def __init__(self):
        self._init_db()
    
    def _init_db(self):
        """Inicializa o banco de dados"""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        with sqlite3.connect(HISTORY_DB) as conn:
            conn.execute("""
                CREATE TABLE IF NOT EXISTS scans (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    url TEXT,
                    mode TEXT,
                    wordlist TEXT,
                    start_time TIMESTAMP,
                    end_time TIMESTAMP,
                    total_requests INTEGER,
                    found_count INTEGER,
                    config TEXT,
                    results TEXT
                )
            """)
    
    def add_scan(self, scan: ScanHistory):
        """Adiciona um novo scan ao histórico"""
        with sqlite3.connect(HISTORY_DB) as conn:
            conn.execute("""
                INSERT INTO scans (url, mode, wordlist, start_time, end_time,
                                 total_requests, found_count, config, results)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """, (
                scan.url, scan.mode, scan.wordlist,
                scan.start_time.isoformat(), scan.end_time.isoformat(),
                scan.total_requests, scan.found_count,
                json.dumps(scan.config), json.dumps(scan.results)
            ))
    
    def get_scans(self, limit: int = 10) -> List[ScanHistory]:
        """Retorna os últimos scans realizados"""
        with sqlite3.connect(HISTORY_DB) as conn:
            cursor = conn.execute("""
                SELECT * FROM scans ORDER BY start_time DESC LIMIT ?
            """, (limit,))
            return [ScanHistory(
                id=row[0],
                url=row[1],
                mode=row[2],
                wordlist=row[3],
                start_time=datetime.fromisoformat(row[4]),
                end_time=datetime.fromisoformat(row[5]),
                total_requests=row[6],
                found_count=row[7],
                config=json.loads(row[8]),
                results=json.loads(row[9])
            ) for row in cursor.fetchall()]

class ConfigManager:
    """Gerencia configurações persistentes"""
    def __init__(self):
        self.config_file = CONFIG_FILE
        self._ensure_config_dir()
        self.config = self._load_config()
    
    def _ensure_config_dir(self):
        """Garante que o diretório de configuração existe"""
        CONFIG_DIR.mkdir(parents=True, exist_ok=True)
        PLUGINS_DIR.mkdir(parents=True, exist_ok=True)
    
    def _load_config(self) -> Dict:
        """Carrega configurações do arquivo"""
        if self.config_file.exists():
            with open(self.config_file, 'r') as f:
                return json.load(f)
        return self._default_config()
    
    def _default_config(self) -> Dict:
        """Retorna configuração padrão"""
        return {
            'threads': DEFAULT_THREADS,
            'timeout': DEFAULT_TIMEOUT,
            'user_agent': DEFAULT_USER_AGENT,
            'verify_ssl': True,
            'rate_limit': {
                'max_requests': RATE_LIMIT_REQUESTS,
                'period': RATE_LIMIT_PERIOD
            },
            'batch_size': BATCH_SIZE,
            'plugins': [],
            'output_formats': ['text', 'json', 'csv'],
            'hooks': {
                'pre_scan': [],
                'post_scan': [],
                'on_result': []
            }
        }
    
    def save(self):
        """Salva configurações no arquivo"""
        with open(self.config_file, 'w') as f:
            json.dump(self.config, f, indent=4)
    
    def update(self, **kwargs):
        """Atualiza configurações"""
        self.config.update(kwargs)
        self.save()

class Plugin(ABC):
    """Classe base para plugins"""
    @abstractmethod
    def on_load(self):
        """Chamado quando o plugin é carregado"""
        pass
    
    @abstractmethod
    def pre_scan(self, config: Dict) -> Dict:
        """Chamado antes do scan iniciar"""
        return config
    
    @abstractmethod
    def post_scan(self, results: List[Dict]) -> List[Dict]:
        """Chamado após o scan terminar"""
        return results
    
    @abstractmethod
    def on_result(self, result: Dict) -> Dict:
        """Chamado para cada resultado encontrado"""
        return result

class PluginManager:
    """Gerencia plugins do sistema"""
    def __init__(self):
        self.plugins: List[Plugin] = []
        self._load_plugins()
    
    def _load_plugins(self):
        """Carrega plugins do diretório de plugins"""
        if not PLUGINS_DIR.exists():
            return
        
        for plugin_file in PLUGINS_DIR.glob('*.py'):
            try:
                # Carrega o módulo do plugin
                spec = importlib.util.spec_from_file_location(
                    plugin_file.stem, plugin_file
                )
                module = importlib.util.module_from_spec(spec)
                spec.loader.exec_module(module)
                
                # Instancia o plugin
                if hasattr(module, 'Plugin'):
                    plugin = module.Plugin()
                    plugin.on_load()
                    self.plugins.append(plugin)
            except Exception as e:
                logging.error(f"Erro ao carregar plugin {plugin_file}: {e}")
    
    def run_hook(self, hook_name: str, data: Any) -> Any:
        """Executa um hook em todos os plugins"""
        for plugin in self.plugins:
            try:
                if hasattr(plugin, hook_name):
                    data = getattr(plugin, hook_name)(data)
            except Exception as e:
                logging.error(f"Erro no plugin {plugin.__class__.__name__}: {e}")
        return data

class BatchProcessor:
    """Processa palavras em lotes para otimizar memória"""
    def __init__(self, wordlist: List[str], batch_size: int = BATCH_SIZE):
        self.wordlist = wordlist
        self.batch_size = batch_size
        self.current_index = 0
    
    def __iter__(self):
        return self
    
    def __next__(self) -> List[str]:
        if self.current_index >= len(self.wordlist):
            raise StopIteration
        
        batch = self.wordlist[
            self.current_index:
            self.current_index + self.batch_size
        ]
        self.current_index += self.batch_size
        return batch

class DNSBruteError(Exception):
    """Classe base para exceções do DNSBrute"""
    pass

class ConfigError(DNSBruteError):
    """Exceção para erros de configuração"""
    pass

class ValidationError(DNSBruteError):
    """Exceção para erros de validação"""
    pass

class ResourceError(DNSBruteError):
    """Exceção para erros de recursos"""
    pass

def setup_logging(verbose: bool = False) -> None:
    """Configura o sistema de logging"""
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_level = logging.DEBUG if verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

def validate_url(url: str) -> bool:
    """Valida uma URL"""
    try:
        parsed = urlparse(url)
        return bool(parsed.scheme in VALID_SCHEMES and parsed.netloc)
    except Exception:
        return False

def validate_file(path: str) -> Tuple[bool, str]:
    """Valida se um arquivo existe e é utilizável"""
    if not os.path.isfile(path):
        return False, "Arquivo não encontrado"
    if not os.access(path, os.R_OK):
        return False, "Sem permissão de leitura"
    if os.path.getsize(path) > MAX_FILE_SIZE:
        return False, f"Arquivo muito grande (máximo {MAX_FILE_SIZE/1024/1024:.1f}MB)"
    if os.path.getsize(path) == 0:
        return False, "Arquivo vazio"
    return True, ""

def validate_mode(mode: str) -> bool:
    """Valida o modo de operação"""
    return mode.lower() in VALID_MODES

def validate_threads(threads: Union[str, int]) -> bool:
    """Valida o número de threads"""
    try:
        thread_count = int(threads)
        return 1 <= thread_count <= 100
    except ValueError:
        return False

def validate_input(value: str, validator, error_msg: str, default: str = None) -> str:
    """Função genérica para validação de input"""
    if not value and default is not None:
        return default
    if not validator(value):
        raise ValidationError(error_msg)
    return value

class Config:
    """Classe de configuração com validação integrada"""
    def __init__(self, **kwargs):
        self.threads = self._validate_threads(kwargs.get('threads', DEFAULT_THREADS))
        self.timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
        self.user_agent = kwargs.get('user_agent', DEFAULT_USER_AGENT)
        self.delay = kwargs.get('delay', DEFAULT_DELAY)
        self.output_format = kwargs.get('output_format', 'text')
        self.auth = kwargs.get('auth', None)
        self.verify_ssl = kwargs.get('verify_ssl', True)
        self.mode = self._validate_mode(kwargs.get('mode', 'directory'))
        self.proxy = kwargs.get('proxy', None)
        self.retries = kwargs.get('retries', DEFAULT_RETRIES)
        self.verbose = kwargs.get('verbose', False)

    def _validate_threads(self, threads: int) -> int:
        if not validate_threads(threads):
            raise ConfigError("Número de threads deve ser entre 1 e 100")
        return threads

    def _validate_mode(self, mode: str) -> str:
        if not validate_mode(mode):
            raise ConfigError("Modo deve ser 'directory' ou 'subdomain'")
        return mode.lower()

class Result:
    """Classe que representa um resultado do scan"""
    def __init__(self, target: str, status_code: int, content_type: str, found: bool):
        self.target = target
        self.status_code = status_code
        self.content_type = content_type
        self.found = found
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict:
        return {
            'target': self.target,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'found': self.found,
            'timestamp': self.timestamp.isoformat()
        }

class LimitedSizeCache:
    """Cache com tamanho limitado usando LRU"""
    def __init__(self, max_size: int = MAX_CACHE_SIZE):
        self._cache = OrderedDict()
        self.max_size = max_size
    
    def __contains__(self, key: str) -> bool:
        return key in self._cache
    
    def __getitem__(self, key: str) -> Any:
        value = self._cache.pop(key)
        self._cache[key] = value
        return value
    
    def __setitem__(self, key: str, value: Any):
        if key in self._cache:
            self._cache.pop(key)
        elif len(self._cache) >= self.max_size:
            self._cache.popitem(last=False)
        self._cache[key] = value

class AsciiInterface:
    """Interface ASCII do programa"""
    
    BANNER = """
    ██████╗ ███╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗████████╗███████╗
    ██╔══██╗████╗  ██║██╔════╝██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝
    ██║  ██║██╔██╗ ██║███████╗██████╔╝██████╔╝██║   ██║   ██║   █████╗  
    ██║  ██║██║╚██╗██║╚════██║██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  
    ██████╔╝██║ ╚████║███████║██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗
    ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚════╝
    v2.2.0 - Por Gabs77u                                                                    
    """
    
    MENU = """
    ╔════════════════════════════════════════════════════════════════════╗
    ║                         MENU PRINCIPAL                             ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║ [1] Iniciar Scan                                                  ║
    ║ [2] Histórico                                                     ║
    ║ [3] Configurações                                                 ║
    ║ [4] Manual de Uso                                                 ║
    ║ [5] Sobre                                                         ║
    ║ [6] Sair                                                         ║
    ╚════════════════════════════════════════════════════════════════════╝
    """
    
    SOBRE = """
    ╔════════════════════════════════════════════════════════════════════╗
    ║                             SOBRE                                  ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║ DNSBrute é uma ferramenta de descoberta de diretórios e           ║
    ║ subdomínios em aplicações web através de ataques de força bruta.  ║
    ║                                                                    ║
    ║ Desenvolvido por: Gabs77u                                         ║
    ║ Versão: 2.1.0                                                     ║
    ║ GitHub: https://github.com/gabs77u/dnsbrute                      ║
    ╚════════════════════════════════════════════════════════════════════╝
    """

    MANUAL = """
    ╔════════════════════════════════════════════════════════════════════╗
    ║                         MANUAL DE USO                              ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║                                                                    ║
    ║  MODOS DE USO:                                                    ║
    ║  1. Modo Interativo:                                              ║
    ║     - Execute sem argumentos: python dnsbrute.py                  ║
    ║     - Siga as instruções na tela                                 ║
    ║                                                                    ║
    ║  2. Linha de Comando:                                             ║
    ║     python dnsbrute.py -u URL -w WORDLIST [opções]               ║
    ║                                                                    ║
    ║  ARGUMENTOS PRINCIPAIS:                                           ║
    ║  -u, --url       URL alvo (ex: https://exemplo.com)              ║
    ║  -w, --wordlist  Arquivo com lista de palavras                   ║
    ║  -m, --mode      Modo: directory ou subdomain                    ║
    ║  -t, --threads   Número de threads (padrão: 10)                  ║
    ║                                                                    ║
    ║  OPÇÕES ADICIONAIS:                                              ║
    ║  -o, --output    Arquivo de saída                                ║
    ║  -f, --format    Formato: text, json, csv                        ║
    ║  -d, --delay     Delay entre requisições                         ║
    ║  -v, --verbose   Modo verboso                                    ║
    ║                                                                    ║
    ║  OPÇÕES AVANÇADAS:                                               ║
    ║  --timeout       Timeout das requisições                         ║
    ║  --user-agent    User-Agent personalizado                        ║
    ║  --no-verify-ssl Desabilita verificação SSL                      ║
    ║  --proxy         Define proxy (http://user:pass@host:port)       ║
    ║  --retries       Número de tentativas por alvo                   ║
    ║                                                                    ║
    ║  EXEMPLOS DE USO:                                                ║
    ║  1. Scan básico de diretórios:                                   ║
    ║     python dnsbrute.py -u https://exemplo.com -w wordlist.txt    ║
    ║                                                                    ║
    ║  2. Descoberta de subdomínios:                                   ║
    ║     python dnsbrute.py -u exemplo.com -w subs.txt -m subdomain   ║
    ║                                                                    ║
    ║  3. Scan otimizado com saída em JSON:                            ║
    ║     python dnsbrute.py -u https://exemplo.com -w words.txt       ║
    ║     -t 20 -o resultado.json -f json                              ║
    ║                                                                    ║
    ║  4. Scan através de proxy:                                       ║
    ║     python dnsbrute.py -u https://exemplo.com -w words.txt       ║
    ║     --proxy http://127.0.0.1:8080                                ║
    ║                                                                    ║
    ║  DICAS:                                                          ║
    ║  - Use modo verboso (-v) para mais informações                   ║
    ║  - Ajuste threads conforme sua conexão                           ║
    ║  - Use delay para evitar bloqueios                               ║
    ║  - Verifique permissões da wordlist                             ║
    ║                                                                    ║
    ║  OBSERVAÇÕES:                                                    ║
    ║  - Tamanho máximo da wordlist: 10MB                             ║
    ║  - Limite de threads: 1-100                                      ║
    ║  - Formatos suportados: text, json, csv                         ║
    ║  - Use Ctrl+C para interromper o scan                           ║
    ╚════════════════════════════════════════════════════════════════════╝    
    """

    @staticmethod
    def clear_screen():
        """Limpa a tela do terminal"""
        os.system('cls' if os.name == 'nt' else 'clear')

    @staticmethod
    def print_banner():
        """Exibe o banner da aplicação"""
        print(AsciiInterface.BANNER)

    @staticmethod
    def print_menu():
        """Exibe o menu principal"""
        print(AsciiInterface.MENU)

    @staticmethod
    def print_sobre():
        """Exibe informações sobre a aplicação"""
        print(AsciiInterface.SOBRE)

    @staticmethod
    def print_manual():
        """Exibe o manual de uso"""
        print(AsciiInterface.MANUAL)

    @staticmethod
    def print_progress(current: int, total: int, width: int = 50):
        """Exibe uma barra de progresso"""
        percent = current / total
        filled = int(width * percent)
        bar = '█' * filled + '░' * (width - filled)
        print(f'\rProgresso: |{bar}| {percent:.1%}', end='')
        if current == total:
            print()

    @staticmethod
    def print_history(scans: List[ScanHistory]):
        """Exibe o histórico de scans"""
        print("\n╔═══════════════════ HISTÓRICO DE SCANS ══════════════════╗")
        if not scans:
            print("║ Nenhum scan realizado ainda                              ║")
        else:
            print("║ ID  │ URL                │ Modo      │ Data       │ Found ║")
            print("╟─────┼──────────────────┼──────────┼───────────┼───────╢")
            for scan in scans:
                url = scan.url[:16].ljust(16)
                mode = scan.mode[:8].ljust(8)
                date = scan.start_time.strftime("%Y-%m-%d")
                print(f"║ {scan.id:3d} │ {url} │ {mode} │ {date} │ {scan.found_count:5d} ║")
        print("╚════════════════════════════════════════════════════════╝")

    @staticmethod
    def print_scan_details(scan: ScanHistory):
        """Exibe detalhes de um scan específico"""
        print("\n╔═══════════════════ DETALHES DO SCAN ══════════════════╗")
        print(f"║ URL: {scan.url}")
        print(f"║ Modo: {scan.mode}")
        print(f"║ Wordlist: {scan.wordlist}")
        print(f"║ Data Início: {scan.start_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"║ Data Fim: {scan.end_time.strftime('%Y-%m-%d %H:%M:%S')}")
        print(f"║ Total Requisições: {scan.total_requests}")
        print(f"║ Encontrados: {scan.found_count}")
        print("║")
        print("║ Resultados:")
        for result in scan.results:
            print(f"║ - {result['target']} ({result['status_code']})")
        print("╚════════════════════════════════════════════════════════╝")

    @staticmethod
    def print_config(config: Dict):
        """Exibe configurações atuais"""
        print("\n╔═══════════════════ CONFIGURAÇÕES ══════════════════════╗")
        print("║ 1. Geral:                                               ║")
        print(f"║    - Threads: {config['threads']}")
        print(f"║    - Timeout: {config['timeout']}s")
        print(f"║    - User-Agent: {config['user_agent']}")
        print("║")
        print("║ 2. Rate Limiting:                                       ║")
        print(f"║    - Max Requests: {config['rate_limit']['max_requests']}")
        print(f"║    - Period: {config['rate_limit']['period']}s")
        print("║")
        print("║ 3. Segurança:                                          ║")
        print(f"║    - Verify SSL: {config['verify_ssl']}")
        print("║")
        print("║ 4. Performance:                                        ║")
        print(f"║    - Batch Size: {config['batch_size']}")
        print("║")
        print("║ 5. Plugins:                                           ║")
        for plugin in config['plugins']:
            print(f"║    - {plugin}")
        print("║")
        print("║ 6. Formatos de Saída:                                 ║")
        for fmt in config['output_formats']:
            print(f"║    - {fmt}")
        print("╚════════════════════════════════════════════════════════╝")

def validate_input_file(value: str, error_msg: str, default: str = None) -> str:
    """Função específica para validação de arquivo"""
    if not value and default is not None:
        return default
    valid, msg = validate_file(value)
    if not valid:
        raise ValidationError(f"{error_msg}: {msg}")
    return value

class Bruteforcer:
    """Classe principal do scanner com gerenciamento de recursos"""
    def __init__(self, url: str, wordlist_path: str, config: Config):
        self.url = self._normalize_url(url)
        self.wordlist_path = wordlist_path
        self.config = config
        self.results: List[Result] = []
        self._cache = LimitedSizeCache()
        self._session = None
        self._running = False
        self._rate_limiter = RateLimiter(
            config.rate_limit['max_requests'],
            config.rate_limit['period']
        )
        self._history_manager = HistoryManager()
        self._plugin_manager = PluginManager()
        self._start_time = None
        self._total_requests = 0
        
        # Configura handler para CTRL+C
        signal.signal(signal.SIGINT, self._signal_handler)
    
    def _signal_handler(self, signum, frame):
        """Handler para CTRL+C"""
        if self._running:
            logging.info("\nParando scan graciosamente...")
            self._running = False
    
    def __enter__(self):
        try:
            self._session = self._create_session()
            return self
        except Exception as e:
            logging.error(f"Erro ao inicializar sessão: {e}")
            self.__exit__(None, None, None)
            raise
    
    def __exit__(self, exc_type, exc_val, exc_tb):
        try:
            if self._session:
                self._session.close()
        except Exception as e:
            logging.error(f"Erro ao fechar sessão: {e}")
        finally:
            self._session = None
            self._running = False
            self._save_history()

    def _create_session(self) -> requests.Session:
        """Cria e configura uma sessão HTTP"""
        session = requests.Session()
        session.headers.update({'User-Agent': self.config.user_agent})
        
        # Configuração SSL
        if self.config.verify_ssl:
            context = ssl.create_default_context()
            context.verify_mode = ssl.CERT_REQUIRED
            context.check_hostname = True
            session.verify = True
        else:
            session.verify = False
        
        if self.config.auth:
            session.auth = self.config.auth
        if self.config.proxy:
            session.proxies = self.config.proxy
        return session

    def _save_history(self):
        """Salva o histórico do scan atual"""
        if not self._start_time:
            return
            
        scan = ScanHistory(
            id=0,  # Será definido pelo banco
            url=self.url,
            mode=self.config.mode,
            wordlist=self.wordlist_path,
            start_time=self._start_time,
            end_time=datetime.now(),
            total_requests=self._total_requests,
            found_count=len(self.results),
            config=asdict(self.config),
            results=[r.to_dict() for r in self.results]
        )
        self._history_manager.add_scan(scan)

    def _validate_batch(self, batch: List[str]) -> List[Result]:
        """Valida um lote de palavras"""
        results = []
        for word in batch:
            # Rate limiting
            wait = self._rate_limiter.wait_time()
            if wait > 0:
                time.sleep(wait)
            
            if not self._rate_limiter.can_proceed():
                logging.warning("Rate limit atingido, aguardando...")
                time.sleep(self._rate_limiter.wait_time())
            
            result = self._validate_target(word)
            self._rate_limiter.add_request()
            self._total_requests += 1
            
            # Executa hook de resultado
            result_dict = result.to_dict()
            result_dict = self._plugin_manager.run_hook('on_result', result_dict)
            
            if result_dict['found']:
                results.append(Result(**result_dict))
            
            if not self._running:
                break
        
        return results

    def run(self) -> List[Result]:
        """Executa o scan"""
        self._start_time = datetime.now()
        self._running = True
        self._total_requests = 0
        
        try:
            # Carrega e valida a wordlist
            wordlist = self._load_wordlist()
            if not wordlist:
                raise ResourceError("Wordlist vazia")

            # Executa hook pre_scan
            config_dict = asdict(self.config)
            config_dict = self._plugin_manager.run_hook('pre_scan', config_dict)
            
            logging.info(f"Iniciando scan com {len(wordlist)} palavras")
            
            # Processa em lotes
            batch_processor = BatchProcessor(wordlist, self.config.batch_size)
            with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
                for batch in batch_processor:
                    if not self._running:
                        break
                        
                    futures = [
                        executor.submit(self._validate_target, word)
                        for word in batch
                    ]
                    
                    for future in futures:
                        try:
                            result = future.result()
                            if result.found:
                                self.results.append(result)
                                logging.info(f"Encontrado: {result.target}")
                        except Exception as e:
                            logging.error(f"Erro ao processar resultado: {e}")
                
            # Executa hook post_scan
            results_dict = [r.to_dict() for r in self.results]
            results_dict = self._plugin_manager.run_hook('post_scan', results_dict)
            
            return self.results
            
        except Exception as e:
            logging.error(f"Erro durante o scan: {e}")
            raise
        finally:
            self._running = False
            self._save_history()

    def save_results(self, filename: str) -> None:
        """Salva os resultados em arquivo"""
        if not self.results:
            logging.warning("Sem resultados para salvar")
            return

        try:
            # Determina o formato de saída
            output_format = filename.split('.')[-1] if '.' in filename else 'text'
            
            # Verifica se é um formato customizado
            custom_formats = self.config.get('output_formats', [])
            if output_format not in ['text', 'json', 'csv'] + custom_formats:
                raise ValueError(f"Formato de saída não suportado: {output_format}")
            
            with open(filename, 'w', encoding='utf-8') as f:
                if output_format == 'json':
                    json.dump([r.to_dict() for r in self.results], f, indent=2)
                elif output_format == 'csv':
                    writer = csv.DictWriter(f, fieldnames=self.results[0].to_dict().keys())
                    writer.writeheader()
                    writer.writerows([r.to_dict() for r in self.results])
                else:
                    # Tenta usar um formato customizado
                    try:
                        formatter = self._plugin_manager.get_formatter(output_format)
                        f.write(formatter.format(self.results))
                    except Exception:
                        # Fallback para formato texto
                        for result in self.results:
                            f.write(f"{result.target}\t{result.status_code}\t{result.content_type}\n")
            
            logging.info(f"Resultados salvos em: {filename}")
        except Exception as e:
            raise ResourceError(f"Erro ao salvar resultados: {e}")

def execute_scan(url: str, wordlist: str, mode: str, threads: int, output: str = None, **kwargs) -> None:
    """Executa um scan com os parâmetros fornecidos"""
    # Validações iniciais
    valid, msg = validate_file(wordlist)
    if not valid:
        raise ValidationError(f"Erro na wordlist: {msg}")
    
    # Configuração completa
    config = Config(
        threads=threads,
        mode=mode,
        output_format='text' if not output else output.split('.')[-1],
        timeout=kwargs.get('timeout', DEFAULT_TIMEOUT),
        user_agent=kwargs.get('user_agent', DEFAULT_USER_AGENT),
        verify_ssl=kwargs.get('verify_ssl', True),
        proxy=kwargs.get('proxy', None),
        retries=kwargs.get('retries', DEFAULT_RETRIES),
        verbose=kwargs.get('verbose', False),
        delay=kwargs.get('delay', DEFAULT_DELAY)
    )
    
    try:
        with Bruteforcer(url, wordlist, config) as bruteforcer:
            results = bruteforcer.run()
            
            if output:
                bruteforcer.save_results(output)
            else:
                for result in results:
                    print(f"{result.target}\t{result.status_code}\t{result.content_type}")
            
            logging.info(f"Scan concluído. Encontrados {len(results)} resultados.")
    
    except KeyboardInterrupt:
        logging.info("\nScan interrompido pelo usuário.")
    except DNSBruteError as e:
        logging.error(f"Erro durante o scan: {e}")
    except Exception as e:
        logging.error("Erro inesperado durante o scan")
        if logging.getLogger().isEnabledFor(logging.DEBUG):
            logging.exception(e)

def interactive_mode() -> None:
    """Interface interativa do programa"""
    interface = AsciiInterface()
    config_manager = ConfigManager()
    history_manager = HistoryManager()
    
    while True:
        interface.clear_screen()
        interface.print_banner()
        interface.print_menu()
        
        try:
            choice = input("\nEscolha uma opção: ")
            
            if choice == "1":
                # Coleta e valida inputs
                url = validate_input(
                    input("\nDigite a URL alvo: "),
                    validate_url,
                    "URL inválida. Use formato: http(s)://exemplo.com"
                )
                
                wordlist = validate_input_file(
                    input("Digite o caminho da wordlist: "),
                    "Erro na wordlist"
                )
                
                mode = validate_input(
                    input("Escolha o modo (directory/subdomain) [directory]: ") or "directory",
                    validate_mode,
                    "Modo inválido. Use 'directory' ou 'subdomain'"
                )
                
                threads = validate_input(
                    input("Número de threads [10]: ") or "10",
                    validate_threads,
                    "Número inválido. Use entre 1 e 100"
                )
                
                output = input("Arquivo de saída (opcional): ")
                if output and os.path.exists(output):
                    if input("Arquivo já existe. Sobrescrever? (s/N): ").lower() != 's':
                        output = None
                
                # Executa o scan
                execute_scan(url, wordlist, mode, int(threads), output)
                input("\nPressione Enter para continuar...")
                
            elif choice == "2":
                # Histórico
                interface.clear_screen()
                scans = history_manager.get_scans()
                interface.print_history(scans)
                
                scan_id = input("\nDigite o ID do scan para ver detalhes (ou Enter para voltar): ")
                if scan_id.isdigit():
                    scan_id = int(scan_id)
                    for scan in scans:
                        if scan.id == scan_id:
                            interface.print_scan_details(scan)
                            break
                
                input("\nPressione Enter para continuar...")
                
            elif choice == "3":
                # Configurações
                while True:
                    interface.clear_screen()
                    interface.print_config(config_manager.config)
                    
                    print("\nOpções:")
                    print("1. Alterar threads")
                    print("2. Alterar timeout")
                    print("3. Alterar rate limit")
                    print("4. Alterar batch size")
                    print("5. Voltar")
                    
                    config_choice = input("\nEscolha uma opção: ")
                    
                    if config_choice == "1":
                        threads = input("Novo número de threads [10-100]: ")
                        if threads.isdigit() and 10 <= int(threads) <= 100:
                            config_manager.update(threads=int(threads))
                    elif config_choice == "2":
                        timeout = input("Novo timeout em segundos [1-60]: ")
                        if timeout.isdigit() and 1 <= int(timeout) <= 60:
                            config_manager.update(timeout=int(timeout))
                    elif config_choice == "3":
                        max_req = input("Máximo de requisições por período [10-1000]: ")
                        period = input("Período em segundos [1-3600]: ")
                        if (max_req.isdigit() and period.isdigit() and
                            10 <= int(max_req) <= 1000 and
                            1 <= int(period) <= 3600):
                            config_manager.update(rate_limit={
                                'max_requests': int(max_req),
                                'period': int(period)
                            })
                    elif config_choice == "4":
                        batch = input("Tamanho do batch [10-1000]: ")
                        if batch.isdigit() and 10 <= int(batch) <= 1000:
                            config_manager.update(batch_size=int(batch))
                    elif config_choice == "5":
                        break
                
            elif choice == "4":
                # Manual
                interface.clear_screen()
                interface.print_manual()
                input("\nPressione Enter para continuar...")
                
            elif choice == "5":
                # Sobre
                interface.clear_screen()
                interface.print_sobre()
                input("\nPressione Enter para continuar...")
                
            elif choice == "6":
                # Sair
                interface.clear_screen()
                print("\nObrigado por usar o DNSBrute!")
                return
                
            else:
                print("\nOpção inválida!")
                sleep(1)
                
        except KeyboardInterrupt:
            print("\nOperação cancelada pelo usuário.")
            return
        except ValidationError as e:
            print(f"\nErro de validação: {e}")
            input("\nPressione Enter para continuar...")
        except Exception as e:
            print(f"\nErro inesperado: {e}")
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                logging.exception(e)
            input("\nPressione Enter para continuar...")

def main():
    """Função principal do programa"""
    parser = argparse.ArgumentParser(description="DNSBrute - Ferramenta de descoberta de diretórios e subdomínios")
    parser.add_argument("-u", "--url", help="URL alvo")
    parser.add_argument("-w", "--wordlist", help="Arquivo de wordlist")
    parser.add_argument("-t", "--threads", type=int, default=DEFAULT_THREADS, help="Número de threads")
    parser.add_argument("-d", "--delay", type=float, default=DEFAULT_DELAY, help="Delay entre requisições (segundos)")
    parser.add_argument("-o", "--output", help="Arquivo de saída")
    parser.add_argument("-f", "--format", choices=['text', 'json', 'csv'], default='text', help="Formato de saída")
    parser.add_argument("-m", "--mode", choices=['directory', 'subdomain'], default='directory', help="Modo de operação")
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT, help="Timeout das requisições (segundos)")
    parser.add_argument("--user-agent", default=DEFAULT_USER_AGENT, help="User-Agent personalizado")
    parser.add_argument("--no-verify-ssl", action="store_true", help="Desabilita verificação SSL")
    parser.add_argument("--proxy", help="Proxy no formato http://user:pass@host:port")
    parser.add_argument("--retries", type=int, default=DEFAULT_RETRIES, help="Número de tentativas para cada alvo")
    parser.add_argument("-v", "--verbose", action="store_true", help="Modo verboso")
    
    args = parser.parse_args()
    
    # Configura logging
    setup_logging(args.verbose)

    try:
        # Se não houver argumentos obrigatórios, inicia modo interativo
        if not (args.url and args.wordlist):
            interactive_mode()
            return

        # Valida argumentos
        validate_input(args.url, validate_url, "URL inválida")
        validate_input(args.wordlist, validate_file, "Arquivo de wordlist inválido")
        validate_input(args.mode, validate_mode, "Modo inválido")
        validate_input(args.threads, validate_threads, "Número de threads inválido")

        # Executa o scan
        execute_scan(args.url, args.wordlist, args.mode, args.threads, args.output)

    except KeyboardInterrupt:
        print("\nOperação cancelada pelo usuário.")
        sys.exit(0)
    except ValidationError as e:
        logging.error(f"Erro de validação: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error("Erro inesperado durante a execução")
        if args.verbose:
            logging.exception(e)
        sys.exit(1)

if __name__ == "__main__":
    main()