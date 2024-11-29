"""
Plugin avançado para geração de relatórios detalhados com recursos estendidos.

Este plugin fornece funcionalidades avançadas para geração de relatórios de scans DNS,
incluindo:

Características Principais:
- Múltiplos formatos de saída (JSON, HTML, CSV)
- Compressão automática de arquivos grandes
- Sistema de perfis configuráveis
- Validação robusta de dados
- Buffer de escrita assíncrono
- Sistema de eventos
- Métricas de performance
- Limpeza automática de arquivos

Uso Básico:
```python
from report_plugin import Plugin

# Inicializa o plugin
plugin = Plugin()

# Registra handlers de eventos
plugin.on('scan_start', lambda data: print(f"Scan iniciado: {data}"))
plugin.on('result_found', lambda result: print(f"Encontrado: {result['target']}"))

# Configura o perfil
plugin.set_profile('standard')

# Processa resultados
plugin.pre_scan(config)
plugin.on_result(result)
plugin.post_scan(results)
```

Configuração:
O plugin usa um arquivo YAML para configuração (config.yaml) com as seguintes seções:
- reports: Configurações de relatórios e limites
- formats: Formatos de saída disponíveis
- profiles: Perfis predefinidos
- validation: Regras de validação

Métricas:
O plugin coleta as seguintes métricas:
- Tempo de resposta (média, mediana)
- Distribuição de códigos de status
- Tipos de conteúdo
- Performance de I/O
- Uso de memória

Eventos Disponíveis:
- scan_start: Início do scan
- scan_end: Fim do scan
- result_found: Resultado encontrado
- result_error: Erro no processamento
- report_start: Início da geração de relatório
- report_end: Fim da geração de relatório
- cleanup_start: Início da limpeza
- cleanup_end: Fim da limpeza
- error: Erro geral

Para mais informações, consulte a documentação completa em:
https://github.com/seu-usuario/dnsbrute/docs/plugins/report.md
"""

import json
import logging
import shutil
import gzip
import csv
import re
import io
import threading
import queue
import time
import psutil
import importlib.util
from datetime import datetime, timedelta
from typing import Dict, List, Optional, Any, Union, Set, Callable
from pathlib import Path
from dataclasses import dataclass, field, asdict
from collections import defaultdict
import jinja2
import statistics
from abc import ABC, abstractmethod
from functools import lru_cache
from concurrent.futures import ThreadPoolExecutor
import yaml

# Configurações do plugin
DEFAULT_CONFIG = {
    'reports': {
        'max_reports': 100,
        'max_dir_size_mb': 500,
        'max_age_days': 30,
        'compression_threshold_mb': 1,
        'buffer_size': 8192,
        'max_write_queue': 1000,
        'write_batch_size': 10,
        'write_interval_seconds': 5
    },
    'formats': {
        'enabled': ['json', 'html', 'csv'],
        'default': 'json',
        'compression': True
    },
    'profiles': {
        'minimal': {
            'metrics': ['total_requests', 'found_count', 'errors'],
            'formats': ['json']
        },
        'standard': {
            'metrics': ['total_requests', 'found_count', 'errors', 'response_times', 'status_codes'],
            'formats': ['json', 'html']
        },
        'complete': {
            'metrics': ['*'],
            'formats': ['*']
        }
    },
    'validation': {
        'max_target_length': 2048,
        'allowed_schemes': ['http', 'https'],
        'allowed_status_codes': range(100, 600),
        'max_content_type_length': 256
    }
}

@dataclass
class ValidationConfig:
    """Configuração de validação"""
    max_target_length: int
    allowed_schemes: Set[str]
    allowed_status_codes: range
    max_content_type_length: int

@dataclass
class ReportConfig:
    """Configuração de relatórios"""
    max_reports: int
    max_dir_size_mb: int
    max_age_days: int
    compression_threshold_mb: int
    buffer_size: int
    max_write_queue: int
    write_batch_size: int
    write_interval_seconds: int

@dataclass
class FormatConfig:
    """Configuração de formatos"""
    enabled: List[str]
    default: str
    compression: bool

@dataclass
class ProfileConfig:
    """Configuração de perfil"""
    metrics: List[str]
    formats: List[str]

@dataclass
class PluginConfig:
    """Configuração completa do plugin"""
    reports: ReportConfig
    formats: FormatConfig
    profiles: Dict[str, ProfileConfig]
    validation: ValidationConfig
    
    @classmethod
    def from_dict(cls, data: Dict) -> 'PluginConfig':
        """Cria configuração a partir de dicionário"""
        return cls(
            reports=ReportConfig(**data['reports']),
            formats=FormatConfig(**data['formats']),
            profiles={k: ProfileConfig(**v) for k, v in data['profiles'].items()},
            validation=ValidationConfig(**data['validation'])
        )
    
    @classmethod
    def load(cls, config_path: Optional[Path] = None) -> 'PluginConfig':
        """Carrega configuração de arquivo ou usa padrão"""
        if config_path and config_path.exists():
            with open(config_path) as f:
                config_data = yaml.safe_load(f)
        else:
            config_data = DEFAULT_CONFIG
        return cls.from_dict(config_data)

class WriteBuffer:
    """Buffer para escritas em arquivo"""
    def __init__(self, max_size: int = 1000):
        self.buffer = queue.Queue(maxsize=max_size)
        self.lock = threading.Lock()
        self.running = True
        self.worker = threading.Thread(target=self._worker, daemon=True)
        self.worker.start()
    
    def write(self, file_path: Path, content: str):
        """Adiciona conteúdo ao buffer"""
        self.buffer.put((file_path, content))
    
    def _worker(self):
        """Worker thread para processar escritas"""
        batch = []
        while self.running:
            try:
                # Coleta itens do buffer
                while len(batch) < 10:
                    try:
                        item = self.buffer.get(timeout=5)
                        batch.append(item)
                    except queue.Empty:
                        break
                
                if batch:
                    # Processa o batch
                    with ThreadPoolExecutor(max_workers=4) as executor:
                        futures = []
                        for file_path, content in batch:
                            futures.append(
                                executor.submit(self._write_file, file_path, content)
                            )
                        # Aguarda conclusão
                        for future in futures:
                            future.result()
                    batch.clear()
                    
            except Exception as e:
                logging.error(f"Erro no worker de escrita: {e}")
    
    def _write_file(self, file_path: Path, content: str):
        """Escreve conteúdo em arquivo"""
        temp_path = file_path.with_suffix('.tmp')
        try:
            with self.lock:
                with open(temp_path, 'w', encoding='utf-8') as f:
                    f.write(content)
                temp_path.rename(file_path)
        except Exception:
            if temp_path.exists():
                temp_path.unlink()
            raise
    
    def stop(self):
        """Para o worker thread"""
        self.running = False
        self.worker.join()

class ResultValidator:
    """Validador de resultados"""
    def __init__(self, config: ValidationConfig):
        self.config = config
    
    def validate_target(self, target: str) -> bool:
        """Valida URL alvo"""
        if not target or len(target) > self.config.max_target_length:
            return False
        
        # Valida esquema
        match = re.match(r'^(https?)://', target.lower())
        if not match or match.group(1) not in self.config.allowed_schemes:
            return False
        
        # Valida caracteres
        if not re.match(r'^[\w\-\./:%]+$', target):
            return False
        
        return True
    
    def validate_status_code(self, status_code: int) -> bool:
        """Valida código de status"""
        return status_code in self.config.allowed_status_codes
    
    def validate_content_type(self, content_type: str) -> bool:
        """Valida content type"""
        if not content_type or len(content_type) > self.config.max_content_type_length:
            return False
        
        # Valida formato
        return bool(re.match(r'^[\w\-\./+]+$', content_type))
    
    def validate_result(self, result: Dict) -> bool:
        """Valida resultado completo"""
        try:
            # Campos obrigatórios
            if not all(k in result for k in {'target', 'status_code', 'content_type'}):
                return False
            
            # Validação de tipos
            if not isinstance(result['target'], str):
                return False
            if not isinstance(result['status_code'], int):
                return False
            if not isinstance(result['content_type'], str):
                return False
            
            # Validação de valores
            if not self.validate_target(result['target']):
                return False
            if not self.validate_status_code(result['status_code']):
                return False
            if not self.validate_content_type(result['content_type']):
                return False
            
            # Validação de campos opcionais
            if 'response_time' in result:
                if not isinstance(result['response_time'], (int, float)):
                    return False
                if result['response_time'] < 0:
                    return False
            
            return True
            
        except Exception as e:
            logging.error(f"Erro na validação: {e}")
            return False

@dataclass
class ScanMetrics:
    """Métricas detalhadas do scan"""
    total_requests: int = 0
    found_count: int = 0
    errors: int = 0
    start_time: Optional[datetime] = None
    end_time: Optional[datetime] = None
    response_times: List[float] = field(default_factory=list)
    status_codes: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    content_types: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    patterns: Dict[str, int] = field(default_factory=lambda: defaultdict(int))
    
    @property
    def avg_response_time(self) -> float:
        """Tempo médio de resposta"""
        return statistics.mean(self.response_times) if self.response_times else 0
    
    @property
    def median_response_time(self) -> float:
        """Mediana do tempo de resposta"""
        return statistics.median(self.response_times) if self.response_times else 0
    
    @property
    def duration(self) -> timedelta:
        """Duração total do scan"""
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return timedelta()

class ReportFormatter(ABC):
    """Classe base para formatadores de relatório"""
    def __init__(self):
        self._template_cache = {}
    
    @abstractmethod
    def format(self, data: Dict) -> str:
        """Formata os dados do relatório"""
        pass
    
    @lru_cache(maxsize=32)
    def _get_template(self, template_key: str) -> Any:
        """Obtém template do cache"""
        return self._template_cache.get(template_key)

class JSONFormatter(ReportFormatter):
    """Formatador JSON"""
    def format(self, data: Dict) -> str:
        return json.dumps(data, indent=2, default=str)

class HTMLFormatter(ReportFormatter):
    """Formatador HTML usando templates Jinja2"""
    def __init__(self):
        super().__init__()
        self._env = jinja2.Environment(
            autoescape=True,
            trim_blocks=True,
            lstrip_blocks=True
        )
        self._template = self._env.from_string("""
        <!DOCTYPE html>
        <html>
        <head>
            <title>DNS Brute Report</title>
            <style>
                body { font-family: Arial, sans-serif; margin: 20px; }
                .metric { margin: 10px 0; }
                .results { margin-top: 20px; }
                table { border-collapse: collapse; width: 100%; }
                th, td { border: 1px solid #ddd; padding: 8px; text-align: left; }
                th { background-color: #f5f5f5; }
                .chart { margin: 20px 0; }
            </style>
        </head>
        <body>
            <h1>DNS Brute Scan Report</h1>
            
            <h2>Scan Information</h2>
            <div class="metric">Start Time: {{ metrics.start_time }}</div>
            <div class="metric">Duration: {{ metrics.duration }}</div>
            <div class="metric">Total Requests: {{ metrics.total_requests }}</div>
            <div class="metric">Found: {{ metrics.found_count }}</div>
            <div class="metric">Errors: {{ metrics.errors }}</div>
            
            <h2>Performance Metrics</h2>
            <div class="metric">Average Response Time: {{ "%.2f"|format(metrics.avg_response_time) }}s</div>
            <div class="metric">Median Response Time: {{ "%.2f"|format(metrics.median_response_time) }}s</div>
            
            <h2>Status Codes Distribution</h2>
            <table>
                <tr><th>Status</th><th>Count</th></tr>
                {% for status, count in metrics.status_codes.items() %}
                <tr><td>{{ status }}</td><td>{{ count }}</td></tr>
                {% endfor %}
            </table>
            
            <h2>Content Types Distribution</h2>
            <table>
                <tr><th>Type</th><th>Count</th></tr>
                {% for type, count in metrics.content_types.items() %}
                <tr><td>{{ type }}</td><td>{{ count }}</td></tr>
                {% endfor %}
            </table>
            
            <h2>Results</h2>
            <table class="results">
                <tr>
                    <th>Target</th>
                    <th>Status</th>
                    <th>Content Type</th>
                    <th>Response Time</th>
                </tr>
                {% for result in results %}
                <tr>
                    <td>{{ result.target }}</td>
                    <td>{{ result.status_code }}</td>
                    <td>{{ result.content_type }}</td>
                    <td>{{ "%.2f"|format(result.response_time) }}s</td>
                </tr>
                {% endfor %}
            </table>
        </body>
        </html>
        """)
    
    @lru_cache(maxsize=1)
    def get_template(self) -> jinja2.Template:
        """Obtém template do cache"""
        return self._template
    
    def format(self, data: Dict) -> str:
        template = self.get_template()
        return template.render(**data)

class CSVFormatter(ReportFormatter):
    """Formatador CSV"""
    def format(self, data: Dict) -> str:
        output = io.StringIO()
        writer = csv.writer(output)
        
        # Cabeçalho
        headers = ['target', 'status_code', 'content_type', 'response_time']
        writer.writerow(headers)
        
        # Resultados
        for result in data['results']:
            row = [
                result['target'],
                result['status_code'],
                result['content_type'],
                f"{result.get('response_time', 0):.2f}"
            ]
            writer.writerow(row)
        
        return output.getvalue()

class EventEmitter:
    """Sistema de eventos do plugin"""
    
    def __init__(self):
        self._handlers: Dict[str, List[Callable]] = defaultdict(list)
        self._metrics: Dict[str, List[float]] = defaultdict(list)
    
    def on(self, event: str, handler: Callable) -> None:
        """Registra um handler para um evento"""
        self._handlers[event].append(handler)
    
    def off(self, event: str, handler: Callable) -> None:
        """Remove um handler de um evento"""
        if event in self._handlers:
            self._handlers[event].remove(handler)
    
    def emit(self, event: str, data: Any = None) -> None:
        """Emite um evento com dados opcionais"""
        start_time = time.time()
        try:
            for handler in self._handlers.get(event, []):
                try:
                    handler(data)
                except Exception as e:
                    logging.error(f"Erro no handler de {event}: {e}")
        finally:
            duration = time.time() - start_time
            self._metrics[event].append(duration)
    
    def get_metrics(self) -> Dict[str, Dict[str, float]]:
        """Retorna métricas de eventos"""
        metrics = {}
        for event, durations in self._metrics.items():
            if durations:
                metrics[event] = {
                    'count': len(durations),
                    'avg_duration': statistics.mean(durations),
                    'max_duration': max(durations),
                    'min_duration': min(durations)
                }
        return metrics

class PerformanceMetrics:
    """Coletor de métricas de performance"""
    
    def __init__(self):
        self.start_time = time.time()
        self.metrics: Dict[str, Any] = defaultdict(list)
        self._process = psutil.Process()
    
    def collect(self) -> Dict[str, Any]:
        """Coleta métricas atuais"""
        try:
            cpu_percent = self._process.cpu_percent()
            memory_info = self._process.memory_info()
            io_counters = self._process.io_counters()
            
            self.metrics['cpu_percent'].append(cpu_percent)
            self.metrics['memory_rss'].append(memory_info.rss)
            self.metrics['memory_vms'].append(memory_info.vms)
            self.metrics['io_read_bytes'].append(io_counters.read_bytes)
            self.metrics['io_write_bytes'].append(io_counters.write_bytes)
            
            return {
                'current': {
                    'cpu_percent': cpu_percent,
                    'memory_mb': memory_info.rss / 1024 / 1024,
                    'io_read_mb': io_counters.read_bytes / 1024 / 1024,
                    'io_write_mb': io_counters.write_bytes / 1024 / 1024
                },
                'averages': {
                    'cpu_percent': statistics.mean(self.metrics['cpu_percent']),
                    'memory_mb': statistics.mean(self.metrics['memory_rss']) / 1024 / 1024,
                    'io_read_mb': statistics.mean(self.metrics['io_read_bytes']) / 1024 / 1024,
                    'io_write_mb': statistics.mean(self.metrics['io_write_bytes']) / 1024 / 1024
                },
                'duration': time.time() - self.start_time
            }
        except Exception as e:
            logging.error(f"Erro ao coletar métricas: {e}")
            return {}

class Plugin:
    """Plugin avançado para geração de relatórios detalhados"""
    
    def __init__(self):
        """Inicializa o plugin com sistema de eventos e métricas"""
        self.report_dir = Path.home() / '.dnsbrute' / 'reports'
        self.config_file = self.report_dir / 'config.yaml'
        self.current_scan: Optional[Dict] = None
        self.metrics: Optional[ScanMetrics] = None
        self.config = self._load_config()
        self.validator = ResultValidator(self.config.validation)
        self.write_buffer = WriteBuffer(self.config.reports.max_write_queue)
        self.formatters = {
            'json': JSONFormatter(),
            'html': HTMLFormatter(),
            'csv': CSVFormatter()
        }
        self.events = EventEmitter()
        self.performance = PerformanceMetrics()
        self._setup_logging()
        self._setup_default_handlers()
    
    def _load_config(self) -> PluginConfig:
        """Carrega e valida configuração"""
        try:
            config = PluginConfig.load(self.config_file)
            self._validate_config(config)
            return config
        except Exception as e:
            logging.error(f"Erro ao carregar configuração: {e}")
            return PluginConfig.from_dict(DEFAULT_CONFIG)
    
    def _validate_config(self, config: PluginConfig) -> None:
        """Valida a configuração carregada"""
        # Validação de reports
        assert config.reports.max_reports > 0, "max_reports deve ser positivo"
        assert config.reports.max_dir_size_mb > 0, "max_dir_size_mb deve ser positivo"
        assert config.reports.max_age_days > 0, "max_age_days deve ser positivo"
        
        # Validação de formatos
        assert config.formats.enabled, "Deve haver pelo menos um formato habilitado"
        assert config.formats.default in config.formats.enabled, "Formato padrão deve estar habilitado"
        
        # Validação de perfis
        for profile in config.profiles.values():
            assert profile.metrics, "Perfil deve ter pelo menos uma métrica"
            assert profile.formats, "Perfil deve ter pelo menos um formato"
            
            # Valida formatos do perfil
            if '*' not in profile.formats:
                invalid_formats = set(profile.formats) - set(config.formats.enabled)
                assert not invalid_formats, f"Formatos inválidos no perfil: {invalid_formats}"
    
    def _setup_default_handlers(self):
        """Configura handlers padrão para eventos"""
        self.events.on('scan_start', lambda data: logging.info(f"Scan iniciado: {data}"))
        self.events.on('scan_end', lambda data: logging.info(f"Scan finalizado: {data}"))
        self.events.on('result_found', lambda data: logging.info(f"Encontrado: {data['target']}"))
        self.events.on('error', lambda data: logging.error(f"Erro: {data}"))
    
    def on(self, event: str, handler: Callable) -> None:
        """Registra um handler para um evento"""
        self.events.on(event, handler)
    
    def off(self, event: str, handler: Callable) -> None:
        """Remove um handler de um evento"""
        self.events.off(event, handler)
    
    def get_metrics(self) -> Dict[str, Any]:
        """Retorna todas as métricas coletadas"""
        return {
            'scan': asdict(self.metrics) if self.metrics else {},
            'events': self.events.get_metrics(),
            'performance': self.performance.collect()
        }
    
    def set_profile(self, profile_name: str) -> None:
        """Define o perfil ativo"""
        if profile_name not in self.config.profiles:
            raise ValueError(f"Perfil não encontrado: {profile_name}")
        if self.current_scan:
            self.current_scan['config']['profile'] = profile_name
    
    def _setup_logging(self):
        """Configura logging específico do plugin"""
        self.logger = logging.getLogger('dnsbrute.report_plugin')
        if not self.logger.handlers:
            handler = logging.FileHandler(self.report_dir / 'plugin.log')
            formatter = logging.Formatter(
                '%(asctime)s - %(name)s - %(levelname)s - %(message)s'
            )
            handler.setFormatter(formatter)
            self.logger.addHandler(handler)
            self.logger.setLevel(logging.INFO)
    
    def on_load(self):
        """Inicialização do plugin"""
        try:
            self.report_dir.mkdir(parents=True, exist_ok=True)
            self._cleanup_old_reports()
            self.logger.info("Plugin inicializado com sucesso")
        except Exception as e:
            self.logger.error(f"Erro na inicialização do plugin: {e}")
            raise
    
    def _cleanup_old_reports(self):
        """Limpa relatórios antigos e mantém o diretório dentro dos limites"""
        try:
            # Remove relatórios antigos
            now = datetime.now()
            for report in self.report_dir.glob('*.*'):
                if report.suffix in {'.json', '.html', '.csv', '.gz'}:
                    age = now - datetime.fromtimestamp(report.stat().st_mtime)
                    if age.days > self.config.reports.max_age_days:
                        report.unlink()
                        self.logger.info(f"Relatório antigo removido: {report}")
            
            # Verifica tamanho do diretório
            total_size = sum(f.stat().st_size for f in self.report_dir.glob('*.*'))
            if total_size > self.config.reports.max_dir_size_mb * 1024 * 1024:
                # Remove relatórios mais antigos até atingir o limite
                reports = sorted(
                    self.report_dir.glob('*.*'),
                    key=lambda x: x.stat().st_mtime
                )
                for report in reports:
                    if total_size <= self.config.reports.max_dir_size_mb * 1024 * 1024:
                        break
                    size = report.stat().st_size
                    report.unlink()
                    total_size -= size
                    self.logger.info(f"Relatório removido por limite de tamanho: {report}")
            
            # Limita número de relatórios
            reports = sorted(
                self.report_dir.glob('*.*'),
                key=lambda x: x.stat().st_mtime,
                reverse=True
            )
            for report in reports[self.config.reports.max_reports:]:
                report.unlink()
                self.logger.info(f"Relatório removido por limite de quantidade: {report}")
                
        except Exception as e:
            self.logger.error(f"Erro na limpeza de relatórios: {e}")
    
    def pre_scan(self, config: Dict) -> Dict:
        """Prepara o scan e inicializa métricas"""
        try:
            self.events.emit('scan_start', config)
            self.metrics = ScanMetrics()
            self.metrics.start_time = datetime.now()
            
            self.current_scan = {
                'config': config,
                'results': [],
                'metrics': self.metrics
            }
            
            return config
            
        except Exception as e:
            self.events.emit('error', str(e))
            return config
    
    def on_result(self, result: Dict) -> Dict:
        """Processa e valida cada resultado"""
        try:
            if not self.metrics or not self.validator.validate_result(result):
                self.events.emit('result_error', result)
                return result
            
            # Atualiza métricas
            self.metrics.total_requests += 1
            
            if result.get('found'):
                self.metrics.found_count += 1
                self.current_scan['results'].append(result)
                self.events.emit('result_found', result)
            elif result['status_code'] == 0:
                self.metrics.errors += 1
                self.events.emit('result_error', result)
            
            # Coleta métricas de performance periodicamente
            if self.metrics.total_requests % 100 == 0:
                self.performance.collect()
            
            return result
            
        except Exception as e:
            self.events.emit('error', str(e))
            return result
    
    def post_scan(self, results: List[Dict]) -> List[Dict]:
        """Finaliza o scan e gera relatórios"""
        if not self.current_scan:
            return results
            
        try:
            self.metrics.end_time = datetime.now()
            self.events.emit('scan_end', self.get_metrics())
            
            # Gera relatórios
            self.events.emit('report_start')
            timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
            base_name = f'report_{timestamp}'
            
            profile = self.config.profiles.get(
                self.current_scan['config'].get('profile', 'standard')
            )
            
            if profile:
                formats = (
                    self.config.formats.enabled 
                    if '*' in profile.formats 
                    else profile.formats
                )
                
                for fmt in formats:
                    if fmt in self.formatters:
                        self._save_report(base_name, fmt, self.formatters[fmt])
            
            self.events.emit('report_end')
            return results
            
        except Exception as e:
            self.events.emit('error', str(e))
            return results
        finally:
            self.current_scan = None
            self.metrics = None
    
    def cleanup(self) -> None:
        """Executa limpeza manual"""
        try:
            self.events.emit('cleanup_start')
            self._cleanup_old_reports()
            self.events.emit('cleanup_end')
        except Exception as e:
            self.events.emit('error', str(e))
    
    def __del__(self):
        """Cleanup ao destruir o objeto"""
        if hasattr(self, 'write_buffer'):
            self.write_buffer.stop()
    
    def _save_report(self, base_name: str, format: str, formatter: ReportFormatter):
        """Salva o relatório em um formato específico"""
        try:
            # Prepara os dados conforme perfil
            profile = self.config.profiles.get(
                self.current_scan['config'].get('profile', 'standard')
            )
            
            data = {
                'metrics': self.metrics,
                'results': self.current_scan['results'],
                'config': self.current_scan['config']
            }
            
            if profile and '*' not in profile.metrics:
                # Filtra métricas conforme perfil
                filtered_metrics = {
                    k: v for k, v in asdict(self.metrics).items()
                    if k in profile.metrics
                }
                data['metrics'] = filtered_metrics
            
            # Formata o conteúdo
            content = formatter.format(data)
            
            # Define o caminho do arquivo
            file_path = self.report_dir / f'{base_name}.{format}'
            
            # Verifica se deve comprimir
            content_size = len(content.encode())
            should_compress = (
                self.config.formats.compression and
                content_size > self.config.reports.compression_threshold_mb * 1024 * 1024
            )
            
            if should_compress:
                file_path = file_path.with_suffix(f'.{format}.gz')
                # Comprime e envia para o buffer
                buffer = io.BytesIO()
                with gzip.GzipFile(fileobj=buffer, mode='wb') as gz:
                    gz.write(content.encode())
                self.write_buffer.write(file_path, buffer.getvalue().decode())
            else:
                # Envia para o buffer
                self.write_buffer.write(file_path, content)
            
            self.logger.info(f"Relatório enviado para buffer: {file_path}")
            
        except Exception as e:
            self.logger.error(f"Erro ao salvar relatório {format}: {e}")
            # Tenta salvar em formato simples como fallback
            self._write_fallback(data, base_name, format)
    
    def _write_fallback(self, data: Dict, base_name: str, format: str):
        """Escrita de fallback em caso de erro"""
        try:
            fallback_path = self.report_dir / f'{base_name}_fallback.txt'
            with open(fallback_path, 'w', encoding='utf-8') as f:
                f.write(f"FALLBACK REPORT (original format: {format})\n")
                f.write("=" * 50 + "\n")
                f.write(f"Metrics:\n{str(data['metrics'])}\n\n")
                f.write(f"Results Count: {len(data['results'])}\n")
            self.logger.info(f"Relatório de fallback salvo: {fallback_path}")
        except Exception as e:
            self.logger.error(f"Erro ao salvar fallback: {e}")