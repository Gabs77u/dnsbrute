"""
Testes unitários para o plugin de relatórios
"""

import unittest
import tempfile
from pathlib import Path
from datetime import datetime
from unittest.mock import Mock, patch
from report_plugin import (
    Plugin, PluginConfig, ResultValidator, WriteBuffer,
    JSONFormatter, HTMLFormatter, CSVFormatter
)

class TestResultValidator(unittest.TestCase):
    """Testes para o validador de resultados"""
    
    def setUp(self):
        self.config = Mock(
            max_target_length=2048,
            allowed_schemes={'http', 'https'},
            allowed_status_codes=range(100, 600),
            max_content_type_length=256
        )
        self.validator = ResultValidator(self.config)
    
    def test_validate_target(self):
        """Testa validação de URLs"""
        # URLs válidas
        self.assertTrue(self.validator.validate_target('http://example.com'))
        self.assertTrue(self.validator.validate_target('https://sub.domain.com/path'))
        
        # URLs inválidas
        self.assertFalse(self.validator.validate_target('ftp://example.com'))
        self.assertFalse(self.validator.validate_target('http://' + 'a' * 2049))
        self.assertFalse(self.validator.validate_target('http://invalid chars'))
    
    def test_validate_status_code(self):
        """Testa validação de códigos de status"""
        # Códigos válidos
        self.assertTrue(self.validator.validate_status_code(200))
        self.assertTrue(self.validator.validate_status_code(404))
        self.assertTrue(self.validator.validate_status_code(500))
        
        # Códigos inválidos
        self.assertFalse(self.validator.validate_status_code(99))
        self.assertFalse(self.validator.validate_status_code(600))
        self.assertFalse(self.validator.validate_status_code(-1))
    
    def test_validate_content_type(self):
        """Testa validação de content types"""
        # Content types válidos
        self.assertTrue(self.validator.validate_content_type('text/html'))
        self.assertTrue(self.validator.validate_content_type('application/json'))
        
        # Content types inválidos
        self.assertFalse(self.validator.validate_content_type(''))
        self.assertFalse(self.validator.validate_content_type('a' * 257))
        self.assertFalse(self.validator.validate_content_type('invalid/type!'))

class TestWriteBuffer(unittest.TestCase):
    """Testes para o buffer de escrita"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        self.buffer = WriteBuffer(max_size=10)
    
    def tearDown(self):
        self.buffer.stop()
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_write_file(self):
        """Testa escrita de arquivo"""
        test_file = Path(self.temp_dir) / 'test.txt'
        content = 'test content'
        
        # Testa escrita síncrona
        self.buffer._write_file(test_file, content)
        self.assertTrue(test_file.exists())
        self.assertEqual(test_file.read_text(), content)
    
    def test_batch_processing(self):
        """Testa processamento em lote"""
        files = []
        for i in range(5):
            test_file = Path(self.temp_dir) / f'test_{i}.txt'
            self.buffer.write(test_file, f'content {i}')
            files.append(test_file)
        
        # Aguarda processamento
        import time
        time.sleep(1)
        
        # Verifica arquivos
        for i, file in enumerate(files):
            self.assertTrue(file.exists())
            self.assertEqual(file.read_text(), f'content {i}')

class TestFormatters(unittest.TestCase):
    """Testes para os formatadores"""
    
    def setUp(self):
        self.test_data = {
            'metrics': {
                'total_requests': 100,
                'found_count': 50,
                'errors': 5,
                'start_time': datetime.now(),
                'status_codes': {'200': 45, '404': 5}
            },
            'results': [
                {
                    'target': 'http://example.com',
                    'status_code': 200,
                    'content_type': 'text/html',
                    'response_time': 0.5
                }
            ]
        }
    
    def test_json_formatter(self):
        """Testa formatador JSON"""
        formatter = JSONFormatter()
        output = formatter.format(self.test_data)
        
        # Verifica se é JSON válido
        import json
        data = json.loads(output)
        self.assertEqual(data['metrics']['total_requests'], 100)
    
    def test_html_formatter(self):
        """Testa formatador HTML"""
        formatter = HTMLFormatter()
        output = formatter.format(self.test_data)
        
        # Verifica elementos HTML básicos
        self.assertIn('<!DOCTYPE html>', output)
        self.assertIn('Total Requests: 100', output)
        self.assertIn('http://example.com', output)
    
    def test_csv_formatter(self):
        """Testa formatador CSV"""
        formatter = CSVFormatter()
        output = formatter.format(self.test_data)
        
        # Verifica formato CSV
        lines = output.strip().split('\n')
        self.assertEqual(len(lines), 2)  # Header + 1 resultado
        self.assertIn('target,status_code,content_type,response_time', lines[0])

class TestPlugin(unittest.TestCase):
    """Testes para o plugin principal"""
    
    def setUp(self):
        self.temp_dir = tempfile.mkdtemp()
        with patch('pathlib.Path.home') as mock_home:
            mock_home.return_value = Path(self.temp_dir)
            self.plugin = Plugin()
    
    def tearDown(self):
        import shutil
        shutil.rmtree(self.temp_dir)
    
    def test_initialization(self):
        """Testa inicialização do plugin"""
        self.assertIsNotNone(self.plugin.config)
        self.assertIsNotNone(self.plugin.validator)
        self.assertIsNotNone(self.plugin.write_buffer)
    
    def test_process_result(self):
        """Testa processamento de resultado"""
        self.plugin.pre_scan({'mode': 'test'})
        
        result = {
            'target': 'http://example.com',
            'status_code': 200,
            'content_type': 'text/html',
            'response_time': 0.5,
            'found': True
        }
        
        processed = self.plugin.on_result(result)
        self.assertEqual(processed, result)
        self.assertEqual(self.plugin.metrics.total_requests, 1)
        self.assertEqual(self.plugin.metrics.found_count, 1)
    
    def test_cleanup(self):
        """Testa limpeza de arquivos antigos"""
        # Cria alguns arquivos de teste
        report_dir = Path(self.temp_dir) / '.dnsbrute' / 'reports'
        report_dir.mkdir(parents=True)
        
        for i in range(5):
            (report_dir / f'test_{i}.json').write_text('test')
        
        self.plugin._cleanup_old_reports()
        
        # Verifica se os arquivos ainda existem (são novos)
        self.assertEqual(len(list(report_dir.glob('*.json'))), 5)

if __name__ == '__main__':
    unittest.main() 