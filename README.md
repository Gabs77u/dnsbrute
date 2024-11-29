# DNSBrute v2.2.0

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Python](https://img.shields.io/badge/python-3.8%2B-blue)

Uma ferramenta avançada para enumeração de subdomínios e diretórios, com recursos de relatórios detalhados e análise de resultados.

## 🚀 Novos Recursos (v2.1.0)

- Sistema de plugins extensível
- Relatórios detalhados em múltiplos formatos
- Cache e otimização de memória
- Validação robusta de dados
- Sistema de eventos e métricas
- Interface interativa melhorada
- Suporte a perfis de configuração
- Compressão automática de relatórios

## 📋 Requisitos

- Python 3.8 ou superior
- pip (gerenciador de pacotes Python)
- Git (para clonar o repositório)

## 🔧 Instalação

1. Clone o repositório:
```bash
git clone https://github.com/seu-usuario/dnsbrute.git
cd dnsbrute
```

2. Instale as dependências:
```bash
pip install -r requirements.txt
```

## 💻 Uso Básico

### Linha de Comando

```bash
# Scan básico de subdomínios
python dnsbrute.py -u example.com -w wordlist.txt

# Scan de diretórios
python dnsbrute.py -u example.com -w wordlist.txt -m directory

# Scan com relatório detalhado
python dnsbrute.py -u example.com -w wordlist.txt --report report.html
```

### Interface Interativa

```bash
python dnsbrute.py --interactive
```

## ⚙️ Configuração

### Perfis Disponíveis

- **minimal**: Relatório básico em JSON
- **standard**: Relatório detalhado em JSON e HTML
- **complete**: Todas as métricas e formatos

### Arquivo de Configuração (config.yaml)

```yaml
reports:
  max_reports: 100
  max_dir_size_mb: 500
  compression: true

formats:
  enabled: [json, html, csv]
  default: json

validation:
  max_target_length: 2048
  allowed_schemes: [http, https]
```

## 📊 Relatórios

### Formatos Suportados

- **JSON**: Dados estruturados para análise
- **HTML**: Relatório visual interativo
- **CSV**: Dados tabulares para planilhas

### Métricas Coletadas

- Tempo de resposta (média/mediana)
- Distribuição de códigos HTTP
- Tipos de conteúdo
- Performance do sistema
- Uso de recursos

## 🔌 Sistema de Plugins

### Criando um Plugin

```python
class MeuPlugin:
    def on_load(self):
        """Chamado ao carregar o plugin"""
        pass
    
    def pre_scan(self, config):
        """Antes do scan"""
        return config
    
    def on_result(self, result):
        """Para cada resultado"""
        return result
    
    def post_scan(self, results):
        """Após o scan"""
        return results
```

### Eventos Disponíveis

- `scan_start`: Início do scan
- `result_found`: Resultado encontrado
- `scan_end`: Fim do scan
- `report_generated`: Relatório gerado

## 🛠️ Opções Avançadas

### Argumentos da Linha de Comando

| Argumento | Descrição | Padrão |
|-----------|-----------|---------|
| -u, --url | URL alvo | - |
| -w, --wordlist | Arquivo wordlist | - |
| -t, --threads | Número de threads | 10 |
| -m, --mode | Modo (subdomain/directory) | subdomain |
| --timeout | Timeout em segundos | 5 |
| --profile | Perfil de relatório | standard |

### Variáveis de Ambiente

- `DNSBRUTE_CONFIG`: Caminho do arquivo de configuração
- `DNSBRUTE_PROFILE`: Perfil padrão
- `DNSBRUTE_DEBUG`: Ativa logs de debug

## 📝 Exemplos de Uso

### 1. Scan Básico
```bash
python dnsbrute.py -u example.com -w common.txt
```

### 2. Scan Completo com Relatório
```bash
python dnsbrute.py -u example.com -w large.txt \
    --profile complete \
    --report scan_report.html \
    --threads 20 \
    --timeout 10
```

### 3. Modo Diretório com Filtros
```bash
python dnsbrute.py -u example.com -w dirs.txt \
    -m directory \
    --status-codes 200,301,403 \
    --content-types html,json
```

## 🔍 Resolução de Problemas

### Problemas Comuns

1. **Erro de memória**
   - Reduza o tamanho do batch
   - Use o perfil minimal
   - Ative a compressão

2. **Timeouts frequentes**
   - Aumente o valor de timeout
   - Reduza o número de threads
   - Verifique a conexão

3. **Arquivos de relatório grandes**
   - Use compressão automática
   - Selecione métricas específicas
   - Limpe relatórios antigos

## 🤝 Contribuindo

1. Fork o projeto
2. Crie sua branch (`git checkout -b feature/nova-feature`)
3. Commit suas mudanças (`git commit -m 'Adiciona nova feature'`)
4. Push para a branch (`git push origin feature/nova-feature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 📬 Contato

- Autor: Gabs77u
- GitHub: [@seu-usuario](https://github.com/seu-usuario)
- Email: seu-email@example.com

## 🙏 Agradecimentos

- Contribuidores do projeto
- Comunidade Python
- Usuários que reportam bugs e sugerem melhorias

