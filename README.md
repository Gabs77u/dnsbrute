# DNSBrute v2.1.0

<div align="center">

![DNSBrute Logo](https://raw.githubusercontent.com/gabs77u/dnsbrute/main/assets/logo.png)

[![Python 3.6+](https://img.shields.io/badge/python-3.6+-blue.svg)](https://www.python.org/downloads/)
[![License](https://img.shields.io/badge/license-MIT-green.svg)](LICENSE)
[![Version](https://img.shields.io/badge/version-2.1.0-red.svg)](https://github.com/gabs77u/dnsbrute)

</div>

> DNSBrute é uma ferramenta avançada de descoberta de diretórios e subdomínios em aplicações web através de ataques de força bruta.

## 📋 Índice

- [Novidades da Versão 2.1.0](#-novidades-da-versão-210)
- [Recursos](#-recursos)
- [Requisitos](#-requisitos)
- [Instalação](#-instalação)
- [Modo de Uso](#-modo-de-uso)
- [Exemplos Práticos](#-exemplos-práticos)
- [Configurações Avançadas](#-configurações-avançadas)
- [FAQ](#-faq)
- [Contribuindo](#-contribuindo)
- [Licença](#-licença)

## 🚀 Novidades da Versão 2.1.0

### Melhorias de Performance
- Sistema de cache para otimização de requisições
- Gerenciamento eficiente de recursos de rede
- Suporte a multithreading configurável
- Mecanismo de retry para falhas de conexão

### Novas Funcionalidades
- Interface ASCII interativa
- Suporte a múltiplos formatos de saída (JSON, CSV, texto)
- Modo de descoberta de subdomínios
- Sistema de logging avançado
- Suporte a proxy
- Validação rigorosa de URLs e entradas

### Segurança
- Validação de certificados SSL
- Proteção contra ataques comuns
- Tratamento seguro de credenciais
- Sanitização de inputs

### Interface
- Menu interativo com ASCII art
- Barra de progresso em tempo real
- Relatórios formatados
- Modo verboso para debugging

## 💻 Recursos

- **Modos de Operação**
  - Descoberta de diretórios
  - Descoberta de subdomínios
  - Modo interativo ou linha de comando

- **Personalização**
  - Número de threads configurável
  - Delay entre requisições
  - User-Agent customizável
  - Timeout configurável

- **Saída de Dados**
  - Formato JSON
  - Formato CSV
  - Texto plano
  - Relatórios detalhados

## 📦 Requisitos

- Python 3.6+
- pip (gerenciador de pacotes Python)
- Bibliotecas necessárias (instaladas automaticamente):
  - requests
  - argparse
  - logging

## 🔧 Instalação

```bash
# Clone o repositório
git clone https://github.com/gabs77u/dnsbrute.git

# Entre no diretório
cd dnsbrute

# Instale as dependências
pip install -r requirements.txt
```

## 📖 Modo de Uso

### Modo Interativo

Execute o programa sem argumentos para iniciar o modo interativo:

```bash
python dnsbrute.py
```

### Linha de Comando

```bash
python dnsbrute.py -u URL -w WORDLIST [opções]
```

#### Opções Disponíveis

| Opção | Descrição | Padrão |
|-------|-----------|--------|
| -u, --url | URL alvo | Obrigatório |
| -w, --wordlist | Arquivo de wordlist | Obrigatório |
| -t, --threads | Número de threads | 10 |
| -d, --delay | Delay entre requisições (segundos) | 0 |
| -o, --output | Arquivo de saída | stdout |
| -f, --format | Formato de saída (text/json/csv) | text |
| -m, --mode | Modo (directory/subdomain) | directory |
| --timeout | Timeout das requisições | 10 |
| --user-agent | User-Agent personalizado | DNSBrute/2.1.0 |
| --no-verify-ssl | Desabilita verificação SSL | False |
| --proxy | Proxy (http://user:pass@host:port) | None |
| --retries | Número de tentativas | 3 |
| -v, --verbose | Modo verboso | False |

## 🎯 Exemplos Práticos

### 1. Descoberta de Diretórios Básica
```bash
python dnsbrute.py -u https://exemplo.com -w wordlists/diretorios.txt
```

### 2. Descoberta de Subdomínios com Saída JSON
```bash
python dnsbrute.py -u exemplo.com -w wordlists/subdomains.txt -m subdomain -f json -o resultados.json
```

### 3. Scan Otimizado para Performance
```bash
python dnsbrute.py -u https://exemplo.com -w wordlists/diretorios.txt -t 20 --timeout 5 --retries 2
```

### 4. Scan Através de Proxy
```bash
python dnsbrute.py -u https://exemplo.com -w wordlists/diretorios.txt --proxy http://127.0.0.1:8080
```

## ⚙️ Configurações Avançadas

### Arquivo de Configuração
Você pode criar um arquivo `config.json` para definir configurações padrão:

```json
{
    "threads": 15,
    "timeout": 5,
    "user_agent": "Mozilla/5.0",
    "verify_ssl": true,
    "retries": 3,
    "delay": 0.1
}

## ❓ FAQ

**P: Como criar uma wordlist personalizada?**
R: Crie um arquivo texto com uma palavra por linha. Recomenda-se usar apenas caracteres alfanuméricos, hífens e pontos.

**P: Qual o limite de threads recomendado?**
R: Depende dos recursos do seu sistema e da largura de banda. Comece com 10 threads e ajuste conforme necessário.

**P: Como interpretar os códigos de status?**
R: 
- 200: Encontrado
- 301/302: Redirecionamento
- 403: Acesso negado
- 404: Não encontrado

## 🤝 Contribuindo

1. Faça um Fork do projeto
2. Crie sua Feature Branch (`git checkout -b feature/AmazingFeature`)
3. Commit suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Push para a Branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📄 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes.

## 👤 Autor

**Gabs77u**
- Github: [@gabs77u](https://github.com/gabs77u)

---

<div align="center">

Desenvolvido por Gabs77u

</div>
