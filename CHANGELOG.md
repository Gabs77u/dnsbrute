# Changelog

Todas as mudanças notáveis neste projeto serão documentadas neste arquivo.

O formato é baseado em [Keep a Changelog](https://keepachangelog.com/pt-BR/1.0.0/),
e este projeto adere ao [Versionamento Semântico](https://semver.org/lang/pt-BR/).

## [2.2.0] - 2024-11-29

### Adicionado
- Sistema de plugins extensível com suporte a hooks e eventos
- Relatórios em múltiplos formatos (JSON, HTML, CSV)
- Sistema de cache com gerenciamento de memória
- Validação robusta de dados de entrada
- Sistema de eventos e métricas de performance
- Interface interativa melhorada com menu ASCII
- Perfis de configuração (minimal, standard, complete)
- Compressão automática de relatórios grandes
- Documentação completa em português
- Testes unitários para componentes principais

### Melhorado
- Otimização do uso de memória com processamento em lotes
- Sistema de logging mais detalhado
- Tratamento de erros mais robusto
- Performance geral do sistema
- Interface de linha de comando
- Validação de URLs e entradas
- Gerenciamento de recursos do sistema

### Corrigido
- Vazamentos de memória em scans longos
- Problemas de concorrência em threads
- Erros de timeout em conexões lentas
- Bugs na geração de relatórios
- Problemas de codificação em arquivos de saída
- Erros na limpeza de arquivos temporários

### Segurança
- Validação de certificados SSL
- Sanitização de inputs
- Proteção contra ataques comuns
- Gerenciamento seguro de arquivos temporários

### Dependências
- Atualizado requests para 2.31.0
- Adicionado jinja2 3.1.2 para templates
- Adicionado pyyaml 6.0.1 para configurações
- Adicionado psutil 5.9.6 para métricas

## [2.0.0] - 2023-10-23

### Adicionado
- Modo de descoberta de subdomínios
- Suporte a múltiplos formatos de saída
- Sistema de cache básico
- Suporte a proxy
- Interface ASCII inicial

### Melhorado
- Reescrita completa do código base
- Nova estrutura de classes
- Sistema de logging básico
- Tratamento de erros

### Removido
- Suporte a Python 2.x
- Funcionalidades legadas

## [1.0.0] - 2023-09-01

### Adicionado
- Primeira versão pública
- Funcionalidade básica de bruteforce
- Suporte a wordlists
- Configurações simples
- Documentação inicial 