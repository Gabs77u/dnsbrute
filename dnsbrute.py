#!/usr/bin/env python3
# dnsbrute 2.1.0
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
from datetime import datetime
from urllib.parse import urlparse
from concurrent.futures import ThreadPoolExecutor
from requests.exceptions import RequestException, ConnectionError, Timeout
from typing import List, Dict, Union, Optional
from contextlib import contextmanager
from time import sleep
import sys

# Constantes globais
DEFAULT_THREADS = 10
DEFAULT_TIMEOUT = 10
DEFAULT_USER_AGENT = "DNSBrute/2.1.0"
DEFAULT_DELAY = 0
DEFAULT_RETRIES = 3
VALID_STATUS_CODES = {200, 201, 202, 203, 204, 301, 302, 307, 308}
VALID_SCHEMES = {'http', 'https'}

class ConfigError(Exception):
    """Exceção personalizada para erros de configuração"""
    pass

class Config:
    """
    Classe de configuração que armazena todas as configurações da ferramenta.
    Realiza validação dos parâmetros fornecidos.
    """
    def __init__(self, **kwargs):
        self.threads = self._validate_threads(kwargs.get('threads', DEFAULT_THREADS))
        self.timeout = kwargs.get('timeout', DEFAULT_TIMEOUT)
        self.user_agent = kwargs.get('user_agent', DEFAULT_USER_AGENT)
        self.delay = kwargs.get('delay', DEFAULT_DELAY)
        self.output_format = kwargs.get('output_format', 'text')
        self.auth = kwargs.get('auth', None)
        self.verify_ssl = kwargs.get('verify_ssl', True)
        self.mode = kwargs.get('mode', 'directory')
        self.proxy = kwargs.get('proxy', None)
        self.retries = kwargs.get('retries', DEFAULT_RETRIES)
        self.verbose = kwargs.get('verbose', False)

    @staticmethod
    def _validate_threads(threads: int) -> int:
        """Valida o número de threads"""
        if not isinstance(threads, int) or threads < 1:
            raise ConfigError("Número de threads deve ser um inteiro positivo")
        return threads

class Result:
    """
    Classe que representa o resultado de uma verificação.
    Armazena informações sobre o alvo, status e timestamp.
    """
    def __init__(self, target: str, status_code: int, content_type: str, found: bool):
        self.target = target
        self.status_code = status_code
        self.content_type = content_type
        self.found = found
        self.timestamp = datetime.now()

    def to_dict(self) -> Dict:
        """Converte o resultado para dicionário"""
        return {
            'target': self.target,
            'status_code': self.status_code,
            'content_type': self.content_type,
            'found': self.found,
            'timestamp': self.timestamp.isoformat()
        }

class Bruteforcer:
    """
    Classe principal que implementa a funcionalidade de bruteforce.
    Gerencia as requisições HTTP e o processamento dos resultados.
    """
    def __init__(self, url: str, wordlist_path: str, config: Config):
        self.url = self._normalize_url(url)
        self.wordlist_path = wordlist_path
        self.config = config
        self.results: List[Result] = []
        self._cache = {}  # Cache de resultados

    @staticmethod
    def _normalize_url(url: str) -> str:
        """
        Normaliza a URL removendo barras finais e garantindo esquema apropriado.
        Raises:
            ValueError: Se a URL for inválida
        """
        url = url.rstrip('/')
        if not any(url.startswith(scheme + '://') for scheme in VALID_SCHEMES):
            url = 'https://' + url
        
        parsed = urlparse(url)
        if not all([parsed.scheme, parsed.netloc]):
            raise ValueError("URL inválida")
        if parsed.scheme not in VALID_SCHEMES:
            raise ValueError(f"Esquema inválido. Use: {', '.join(VALID_SCHEMES)}")
        
        return url

    @contextmanager
    def _get_session(self):
        """
        Gerenciador de contexto para sessões HTTP.
        Garante que a sessão seja fechada apropriadamente.
        """
        session = requests.Session()
        try:
            session.headers.update({'User-Agent': self.config.user_agent})
            if self.config.auth:
                session.auth = self.config.auth
            if self.config.proxy:
                session.proxies = self.config.proxy
            yield session
        finally:
            session.close()

    def _validate_target(self, word: str, retry_count: int = 0) -> Result:
        """
        Valida um alvo específico com mecanismo de retry.
        Args:
            word: Palavra da wordlist a ser testada
            retry_count: Contador de tentativas
        Returns:
            Result: Objeto com o resultado da validação
        """
        # Verifica cache
        cache_key = f"{self.url}:{word}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        if self.config.delay > 0:
            sleep(self.config.delay)

        target = (f"{self.url}/{word}" if self.config.mode == 'directory' 
                 else f"https://{word}.{self.url}")
        
        try:
            with self._get_session() as session:
                response = session.head(
                    target,
                    timeout=self.config.timeout,
                    verify=self.config.verify_ssl,
                    allow_redirects=True
                )
                
                found = response.status_code in VALID_STATUS_CODES
                content_type = response.headers.get('Content-Type', '')
                
                result = Result(target, response.status_code, content_type, found)
                self._cache[cache_key] = result  # Armazena no cache
                return result
                
        except (ConnectionError, Timeout) as e:
            if retry_count < self.config.retries:
                if self.config.verbose:
                    logging.warning(f"Tentando novamente {target} após erro: {e}")
                return self._validate_target(word, retry_count + 1)
            logging.error(f"Falha ao verificar {target} após {self.config.retries} tentativas: {e}")
            return Result(target, 0, '', False)
        except RequestException as e:
            logging.error(f"Erro ao verificar {target}: {e}")
            return Result(target, 0, '', False)

    def _load_wordlist(self) -> List[str]:
        """
        Carrega e valida a wordlist.
        Returns:
            List[str]: Lista de palavras válidas
        """
        try:
            with open(self.wordlist_path, 'r', encoding='utf-8') as f:
                return [line.strip() for line in f if line.strip() and self._is_valid_word(line.strip())]
        except Exception as e:
            logging.error(f"Erro ao carregar wordlist: {e}")
            return []

    @staticmethod
    def _is_valid_word(word: str) -> bool:
        """Valida uma palavra da wordlist"""
        return bool(re.match(r"^[\w.-]+$", word))

    def run(self) -> List[Result]:
        """
        Executa o processo de bruteforce.
        Returns:
            List[Result]: Lista de resultados encontrados
        """
        wordlist = self._load_wordlist()
        if not wordlist:
            logging.error("Wordlist vazia ou inválida")
            return []

        logging.info(f"Iniciando bruteforce com {len(wordlist)} palavras")
        
        with ThreadPoolExecutor(max_workers=self.config.threads) as executor:
            futures = [executor.submit(self._validate_target, word) for word in wordlist]
            
            for future in futures:
                try:
                    result = future.result()
                    if result.found:
                        self.results.append(result)
                        if self.config.verbose:
                            logging.info(f"Encontrado: {result.target} ({result.status_code})")
                except Exception as e:
                    logging.error(f"Erro ao processar resultado: {e}")

        return self.results

    def save_results(self, filename: str):
        """
        Salva os resultados em um arquivo no formato especificado.
        Args:
            filename: Nome do arquivo de saída
        """
        if not self.results:
            logging.warning("Sem resultados para salvar")
            return

        try:
            if self.config.output_format == 'json':
                with open(filename, 'w', encoding='utf-8') as f:
                    json.dump([r.to_dict() for r in self.results], f, indent=2)
            elif self.config.output_format == 'csv':
                with open(filename, 'w', newline='', encoding='utf-8') as f:
                    writer = csv.DictWriter(f, fieldnames=self.results[0].to_dict().keys())
                    writer.writeheader()
                    writer.writerows([r.to_dict() for r in self.results])
            else:
                with open(filename, 'w', encoding='utf-8') as f:
                    for result in self.results:
                        f.write(f"{result.target}\t{result.status_code}\t{result.content_type}\n")
            
            logging.info(f"Resultados salvos em: {filename}")
        except Exception as e:
            logging.error(f"Erro ao salvar resultados: {e}")

class AsciiInterface:
    """Classe responsável pela interface visual em ASCII"""
    
    BANNER = """
    ██████╗ ███╗   ██╗███████╗██████╗ ██████╗ ██╗   ██╗████████╗███████╗
    ██╔══██╗████╗  ██║██╔════╝██╔══██╗██╔══██╗██║   ██║╚══██╔══╝██╔════╝
    ██║  ██║██╔██╗ ██║███████╗██████╔╝██████╔╝██║   ██║   ██║   █████╗  
    ██║  ██║██║╚██╗██║╚════██║██╔══██╗██╔══██╗██║   ██║   ██║   ██╔══╝  
    ██████╔╝██║ ╚████║███████║██████╔╝██║  ██║╚██████╔╝   ██║   ███████╗
    ╚═════╝ ╚═╝  ╚═══╝╚══════╝╚═════╝ ╚═╝  ╚═╝ ╚═════╝    ╚═╝   ╚══════╝
    v2.1.0 - Por Gabs77u                                                                    
    """

    MENU = """
    ╔════════════════════════════════════════════════════════════════════╗
    ║                         MENU PRINCIPAL                             ║
    ╠════════════════════════════════════════════════════════════════════╣
    ║ [1] Iniciar Scan                                                  ║
    ║ [2] Configurações                                                 ║
    ║ [3] Sobre                                                         ║
    ║ [4] Sair                                                         ║
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
    def print_progress(current: int, total: int, width: int = 50):
        """
        Exibe uma barra de progresso
        Args:
            current: Valor atual
            total: Valor total
            width: Largura da barra
        """
        percent = current / total
        filled = int(width * percent)
        bar = '█' * filled + '░' * (width - filled)
        print(f'\rProgresso: |{bar}| {percent:.1%}', end='')
        if current == total:
            print()

    @staticmethod
    def print_result_header():
        """Exibe o cabeçalho da tabela de resultados"""
        print("\n╔═══════════════════════════════════════════════════════════════════════════╗")
        print("║                              RESULTADOS                                    ║")
        print("╠═══════════════════════════════════════════════════════════════════════════╣")
        print("║ Alvo                          │ Status │ Tipo de Conteúdo                 ║")
        print("╟───────────────────────────────┼────────┼────────────────────────────────╢")

    @staticmethod
    def print_result_footer():
        """Exibe o rodapé da tabela de resultados"""
        print("╚═══════════════════════════════════════════════════════════════════════════╝")

    @staticmethod
    def print_result(result: Result):
        """
        Exibe um resultado formatado
        Args:
            result: Objeto Result a ser exibido
        """
        target = result.target[:30]
        content_type = result.content_type[:30]
        print(f"║ {target:<30} │ {result.status_code:<6} │ {content_type:<30} ║")

def interactive_mode():
    """Modo interativo da aplicação"""
    interface = AsciiInterface()
    
    while True:
        interface.clear_screen()
        interface.print_banner()
        interface.print_menu()
        
        choice = input("\nEscolha uma opção: ")
        
        if choice == "1":
            # Iniciar Scan
            url = input("\nDigite a URL alvo: ")
            wordlist = input("Digite o caminho da wordlist: ")
            mode = input("Escolha o modo (directory/subdomain): ")
            threads = input("Número de threads [10]: ") or "10"
            output = input("Arquivo de saída (opcional): ")
            
            cmd = f"-u {url} -w {wordlist} -m {mode} -t {threads}"
            if output:
                cmd += f" -o {output}"
            
            # Executa o scan com os parâmetros fornecidos
            sys.argv = ["dnsbrute.py"] + cmd.split()
            main()
            
            input("\nPressione Enter para continuar...")
            
        elif choice == "2":
            # Configurações
            interface.clear_screen()
            print("\n╔═══════════════ CONFIGURAÇÕES ═══════════════╗")
            print("║ Configurações disponíveis via linha          ║")
            print("║ de comando ou arquivo de configuração.       ║")
            print("║                                             ║")
            print("║ Use --help para ver todas as opções.        ║")
            print("╚═════════════════════════════════════════════╝")
            input("\nPressione Enter para continuar...")
            
        elif choice == "3":
            # Sobre
            interface.clear_screen()
            interface.print_sobre()
            input("\nPressione Enter para continuar...")
            
        elif choice == "4":
            # Sair
            interface.clear_screen()
            print("\nObrigado por usar o DNSBrute!")
            sys.exit(0)
            
        else:
            print("\nOpção inválida!")
            sleep(1)

def main():
    """Função principal do programa"""
    if len(sys.argv) == 1:
        # Se não houver argumentos, inicia o modo interativo
        interactive_mode()
        return

    # Configuração de logging
    log_format = '%(asctime)s - %(levelname)s - %(message)s'
    log_level = logging.DEBUG if args.verbose else logging.INFO
    logging.basicConfig(
        level=log_level,
        format=log_format,
        datefmt='%Y-%m-%d %H:%M:%S'
    )

    try:
        # Criação da configuração
        config = Config(
            threads=args.threads,
            timeout=args.timeout,
            user_agent=args.user_agent,
            delay=args.delay,
            output_format=args.format,
            verify_ssl=not args.no_verify_ssl,
            mode=args.mode,
            proxy=args.proxy,
            retries=args.retries,
            verbose=args.verbose
        )

        # Inicialização e execução do bruteforcer
        bruteforcer = Bruteforcer(args.url, args.wordlist, config)
        results = bruteforcer.run()

        # Salvamento ou exibição dos resultados
        if args.output:
            bruteforcer.save_results(args.output)
        else:
            for result in results:
                print(f"{result.target}\t{result.status_code}\t{result.content_type}")

        logging.info(f"Scan concluído. Encontrados {len(results)} resultados.")
        
    except (ConfigError, ValueError) as e:
        logging.error(f"Erro de configuração: {e}")
        sys.exit(1)
    except Exception as e:
        logging.error(f"Erro inesperado: {e}")
        if args.verbose:
            logging.exception("Detalhes do erro:")
        sys.exit(1)

if __name__ == "__main__":
    main()