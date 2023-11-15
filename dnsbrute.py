# dnsbrute 1.0.2
# por Gabs77u
# 2023-07-20

# Um bruteforcer de diretórios web

import requests
import string
import logging
import re
import os
import argparse

from requests import get, head
from concurrent.futures import ThreadPoolExecutor

def validate_url(url):
    try:
        parsed_url = urlparse(url)
        return parsed_url.scheme and parsed_url.netloc and parsed_url.path
    except ValueError:
        return False


def validate_word(word):
    return re.match(r"\w+", word) is not None


def validate_directory(url, word):
    try:
        response = requests.head(f"{url}/{word}")
        return response.status_code == 200 and response.headers["Content-Type"].startswith("text/html")
    except requests.exceptions.ConnectionError:
        return False


class Bruteforcer:
    def __init__(self, url, wordlist):
        self.url = url
        self.wordlist = wordlist

    def run(self):
        count = 0
        table = []

        with ThreadPoolExecutor(max_workers=10) as executor:
            futures = [
                executor.submit(validate_directory, self.url, word)
                for word in self.wordlist
                if validate_word(word)
            ]

            for future in futures:
                result = future.result()
                if result:
                    table.append([word, "Diretório encontrado"])
                    return table
                else:
                    table.append([word, "Diretório não encontrado"])

            count = len(self.wordlist)

        logging.info(f"Foram verificadas {count} palavras e foram encontrados {len(table)} diretórios.")
        return table


def main():
    logging.basicConfig(format="%(asctime)s %(levelname)s %(message)s", level=logging.INFO)

    parser = argparse.ArgumentParser(description="Bruteforcer de diretórios web")
    parser.add_argument("-u", "--url", required=True, help="URL da aplicação web")
    parser.add_argument("-w", "--wordlist", required=True, help="Arquivo de lista de palavras")
    args = parser.parse_args()

    while True:
        print(
            """
            Olá! Seja bem-vindo ao dnsbrute, um bruteforcer de diretórios web.

            Para usar o dnsbrute, você precisa fornecer duas informações:

            * A URL da aplicação web
            * O arquivo de lista de palavras

            Para iniciar o ataque de força bruta, siga estas etapas:

            1. Digite a URL da aplicação web no prompt.
            2. Digite o caminho do arquivo de lista de palavras no prompt.
            3. Pressione Enter.

            **Você deseja iniciar o ataque de força bruta? (s/n)**
            """
        )

        choice = input()

        if choice == "s":
            # Valida os inputs
            if not validate_url(args.url):
                print("Por favor, insira uma URL válida.")
                continue

            if not os.path.isfile(args.wordlist):
                print("O arquivo de lista de palavras não existe.")
                continue

            # Inicia o ataque de força bruta
            bruteforcer = Bruteforcer(args.url, args.wordlist)
            table = bruteforcer.run()

            # Exibe os resultados do ataque
            print("-" * 80)
            print("Resultados:")
            for word, status in table:
                print(f"{word:<20} {status:>20}")
            print("-" * 80)

            break
        elif choice == "n":
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    main()

# Alterações feitas nas versões:

# Versão 1.0.2:
# * Corrigi erros de sintaxe, lógica e bugs.
# * Adicionei verificações para garantir que a URL e a palavra sejam válidas.
# * Paralelizei o ataque usando uma thread pool.