# dnsbrute 1.0.0
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

def validate_url(url):
    try:
        return requests.head(url).status_code == 200
    except requests.exceptions.ConnectionError:
        return False


def validate_wordlist(wordlist):
    return os.path.isfile(wordlist)


def validate_word(word):
    return re.match(r"\w+", word)


class Bruteforcer:
    def __init__(self, url, wordlist):
        self.url = url
        self.wordlist = wordlist

    def run(self):
        count = 0

        for word in self.wordlist:
            if requests.get(f"{self.url}/{word}").status_code == 200:
                logging.info(
                    f"Diretório encontrado: {self.url}/{word}, data e hora: {datetime.now()}"
                )
                return

            count += 1

        logging.info(f"Foram verificadas {count} palavras e foram encontrados {count} diretórios.")


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

            if not validate_wordlist(args.wordlist):
                print("O arquivo de lista de palavras não existe.")
                continue

            # Inicia o ataque de força bruta
            bruteforcer = Bruteforcer(args.url, args.wordlist)
            bruteforcer.run()

            break
        elif choice == "n":
            break
        else:
            print("Opção inválida.")


if __name__ == "__main__":
    main()