import json
import os.path
from .scrypt_parameters import ScryptParameters


class Wallet:
    def __init__(self):
        self.name = None
        self.version = '1.0'
        self.scrypt = ScryptParameters.default()
        self.accounts = []
        self.extra = None

    def __init__(self, path, name=None):

        if os.path.isfile(path):
            with open(path) as json_file:
                self = json.load(json_file)
        else:
            self.name = name
            self.version = '1.0'
            self.scrypt = ScryptParameters.default()
            self.accounts = []
            self.extra = None

    def save(self):
        with open('wallet.json', 'w') as json_file:
            json.dump(self, json_file)
