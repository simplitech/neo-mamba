import json
import os.path
from .scrypt_parameters import ScryptParameters


def encode_scrypt_parameters(scrypt_parameters):
    if isinstance(scrypt_parameters, ScryptParameters):
        return {'n': scrypt_parameters.n, 'r': scrypt_parameters.r, 'p': scrypt_parameters.p}
    else:
        type_name = scrypt_parameters.__class__.__name__
        raise TypeError(f"Object of type '{type_name}' is not JSON serializable")


class Wallet:

    def __init__(self, path, name=None, json_wallet=None):
        if json_wallet is not None:
            self.name = json_wallet['name']
            self.version = json_wallet['version']
            self.scrypt = ScryptParameters(json_wallet['scrypt']['n'], json_wallet['scrypt']['r'], json_wallet['scrypt']['p'])
            self.accounts = json_wallet['accounts']
            self.extra = json_wallet['extra']
        else:
            if os.path.isfile(path):
                with open(path) as json_file:
                    data = json.load(json_file)
                self.name = data['name']
                self.version = data['version']
                self.scrypt = ScryptParameters(data['scrypt']['n'], data['scrypt']['r'], data['scrypt']['p'])
                self.accounts = data['accounts']
                self.extra = data['extra']
            else:
                self.name = name
                self.version = '1.0'
                self.scrypt = ScryptParameters.default()
                self.accounts = []
                self.extra = None

    def save(self):
        with open('wallet.json', 'w') as json_file:
            json.dump(vars(self), json_file, default=encode_scrypt_parameters)
