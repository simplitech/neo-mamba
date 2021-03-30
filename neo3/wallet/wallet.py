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

    def __init__(self, path=None, name=None, json_wallet=None):
        if json_wallet is not None:
            self.load_json(json_wallet)
        else:
            self.path = path

            if os.path.isfile(path):
                with open(path) as json_file:
                    data = json.load(json_file)
                self.load_json(data)
            else:
                self.name = name
                self.version = '3.0'
                self.scrypt = ScryptParameters.default()
                self.accounts = {}
                self.extra = None

    def load_json(self, json_data):
        self.version = json_data['version']
        assert not (float(self.version) < 3.0), "Version is lower than 3.0 and isn't compatible with the wallet"

        self.name = json_data['name']
        self.scrypt = ScryptParameters(json_data['scrypt']['n'], json_data['scrypt']['r'], json_data['scrypt']['p'])
        self.accounts = json_data['accounts']
        self.extra = json_data['extra']

    def save(self):
        with open(self.path, 'w') as json_file:
            json.dump(vars(self), json_file, default=encode_scrypt_parameters)
