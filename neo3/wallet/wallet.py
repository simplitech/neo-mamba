import hashlib
import os.path
import json
import unicodedata

import base58
from Crypto.Cipher import AES
from jsonschema import validate  # type: ignore
from typing import List, Dict, Any, TypeVar, Type, Optional

from neo3 import contracts, settings
from neo3.core import IJson, KeyPair, to_script_hash, types
from neo3.wallet.scrypt_parameters import ScryptParameters
from neo3.wallet.account import Account


def encode_scrypt_parameters(scrypt_parameters):
    if isinstance(scrypt_parameters, ScryptParameters):
        return {'n': scrypt_parameters.n, 'r': scrypt_parameters.r, 'p': scrypt_parameters.p,
                'length': scrypt_parameters.length}
    else:
        type_name = scrypt_parameters.__class__.__name__
        raise TypeError(f"Object of type '{type_name}' is not JSON serializable")


T = TypeVar('T', bound='Wallet')

# A sample schema, like what we'd get from json.load()
schema = {
    "type": "object",
    "properties": {
        "path": {"type": "string"},
        "name": {"type": "string"},
        "scrypt": {"$ref": "#/$defs/scrypt_parameters"},
        "accounts": {
            "type": "array",
            "items": {"$ref": "#/$defs/account"},
            "minItems": 0,
        },
        "extra": {"type": ["object", "null"],
                  "properties": {},
                  "additionalProperties": True
                  },
    },
    "required": ["path", "name", "scrypt", "accounts", "extra"],
    "$defs": {
        "account": {
            "type": "object",
            "properties": {
                "address": {"type": "string"},
                "label": {"type": "string"},
                "is_default": {"type": "boolean"},
                "lock": {"type": "boolean"},
                "key": {"type": "string"},
                "contract": {"type": ""},
                "extra": {"type": ["object", "null"],
                          "properties": {},
                          "additionalProperties": True}
            },
            "required": ["address", "label", "is_default", "lock", "key", "contract", "extra"]

        },
        "scrypt_parameters": {
            "type": "object",
            "properties": {
                "n": {"type": "integer"},
                "r": {"type": "integer"},
                "p": {"type": "integer"},
                "length": {"type": "integer"}
            },
            "required": ["n", "r", "p"]
        }
    }
}


class Wallet(IJson):

    def __init__(self,
                 path: str,
                 name: Optional[str],
                 version: str,
                 scrypt: ScryptParameters,
                 accounts: List[Account],
                 extra: Optional[Dict[Any, Any]]):
        """
        Args:
            path: the JSON's path
            name: a label that the user has given to the wallet
            version: the wallet's version, must be equal or greater then 3.0
            scrypt: a ScryptParameters object which describes the parameters of the SCrypt algorithm used for encrypting
                    and decrypting the private keys in the wallet.
            accounts: an array of Account objects which describe the details of each account in the wallet.
            extra: an object that is defined by the implementor of the client for storing extra data. This field can be
                   None.
        """

        self.path = path
        self.name = name
        self.version = version
        self.scrypt = scrypt
        self.accounts = accounts
        self.extra = extra

    @classmethod
    def new_wallet(cls: Type[T], path: str, name: Optional[str] = None) -> T:
        """
        Create a new Wallet with the default settings.

        Args:
            path: the JSON's path.
            name: the Wallet name.
        """
        return cls(path, name, "3.0", ScryptParameters.default(), [], None)

    @classmethod
    def new_wallet_from_file(cls: Type[T], path: str) -> T:
        """
        Create a Wallet from a JSON file.

        Args:
            path: the JSON's path.
        """
        if os.path.isfile(path):
            with open(path) as json_file:
                data = json.load(json_file)

        return cls.from_json(data)

    def save(self):
        """
        Save a wallet as a JSON.
        """
        with open(self.path, 'w') as json_file:
            json.dump(self.to_json(), json_file, default=encode_scrypt_parameters)

    def to_json(self) -> dict:
        """
        Convert object into JSON representation.
        """

        json = {
            'path': self.path,
            'name': self.name,
            'version': self.version,
            'scrypt': self.scrypt,
            'accounts': self.accounts,
            'extra': self.extra
        }

        return json

    @classmethod
    def from_json(cls: Type[T], json: dict) -> T:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.

        Raises:
            KeyError: if the data supplied does not contain the necessary key.
            ValueError: if the 'version' property is under 3.0 or is not a valid string.
        """
        validate(json, schema=schema)
        try:
            if float(json['version']) < 3.0:
                raise ValueError("Format error - invalid 'version'")
        except ValueError:
            raise ValueError("Format error - invalid 'version'")

        return cls(json['path'],
                   json['name'],
                   json['version'],
                   ScryptParameters(json['scrypt']['n'],
                                    json['scrypt']['r'],
                                    json['scrypt']['p'],
                                    json['scrypt']['length']),
                   json['accounts'],
                   json['extra'])



    def create_account(self, name: str, passphrase: str):
        account = Account()
        account.label = name
        account.encrypt(passphrase)
        self.accounts.append(account)
        self.save()


NEP_HEADER = bytearray([0x01, 0x42])
NEP_FLAG = bytearray([0xe0])


def address_to_script_hash(address: str, version: int) -> types.UInt160:
    """
    Converts the specified address to a script hash.

    Args:
        address: address to convert
        version: address version
    """
    data_ = base58.b58decode_check(address)
    if len(data_) != len(types.UInt160.zero()) + 1:
        raise Exception

    if data_[0] != version:
        raise Exception

    return types.UInt160(data_[1:])


# TODO: replace version with settings.network.account_version
def to_address(script_hash: types.UInt160, version: int = settings.network.account_version) -> str:
    """
    Converts the specified script hash to an address.

    Args:
        script_hash: script hash to convert
        version: address version
    """
    data_ = version.to_bytes(1, 'little') + script_hash.to_array()

    return base58.b58encode_check(data_).decode('utf-8')


def wif_to_nep2(wif: str, passphrase: str):
    return None


def private_key_to_nep2(private_key: bytes, passphrase: str):
    key_pair = KeyPair(private_key=private_key)
    script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
    address = to_address(script_hash)
    # NEP2 checksum: hash the address twice and get the first 4 bytes
    first_hash = hashlib.sha256(address.encode("utf-8")).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]

    pwd_normalized = bytes(unicodedata.normalize('NFC', passphrase), 'utf-8')
    derived = hashlib.scrypt(password=pwd_normalized, salt=checksum,
                             n=16384,
                             r=8,
                             p=8,
                             dklen=64)

    derived1 = derived[:32]
    derived2 = derived[32:]

    xor_ed = xor_bytes(bytes(private_key), derived1)
    cipher = AES.new(derived2, AES.MODE_ECB)
    encrypted = cipher.encrypt(xor_ed)

    nep2 = bytearray()
    nep2.extend(NEP_HEADER)
    nep2.extend(NEP_FLAG)
    nep2.extend(checksum)
    nep2.extend(encrypted)

    # Finally, encode with Base58Check
    encoded_nep2 = base58.b58encode_check(bytes(nep2))

    return encoded_nep2


def private_key_from_nep2(nep2_key: str, passphrase: str):
    if not nep2_key or len(nep2_key) != 58:
        raise ValueError('Please provide a nep2_key with a length of 58 bytes (LEN: {0:d})'.format(len(nep2_key)))

    address_hash_size = 4
    address_hash_offset = len(NEP_FLAG) + len(NEP_HEADER)

    try:
        decoded_key = base58.b58decode_check(nep2_key)
    except Exception:
        raise ValueError("Invalid nep2_key")

    address_checksum = decoded_key[address_hash_offset:address_hash_offset + address_hash_size]
    encrypted = decoded_key[-32:]

    pwd_normalized = bytes(unicodedata.normalize('NFC', passphrase), 'utf-8')
    derived = hashlib.scrypt(password=pwd_normalized, salt=address_checksum,
                             n=16384,
                             r=8,
                             p=8,
                             dklen=64)

    derived1 = derived[:32]
    derived2 = derived[32:]

    cipher = AES.new(derived2, AES.MODE_ECB)
    decrypted = cipher.decrypt(encrypted)
    private_key = xor_bytes(decrypted, derived1)

    # Now check that the address hashes match. If they don't, the password was wrong.
    key_pair = KeyPair(private_key=private_key)
    script_hash = to_script_hash(contracts.Contract.create_signature_redeemscript(key_pair.public_key))
    address = to_address(script_hash)
    first_hash = hashlib.sha256(address.encode("utf-8")).digest()
    second_hash = hashlib.sha256(first_hash).digest()
    checksum = second_hash[:4]
    if checksum != address_checksum:
        raise ValueError("Wrong passphrase")

    return private_key


def xor_bytes(a: bytes, b: bytes):
    """
    XOR on two bytes objects
    Args:
        a (bytes): object 1
        b (bytes): object 2
    Returns:
        bytes: The XOR result
    """
    assert len(a) == len(b)
    res = bytearray()
    for i in range(len(a)):
        res.append(a[i] ^ b[i])
    return bytes(res)