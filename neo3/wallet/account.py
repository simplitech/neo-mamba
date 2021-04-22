from __future__ import annotations

from neo3 import contracts, settings, wallet
from neo3.core import cryptography
from neo3.wallet.wallet import private_key_to_nep2, to_address, xor_bytes

class Account:

    def __init__(self):
        self.encrypted_key: str = ''
        self.label = ''
        self.is_default = False
        self.lock = False
        self._key_pair: cryptography.KeyPair = cryptography.KeyPair.generate()
        self.contract: contracts.Contract = None
        self.extra = None

    def encrypt(self, password: str):
        self.encrypted_key = private_key_to_nep2(self.private_key, password)

    @property
    def private_key(self) -> bytes:
        return self._key_pair.private_key

    @property
    def public_key(self) -> bytes:
        return self._key_pair.public_key

    @property
    def address(self) -> str:
        return wallet.to_address(self._script_hash, settings.network.account_version)

    @property
    def decrypted(self) -> bool:
        return self.encrypted_key is not None or self._key_pair is not None

    @property
    def has_key(self) -> bool:
        return self.encrypted_key is not None

    @classmethod
    def from_json(cls, json: dict) -> Account:
        account = cls(wallet.address_to_script_hash(json['address'], settings.network.account_version), json['key'])

        account.label = json['label']
        account.is_default = json['isdefault']
        account.lock = json['lock']
        account.contract = wallet.NEP6Contract.from_json(json['contract'])
        account.extra = json['extra']

        return account

    def to_json(self) -> dict:
        return {
            'address': self.address,
            'label': self.label,
            'isdefault': self.is_default,
            'lock': self.lock,
            'key': self.encrypted_key,
            'contract': self.contract.to_json() if hasattr(self.contract, 'to_json') else None,
            'extra': self.extra
        }

    def get_key(self, password: str = None) -> cryptography.KeyPair:
        if self.encrypted_key is None:
            return None

        # TODO: validate password
        return self._key_pair

