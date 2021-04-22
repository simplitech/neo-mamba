from __future__ import annotations

from typing import List

from neo3 import contracts, settings, wallet
from neo3.core import cryptography, types


class Account:

    def __init__(self, script_hash: types.UInt160, nep2key: str = None):
        self._script_hash: types.UInt160 = script_hash
        self._nep2key: str = nep2key
        self.label = ''
        self.is_default = True
        self.lock = False
        self._key: cryptography.KeyPair = None
        self.contract: contracts.Contract = None
        self.extra = None

    @property
    def address(self) -> str:
        return wallet.to_address(self._script_hash, settings.network.account_version)

    @property
    def decrypted(self) -> bool:
        return self._nep2key is not None or self._key is not None

    @property
    def has_key(self) -> bool:
        return self._nep2key is not None

    @classmethod
    def new_account(cls, passphrase: str) -> Account:
        key_pair = cryptography.KeyPair.generate()
        return cls.new_account_from_private_key(key_pair, passphrase)

    @classmethod
    def new_account_from_private_key(cls, key_pair: cryptography.KeyPair, passphrase: str) -> Account:
        public_key = key_pair.public_key
        from neo3.core import to_script_hash
        script_hash = to_script_hash(public_key)
        from neo3.wallet import private_key_to_nep2

        account: Account
        account = cls(script_hash, private_key_to_nep2(key_pair.private_key, passphrase))
        account._key = key_pair
        account.contract.script = public_key.get_veritification_script()
        account.contract.parameter_list = Account.get_contract_params(1)

        return account

    @classmethod
    def get_contract_params(cls, n: int) -> List[contracts.ContractParameterType]:
        params: List[contracts.ContractParameterType] = []
        for i in range(0, n):
            params[i] = contracts.ContractParameterType.SIGNATURE

        return params

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
            'key': self._nep2key,
            'contract': self.contract.to_json() if hasattr(self.contract, 'to_json') else None,
            'extra': self.extra
        }

    def get_key(self, password: str = None) -> cryptography.KeyPair:
        if self._nep2key is None:
            return None

        # TODO: validate password
        return self._key
