import unittest
from neo3.wallet import Wallet, ScryptParameters
import os.path
import json


class WalletCreationTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None

    def test_wallet_default_value(self):
        wallet = Wallet('wallet.json')
        self.assertEqual(None, wallet.name)
        self.assertEqual('1.0', wallet.version)
        self.assertEqual(ScryptParameters.default().r, wallet.scrypt.r)
        self.assertEqual(ScryptParameters.default().p, wallet.scrypt.p)
        self.assertEqual(ScryptParameters.default().n, wallet.scrypt.n)
        self.assertEqual([], wallet.accounts)
        self.assertEqual(None, wallet.extra)

    def test_wallet_save(self):
        wallet = Wallet('wallet.json', 'NEP6 Wallet')
        wallet.save()
        self.assertTrue(os.path.isfile('wallet.json'))

        with open('wallet.json') as json_file:
            data = json.load(json_file)
        self.assertEqual(data, wallet)

    def test_wallet_load(self):
        wallet = Wallet('wallet.json', 'NEP6 Wallet')
        wallet.save()
        self.assertTrue(os.path.isfile('wallet.json'))

        wallet_loaded = Wallet('wallet.json')
        self.assertEqual(wallet, wallet_loaded)
