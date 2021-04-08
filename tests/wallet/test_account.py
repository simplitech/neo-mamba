import unittest
from neo3.wallet.utils import Utils


class AccountCreationTestCase(unittest.TestCase):
    def shortDescription(self):
        # disable docstring printing in test runner
        return None


    def test_createAccountUsingNep2(self):
        #Neo 2 NEP-2
        nep2 = "6PYN6mjwYfjPUuYT3Exajvx25UddFVLpCw4bMsmtLdnKwZ9t1Mi3CfKe8S"
        password = "Satoshi"
        privateKey = Utils.PrivateKeyFromNEP2(nep2, password)
        print(privateKey)
        return None

