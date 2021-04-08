from neo3.core.cryptography import KeyPair


class Account:
    # this is a place holder to test the accounts, it will be better implemented later

    keypair: KeyPair

    def __init__(self):
        self.address = ''
        self.label = ''
        self.is_default = True
        self.lock = False
        self.key = ''
        self.contract = {}
        self.extra = None


