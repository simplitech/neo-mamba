import hashlib
import unicodedata

import base58

from Crypto.Cipher import AES
from neo3.core.cryptography import KeyPair
from neo3.wallet import ScryptParameters

NEP_HEADER = bytearray([0x01, 0x42])
NEP_FLAG = bytearray([0xe0])


class Utils(object):

    @staticmethod
    def PrivateKeyFromNEP2(nep2_key, passphrase):
        if not nep2_key or len(nep2_key) != 58:
            raise ValueError('Please provide a nep2_key with a length of 58 bytes (LEN: {0:d})'.format(len(nep2_key)))

        ADDRESS_HASH_SIZE = 4
        ADDRESS_HASH_OFFSET = len(NEP_FLAG) + len(NEP_HEADER)

        try:
            decoded_key = base58.b58decode_check(nep2_key)
        except Exception:
            raise ValueError("Invalid nep2_key")

        address_hash = decoded_key[ADDRESS_HASH_OFFSET:ADDRESS_HASH_OFFSET + ADDRESS_HASH_SIZE]
        encrypted = decoded_key[-32:]

        pwd_normalized = bytes(unicodedata.normalize('NFC', passphrase), 'utf-8')
        derived = hashlib.scrypt(password=pwd_normalized, salt=address_hash,
                                 n=16384,
                                 r=8,
                                 p=8,
                                 dklen=64)

        derived1 = derived[:32]
        derived2 = derived[32:]

        cipher = AES.new(derived2, AES.MODE_ECB)
        decrypted = cipher.decrypt(encrypted)
        private_key = Utils.xor_bytes(decrypted, derived1)

        # Now check that the address hashes match. If they don't, the password was wrong.
        kp_new = KeyPair(private_key=private_key)

        kp_new_address = kp_new.GetAddress()
        kp_new_address_hash_tmp = hashlib.sha256(kp_new_address.encode("utf-8")).digest()
        kp_new_address_hash_tmp2 = hashlib.sha256(kp_new_address_hash_tmp).digest()
        kp_new_address_hash = kp_new_address_hash_tmp2[:4]
        if kp_new_address_hash != address_hash:
            raise ValueError("Wrong passphrase")

        return private_key

    @staticmethod
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
