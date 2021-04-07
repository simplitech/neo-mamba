import base58

from .account import Account
from .nep6contract import NEP6Contract
from neo3.core import types


def to_script_hash(address: str, version: int) -> types.UInt160:
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


def to_address(script_hash: types.UInt160, version: int) -> str:
    """
    Converts the specified script hash to an address.

    Args:
        script_hash: script hash to convert
        version: address version
    """
    data_ = version.to_bytes(1, 'little') + script_hash.to_array()

    return base58.b58encode_check(data_).decode('utf-8')
