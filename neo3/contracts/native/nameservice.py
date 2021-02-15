from __future__ import annotations
import re
import ipaddress
from enum import IntEnum
from .nonfungible import NFTState, NonFungibleToken
from typing import Optional, Iterator, Tuple
from neo3 import contracts, storage, vm
from neo3.core import serialization, types


class RecordType(IntEnum):
    A = 1
    CNAME = 5
    TXT = 16
    AAAA = 28


class NameState(NFTState):
    def __init__(self,
                 owner: types.UInt160,
                 name: str,
                 description: str,
                 expiration: int,
                 admin: Optional[types.UInt160] = None):
        super(NameState, self).__init__(owner, name, description)
        self._expiration = expiration
        self._admin = admin if admin else types.UInt160.zero()
        self.storage_item = storage.StorageItem(b'')
        self.id = name.encode()

    def __len__(self):
        return len(self.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        super(NameState, self).serialize(writer)
        writer.write_uint32(self._expiration)
        writer.write_serializable(self._admin)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        super(NameState, self).deserialize(reader)
        self._expiration = reader.read_uint32()
        self._admin = reader.read_serializable(types.UInt160)

    @property
    def admin(self):
        return self._admin

    @admin.setter
    def admin(self, value):
        self._admin = value
        self.storage_item.value = self.to_array()

    @property
    def expiration(self):
        return self._expiration

    @expiration.setter
    def expiration(self, value):
        self._expiration = value
        self.storage_item.value = self.to_array()

    @classmethod
    def from_storage(cls, item: storage.StorageItem):
        c = cls.deserialize_from_bytes(item.value)
        c.storage_item = item
        return c

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt160.zero(), "", "", 0, types.UInt160.zero())


class StringList(list, serialization.ISerializable):
    def __init__(self):
        super().__init__()
        self.storage_item = storage.StorageItem(b'')

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_var_int(len(self))
        for i in self:
            writer.write_var_string(i)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        for _ in range(reader.read_var_int()):
            self.append(reader.read_var_string())

    def __setitem__(self, key, value):
        super(StringList, self).__setitem__(key, value)
        self.storage_item.value = self.to_array()

    def append(self, __object) -> None:
        super(StringList, self).append(__object)
        self.storage_item.value = self.to_array()

    @classmethod
    def from_storage(cls, item: storage.StorageItem):
        c = cls.deserialize_from_bytes(item.value)
        c.storage_item = item
        return c


class NameService(NonFungibleToken):
    _id = -6
    _symbol = "NNS"
    _service_name = None

    _PREFIX_ROOTS = b'\x0a'
    _PREFIX_DOMAIN_PRICE = b'\x16'
    _PREFIX_EXPIRATION = b'\x14'
    _PREFIX_RECORD = b'\x12'
    key_roots = storage.StorageKey(_id, _PREFIX_ROOTS)
    key_domain_price = storage.StorageKey(_id, _PREFIX_DOMAIN_PRICE)
    key_expiration = storage.StorageKey(_id, _PREFIX_EXPIRATION)
    key_record = storage.StorageKey(_id, _PREFIX_RECORD)

    ONE_YEAR = 365 * 24 * 3600
    REGEX_ROOT = re.compile("^[a-z][a-z0-9]{0,15}$")
    REGEX_NAME = re.compile("^(?=.{3,255}$)([a-z0-9]{1,62}\\.)+[a-z][a-z0-9]{0,15}$")

    def init(self):
        super(NameService, self).init()
        self._register_contract_method(self.add_root,
                                       "addRoot",
                                       3000000,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       parameter_names=["root"],
                                       parameter_types=[str],
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )
        self._register_contract_method(self.set_price,
                                       "setPrice",
                                       3000000,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       parameter_names=["price"],
                                       parameter_types=[int],
                                       call_flags=contracts.CallFlags.WRITE_STATES)
        self._register_contract_method(self.register,
                                       "register",
                                       1000000,
                                       return_type=bool,
                                       add_engine=True,
                                       add_snapshot=False,
                                       parameter_names=["name", "owner"],
                                       parameter_types=[str, types.UInt160],
                                       call_flags=contracts.CallFlags.WRITE_STATES
                                       )

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        super(NameService, self)._initialize(engine)
        engine.snapshot.storages.put(self.key_domain_price, storage.StorageItem(vm.BigInteger(1000000000).to_array()))

    def on_persist(self, engine: contracts.ApplicationEngine) -> None:
        now = vm.BigInteger((engine.snapshot.persisting_block.timestamp // 1000) + 1)
        start = (self.key_expiration + b'\x00').to_array()
        end = (self.key_expiration + now.to_array()).to_array()
        for key, _ in engine.snapshot.storages.find_range(start, end):
            engine.snapshot.storages.delete(key)
            for key2, _ in engine.snapshot.storages.find(self.key_record + key.key[5:]):
                engine.snapshot.storages.delete(key2)
            self.burn(engine, self.key_token + key.key[5:])

    def add_root(self, engine: contracts.ApplicationEngine, root: str) -> None:
        if not self.REGEX_ROOT.match(root):
            raise ValueError("Regex failure - root not found")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item_roots = engine.snapshot.storages.try_get(self.key_roots, read_only=False)
        if storage_item_roots is None:
            storage_item_roots = storage.StorageItem(b'\x00')
            engine.snapshot.storages.put(self.key_roots, storage_item_roots)

        roots = StringList.from_storage(storage_item_roots)
        if root in roots:
            raise ValueError("The name already exists")
        roots.append(root)

    def set_price(self, engine: contracts.ApplicationEngine, price: int) -> None:
        if price <= 0 or price > 10000_00000000:
            raise ValueError(f"New price '{price}' exceeds limits")
        if not self._check_committee(engine):
            raise ValueError("Check committee failed")
        storage_item = engine.snapshot.storages.get(self.key_domain_price, read_only=False)
        storage_item.value = price.to_bytes(8, 'little')

    def get_price(self, snapshot: storage.Snapshot) -> int:
        return int.from_bytes(snapshot.storages.get(self.key_domain_price, read_only=True).value, 'little')

    def is_available(self, snapshot: storage.Snapshot, name: str) -> bool:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        names = name.split(".")
        if len(names) != 2:
            raise ValueError("Invalid format")
        storage_item = snapshot.storages.try_get(self.key_token + name.encode(), read_only=True)
        if storage_item:
            return False
        storage_item_roots = snapshot.storages.try_get(self.key_roots, read_only=True)
        if storage_item_roots is None:
            raise ValueError("Can't find roots in storage")

        roots = StringList.from_storage(storage_item_roots)
        if names[1] not in roots:
            raise ValueError(f"'{names[1]}' is not a registered root")
        return True

    def register(self, engine: contracts.ApplicationEngine, name: str, owner: types.UInt160) -> bool:
        if not self.is_available(engine.snapshot, name):
            raise ValueError(f"Registration failure - '{name}' is not available")

        if not engine.checkwitness(owner):
            raise ValueError("CheckWitness failed")
        engine.add_gas(self.get_price(engine.snapshot))

        state = NameState(owner, name, "", (engine.snapshot.persisting_block.timestamp // 1000) + self.ONE_YEAR)
        self.mint(engine, state)
        engine.snapshot.storages.put(
            self.key_expiration + state.expiration.to_bytes(4, 'little') + name.encode(),
            storage.StorageItem(b'\x00')
        )
        return True

    def renew(self, engine: contracts.ApplicationEngine, name: str) -> int:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        names = name.split(".")
        if len(names) != 2:
            raise ValueError("Invalid format")
        storage_item_state = engine.snapshot.storages.get(self.key_token + name.encode(), read_only=False)
        state = NameState.from_storage(storage_item_state)
        state.expiration += self.ONE_YEAR
        return state.expiration

    def set_admin(self, engine: contracts.ApplicationEngine, name: str, admin: types.UInt160) -> None:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        names = name.split(".")

        if len(names) != 2:
            raise ValueError("Invalid format")

        if admin != types.UInt160.zero() and not engine.checkwitness(admin):
            raise ValueError("New admin is not valid - check witness failed")

        state = NameState.from_storage(engine.snapshot.storages.get(self.key_token + name.encode()))
        if not engine.checkwitness(state.owner):
            raise ValueError

        state.admin = admin

    def _check_admin(self, engine: contracts.ApplicationEngine, state: NameState) -> bool:
        if engine.checkwitness(state.owner):
            return True

        if state.admin == types.UInt160.zero:
            return False

        return engine.checkwitness(state.admin)

    def set_record(self, engine: contracts.ApplicationEngine, name: str, record_type: RecordType, data: str) -> None:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")

        if record_type == RecordType.A:
            # we only validate if the data is a valid IPv4 address
            ipaddress.IPv4Address(data)
        elif record_type == RecordType.CNAME:
            if not self.REGEX_NAME.match(data):
                raise ValueError("Invalid CNAME")
        elif record_type == RecordType.TXT:
            if len(data) > 255:
                raise ValueError("TXT data exceeds maximum length of 255")
        elif record_type == RecordType.AAAA:
            # we only validate if the data is a valid IPv6 address
            ipaddress.IPv6Address(data)

        domain = '.'.join(name.split('.')[2:])
        state = NameState.from_storage(engine.snapshot.storages.get(self.key_token + domain.encode()))
        if not self._check_admin(engine, state):
            raise ValueError("Admin check failed")

        storage_key_record = self.key_record + domain.encode() + name.encode() + record_type.to_bytes(2, 'little')
        engine.snapshot.storages.update(storage_key_record, storage.StorageItem(data.encode()))

    def get_record(self, snapshot: storage.Snapshot, name: str, record_type: RecordType) -> Optional[str]:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        domain = '.'.join(name.split('.')[2:])
        storage_key_record = self.key_record + domain.encode() + name.encode() + record_type.to_bytes(2, 'little')
        storage_item = snapshot.storages.try_get(storage_key_record)
        if storage_item is None:
            return None
        return storage_item.value.decode()

    def get_records(self, snapshot: storage.Snapshot, name: str) -> Iterator[Tuple[RecordType, str]]:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")
        domain = '.'.join(name.split('.')[2:])
        storage_key = self.key_record + domain.encode() + name.encode()
        for key, value in snapshot.storages.find(storage_key.to_array()):
            record_type = RecordType(int.from_bytes(key.key[:-2], 'little'))
            yield record_type, value.value.decode()

    def delete_record(self, engine: contracts.ApplicationEngine, name: str, record_type: RecordType) -> None:
        if not self.REGEX_NAME.match(name):
            raise ValueError("Regex failure - name is not valid")

        domain = '.'.join(name.split('.')[2:])
        state = NameState.from_storage(engine.snapshot.storages.get(self.key_token + domain.encode()))
        if not self._check_admin(engine, state):
            raise ValueError("Admin check failed")

        storage_key_record = self.key_record + domain.encode() + name.encode() + record_type.to_bytes(2, 'little')
        engine.snapshot.storages.delete(storage_key_record)

    def resolve(self,
                snapshot: storage.Snapshot,
                name: str,
                record_type: RecordType,
                redirect_count: int = 2) -> Optional[str]:
        if redirect_count < 0:
            raise ValueError("Redirect count can't be negative")
        records = {}
        for key, value in self.get_records(snapshot, name):
            records.update({key: value})
        if record_type in records:
            return records[record_type]
        data = records.get(RecordType.CNAME, None)
        if data is None:
            return None
        return self.resolve(snapshot, data, record_type, redirect_count - 1)