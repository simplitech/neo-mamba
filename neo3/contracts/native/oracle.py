from __future__ import annotations
from typing import Optional, cast, List, Tuple
from . import NativeContract
from neo3 import contracts, storage, vm
from neo3.core import types, cryptography, serialization, to_script_hash
from neo3.network import payloads


class OracleRequest(serialization.ISerializable):
    def __init__(self,
                 original_tx_id: types.UInt256,
                 gas_for_response: int,
                 url: str,
                 filter: str,
                 callback_contract: types.UInt160,
                 callback_method: str,
                 user_data: bytes
                 ):
        self.original_tx_id = original_tx_id
        self.gas_for_response = gas_for_response
        self.url = url
        self.filter = filter
        self.callback_contract = callback_contract
        self.callback_method = callback_method
        self.user_data = user_data

    def __len__(self):
        return len(self.to_array())

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        writer.write_serializable(self.original_tx_id)
        writer.write_uint64(self.gas_for_response)
        writer.write_var_string(self.url)
        writer.write_var_string(self.filter)
        writer.write_serializable(self.callback_contract)
        writer.write_var_string(self.callback_method)
        writer.write_var_bytes(self.user_data)

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        self.original_tx_id = reader.read_serializable(types.UInt256)
        self.gas_for_response = reader.read_uint64()
        self.url = reader.read_var_string()
        self.filter = reader.read_var_string()
        self.callback_contract = reader.read_serializable(types.UInt160)
        self.callback_method = reader.read_var_string()
        self.user_data = reader.read_var_bytes()

    @classmethod
    def _serializable_init(cls):
        return cls(types.UInt256.zero(), 0, "", "", types.UInt160.zero(), "", b'')


class OracleContract(NativeContract):
    _MAX_URL_LENGTH = 256
    _MAX_FILTER_LEN = 128
    _MAX_CALLBACK_LEN = 32
    _MAX_USER_DATA_LEN = 512
    _PREFIX_NODE_LIST = b'\x08'
    _PREFIX_REQUEST_ID = b'\x09'
    _PREFIX_REQUEST = b'\x07'
    _PREFIX_ID_LIST = b'\x06'

    _ORACLE_REQUEST_PRICE = 50000000

    _id = -4
    _service_name = "Oracle"

    def init(self):
        super(OracleContract, self).init()
        self.manifest.features = contracts.ContractFeatures.HAS_STORAGE

        self._register_contract_method(self.finish,
                                       "finish",
                                       0,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       safe_method=False)

        self._register_contract_method(self._request,
                                       "request",
                                       self._ORACLE_REQUEST_PRICE,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       safe_method=False)

        self._register_contract_method(self.get_oracle_nodes,
                                       "getOracleNodes",
                                       1000000,
                                       return_type=List[types.UInt160],
                                       add_engine=False,
                                       add_snapshot=True,
                                       safe_method=True)

        self._register_contract_method(self._set_oracle_nodes,
                                       "setOracleNodes",
                                       0,
                                       return_type=None,
                                       add_engine=True,
                                       add_snapshot=False,
                                       safe_method=False)

        self._register_contract_method(self._verify,
                                       "verify",
                                       1000000,
                                       return_type=bool,
                                       add_engine=True,
                                       add_snapshot=False,
                                       safe_method=True)

    def _initialize(self, engine: contracts.ApplicationEngine) -> None:
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_NODE_LIST),
            storage.StorageItem(b'\x00')  # number of items in the list
        )
        engine.snapshot.storages.put(
            storage.StorageKey(self.script_hash, self._PREFIX_REQUEST_ID),
            storage.StorageItem(b'\x00' * 8)  # uint64
        )

    def finish(self, engine: contracts.ApplicationEngine) -> None:
        tx = engine.script_container
        tx = cast(payloads.Transaction, tx)
        response = tx.try_get_attribute(payloads.OracleResponse)
        if response is None:
            raise ValueError("Oracle response not found")

        request = self.get_request(engine.snapshot, response.id)
        if request is None:
            raise ValueError("Oracle request not found")

        user_data = contracts.BinarySerializer.deserialize(request.user_data,
                                                           engine.MAX_STACK_SIZE,
                                                           engine.MAX_ITEM_SIZE,
                                                           engine.reference_counter)
        args: List[vm.StackItem] = [vm.ByteStringStackItem(request.url.encode()),
                                    user_data,
                                    vm.IntegerStackItem(int(response.code)),
                                    vm.ByteStringStackItem(response.result)]

        engine.call_from_native(None, request.callback_contract, request.callback_method, args)

    def get_request(self, snapshot: storage.Snapshot, id: int) -> Optional[OracleRequest]:
        id_bytes = id.to_bytes(8, 'little', signed=False)
        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_REQUEST + id_bytes)
        storage_item = snapshot.storages.try_get(storage_key)
        if storage_item is None:
            return None

        return OracleRequest.deserialize_from_bytes(storage_item.value)

    def _get_url_hash(self, url: str) -> bytes:
        return to_script_hash(url.encode('utf-8')).to_array()

    def _get_original_txid(self, engine: contracts.ApplicationEngine) -> types.UInt256:
        tx = cast(payloads.Transaction, engine.script_container)
        response = tx.try_get_attribute(payloads.OracleResponse)
        if response is None:
            return tx.hash()
        request = self.get_request(engine.snapshot, response.id)
        if request is None:
            raise ValueError  # C# will throw null pointer access exception
        return request.original_tx_id

    def _request(self,
                 engine: contracts.ApplicationEngine,
                 url: str,
                 filter: str,
                 callback: str,
                 user_data: vm.StackItem,
                 gas_for_response: int) -> None:
        if len(url.encode('utf-8')) > self._MAX_URL_LENGTH or \
                len(filter.encode('utf-8')) > self._MAX_FILTER_LEN or \
                len(callback.encode('utf-8')) > self._MAX_CALLBACK_LEN or \
                gas_for_response < 10000000:
            raise ValueError

        engine.add_gas(gas_for_response)
        self._gas.mint(engine, self.script_hash, vm.BigInteger(gas_for_response))

        sk_item_id = storage.StorageKey(self.script_hash, self._PREFIX_REQUEST_ID)
        si_item_id = engine.snapshot.storages.get(sk_item_id, read_only=False)
        item_id = int.from_bytes(si_item_id.value, 'little', signed=False)
        si_item_id.value = item_id.to_bytes(8, 'little', signed=False)

        if engine.snapshot.contracts.try_get(engine.calling_scripthash) is None:
            raise ValueError

        sk_request = storage.StorageKey(self.script_hash, self._PREFIX_REQUEST + si_item_id.value)
        oracle_request = OracleRequest(self._get_original_txid(engine),
                                       gas_for_response,
                                       url,
                                       filter,
                                       engine.calling_scripthash,
                                       callback,
                                       contracts.BinarySerializer.serialize(user_data, self._MAX_USER_DATA_LEN))
        engine.snapshot.storages.put(sk_request, storage.StorageItem(oracle_request.to_array()))

        sk_id_list = storage.StorageKey(self.script_hash, self._PREFIX_ID_LIST + self._get_url_hash(url))
        si_id_list = engine.snapshot.storages.try_get(sk_id_list, read_only=False)
        if si_id_list is None:
            si_id_list = storage.StorageItem(b'\x00')

        with serialization.BinaryReader(si_id_list.value) as reader:
            count = reader.read_var_int()
            id_list = []
            for _ in range(count):
                id_list.append(reader.read_uint64())

        id_list.append(item_id)
        with serialization.BinaryWriter() as writer:
            for id in id_list:
                writer.write_uint64(id)
            si_id_list.value = writer.to_array()
        engine.snapshot.storages.update(sk_id_list, si_id_list)

    def get_oracle_nodes(self, snapshot: storage.Snapshot) -> List[cryptography.ECPoint]:
        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_NODE_LIST)
        storage_item = snapshot.storages.get(storage_key)
        with serialization.BinaryReader(storage_item.value) as reader:
            return reader.read_serializable_list(cryptography.ECPoint)

    def _set_oracle_nodes(self, engine: contracts.ApplicationEngine, nodes: List[cryptography.ECPoint]) -> None:
        nodes.sort()
        storage_key = storage.StorageKey(self.script_hash, self._PREFIX_NODE_LIST)
        with serialization.BinaryWriter() as writer:
            writer.write_serializable_list(nodes)
            storage_item = storage.StorageItem(writer.to_array())
        engine.snapshot.storages.update(storage_key, storage_item)

    def _verify(self, engine: contracts.ApplicationEngine) -> bool:
        tx = engine.script_container
        if not isinstance(tx, payloads.Transaction):
            return False
        return bool(tx.try_get_attribute(payloads.OracleResponse))

    def post_persist(self, engine: contracts.ApplicationEngine) -> None:
        super(OracleContract, self).post_persist(engine)
        nodes = []
        for tx in engine.snapshot.transactions:
            response = tx.try_get_attribute(payloads.OracleResponse)
            if response is None:
                continue

            # remove request from storage
            sk_request = storage.StorageKey(self.script_hash, self._PREFIX_REQUEST + response.id.to_bytes(8, 'little'))
            si_request = engine.snapshot.storages.get(sk_request)
            request = OracleRequest.deserialize_from_bytes(si_request.value)
            engine.snapshot.storages.delete(sk_request)

            # remove id from id list
            sk_id_list = storage.StorageKey(self.script_hash, self._PREFIX_ID_LIST + self._get_url_hash(request.url))
            si_id_list = engine.snapshot.storages.try_get(sk_id_list, read_only=False)
            if si_id_list is None:
                si_id_list = storage.StorageItem(b'\x00')

            with serialization.BinaryReader(si_id_list.value) as reader:
                count = reader.read_var_int()
                id_list = []
                for _ in range(count):
                    id_list.append(reader.read_uint64())

            id_list.remove(response.id)
            if len(id_list) == 0:
                engine.snapshot.storages.delete(sk_id_list)

            # mint gas for oracle nodes
            nodes_public_keys = self.get_oracle_nodes(engine.snapshot)
            for public_key in nodes_public_keys:
                nodes.append((
                    to_script_hash(contracts.Contract.create_signature_redeemscript(public_key)),
                    vm.BigInteger.zero()
                ))

        for pair in nodes:  # type: Tuple[types.UInt160, vm.BigInteger]
            if pair[1].sign > 0:
                self._gas.mint(engine, pair[0], pair[1])