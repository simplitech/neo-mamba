import hashlib
from typing import List
from neo3.network import payloads
from neo3.core import types, serialization
from neo3 import vm, contracts, blockchain, storage


def syscall_name_to_int(name: str) -> int:
    return int.from_bytes(hashlib.sha256(name.encode()).digest()[:4], 'little', signed=False)


def test_engine(has_container=False, has_snapshot=False, default_script=True):
    tx = payloads.Transaction._serializable_init()

    # this little hack basically nullifies the singleton behaviour and ensures we create
    # a new instance every time we call it. This in turn gives us a clean backend/snapshot
    blockchain.Blockchain.__it__ = None

    snapshot = blockchain.Blockchain(store_genesis_block=False).currentSnapshot
    if has_container and has_snapshot:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, snapshot, 0, test_mode=True)
    elif has_container:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, tx, None, 0, test_mode=True)
    elif has_snapshot:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, None, snapshot, 0, test_mode=True)
    else:
        engine = contracts.ApplicationEngine(contracts.TriggerType.APPLICATION, None, None, 0, test_mode=True)

    if default_script:
        engine.load_script(vm.Script(b'\x40'))  # OpCode::RET
    return engine


def test_tx(with_block_height=1) -> payloads.Transaction:
    tx = payloads.Transaction(version=0,
                              nonce=123,
                              system_fee=456,
                              network_fee=789,
                              valid_until_block=1,
                              attributes=[],
                              signers=[payloads.Signer(types.UInt160.from_string("f782c7fbb2eef6afe629b96c0d53fb525eda64ce"))],
                              script=b'\x01',
                              witnesses=[])
    tx.block_height = with_block_height
    return tx


def test_block(with_index=1) -> payloads.Block:
    tx = test_tx(with_index)
    block1 = payloads.Block(version=0,
                            prev_hash=types.UInt256.from_string(
                                "f782c7fbb2eef6afe629b96c0d53fb525eda64ce5345057caf975ac3c2b9ae0a"),
                            timestamp=123,
                            index=with_index,
                            next_consensus=types.UInt160.from_string("d7678dd97c000be3f33e9362e673101bac4ca654"),
                            witness=payloads.Witness(invocation_script=b'', verification_script=b'\x55'),
                            consensus_data=payloads.ConsensusData(primary_index=1, nonce=123),
                            transactions=[tx])
    block1.rebuild_merkle_root()
    return block1


class TestIVerifiable(payloads.IVerifiable):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.script_hashes = [types.UInt160.zero()]

    def serialize(self, writer: serialization.BinaryWriter) -> None:
        pass

    def deserialize(self, reader: serialization.BinaryReader) -> None:
        pass

    def __len__(self):
        pass

    def serialize_unsigned(self, writer: serialization.BinaryWriter) -> None:
        pass

    def deserialize_unsigned(self, reader: serialization.BinaryReader) -> None:
        pass

    def get_script_hashes_for_verifying(self, snapshot: storage.Snapshot) -> List[types.UInt160]:
        return self.script_hashes
