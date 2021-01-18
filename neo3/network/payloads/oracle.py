from enum import IntEnum
from neo3.network import payloads
from neo3.core import Size as s, utils, serialization
from neo3 import storage, blockchain, vm, contracts
import base64


class OracleReponseCode(IntEnum):
    SUCCESS = 0x00
    NOT_FOUND = 0x10
    TIMEOUT = 0x12
    FORBIDDEN = 0x14
    ERROR = 0xFF


sb = vm.ScriptBuilder()
sb.emit_contract_call(contracts.native.OracleContract().script_hash, "finish")  # type: ignore
FIXED_ORACLE_SCRIPT = sb.to_array()


class OracleResponse(payloads.TransactionAttribute):
    _MAX_RESULT_SIZE = 1024

    def __init__(self, id: int, code: OracleReponseCode, result: bytes):
        super(OracleResponse, self).__init__()
        self.type_ = payloads.TransactionAttributeType.ORACLE_RESPONSE
        self.allow_multiple = False
        self.id = id
        self.code = code
        self.result = result

    def __len__(self):
        return s.uint64 + s.uint8 + utils.get_var_size(self.result)

    def _deserialize_without_type(self, reader: serialization.BinaryReader) -> None:
        self.id = reader.read_uint64()
        self.code = OracleReponseCode(reader.read_uint8())
        self.result = reader.read_var_bytes(self._MAX_RESULT_SIZE)
        if self.code != OracleReponseCode.SUCCESS and len(self.result) > 0:
            raise ValueError(f"Deserialization error - oracle response: {self.code}")

    def _serialize_without_type(self, writer: serialization.BinaryWriter) -> None:
        writer.write_uint64(self.id)
        writer.write_uint8(self.code)
        writer.write_var_bytes(self.result)

    def to_json(self) -> dict:
        json = super(OracleResponse, self).to_json()
        json.update({"id": id,
                     "code": self.code,
                     "result": base64.b64encode(self.result)}
                    )
        return json

    def verify(self, snapshot: storage.Snapshot, tx: payloads.Transaction) -> bool:
        if any(map(lambda signer: signer.scope != payloads.WitnessScope.NONE, tx.signers)):
            return False

        if tx.script != FIXED_ORACLE_SCRIPT:
            return False

        oracle = contracts.native.OracleContract()
        request = oracle.get_request(snapshot, self.id)
        if request is None:
            return False
        if tx.network_fee + tx.system_fee != request.gas_for_response:
            return False
        oracle_account = blockchain.Blockchain().get_consensus_address(oracle.get_oracle_nodes(snapshot))
        return any(map(lambda signer: signer.account == oracle_account, tx.signers))

    @classmethod
    def _serializable_init(cls):
        return cls(0, OracleReponseCode.ERROR, b'')