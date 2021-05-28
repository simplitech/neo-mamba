from __future__ import annotations
import base64
from typing import List
from jsonschema import validate  # type: ignore
from neo3 import contracts


class AccountContract(contracts.Contract):
    _contract_params_schema = {
        "type": ["object", "null"],
        "properties": {
            "name": {"type": "string"},
            "type": {"type": "string"}
        },
        "required": ["name", "type"]
    }
    _json_schema = {
        "type": ["object", "null"],
        "properties": {
            "script": {"type": "string"},
            "parameters": {
                "type": "array",
                "items": _contract_params_schema,
                "minItems": 0,
            },
            "deployed": {"type": "boolean"}
        },
        "required": ["script", "parameters", "deployed"]
    }

    def __init__(self, script: bytes, parameter_list: List[contracts.ContractParameterDefinition]):
        super().__init__(script, [param.type for param in parameter_list])

        self.parameter_names: List[str] = [param.name for param in parameter_list]
        self.deployed: bool = False

    @classmethod
    def from_contract(cls, contract: contracts.Contract) -> AccountContract:
        if isinstance(contract, AccountContract):
            return contract

        parameters = [contracts.ContractParameterDefinition(f"arg{index}", contract.parameter_list[index])
                      for index in range(len(contract.parameter_list))]
        return cls(script=contract.script,
                   parameter_list=parameters)

    @classmethod
    def from_json(cls, json: dict) -> AccountContract:
        """
        Parse object out of JSON data.

        Args:
            json: a dictionary.
        """
        validate(json, schema=cls._json_schema)

        contract = cls(
            script=base64.b64decode(json['script']),
            parameter_list=list(map(lambda p: contracts.ContractParameterDefinition.from_json(p), json['parameters']))
        )
        contract.deployed = json['deployed']

        return contract

    def to_json(self) -> dict:
        """ Convert object into JSON representation. """
        return {
            'script': base64.b64encode(self.script).decode('utf-8'),
            'parameters': list(map(lambda index: {'name': self.parameter_names[index],
                                                  'type': self.parameter_list[index].PascalCase()
                                                  },
                                   range(len(self.parameter_list)))),
            'deployed': self.deployed
        }
