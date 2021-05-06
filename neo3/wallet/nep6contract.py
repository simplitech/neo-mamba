from __future__ import annotations

from typing import List

from neo3 import contracts


class NEP6Contract(contracts.Contract):

    def __init__(self, script: bytes, parameter_list: List[contracts.ContractParameterType]):
        super().__init__(script, parameter_list)
        self.parameter_names: List[str] = []
        self.deployed: bool = False
