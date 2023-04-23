from __future__ import annotations

import random
from collections import UserList


Octet = int

OCTET_SIZE = 8
OCTET_MAX = 2**OCTET_SIZE - 1


def random_octet() -> Octet:
    return random.randint(0, OCTET_MAX)


class OctetString(UserList[Octet]):
    def to_str(self) -> str:
        return self.to_bytes().decode("utf-8")

    @classmethod
    def from_str(cls, value: str) -> OctetString:
        return cls.from_bytes(value.encode("utf-8"))

    def to_bytes(self) -> bytes:
        return bytes(self)

    @classmethod
    def from_bytes(cls, value: bytes) -> OctetString:
        return cls(value)

    def to_bytearray(self) -> bytearray:
        return bytearray(it for it in self)

    def oct_repr(self) -> str:
        return "[" + ", ".join(oct(it) for it in self) + "]"

    def hex_repr(self) -> str:
        return "[" + " ".join(hex(it)[2:].rjust(2, "0") for it in self) + "]"

    def diagnostic(self) -> str:
        return f"OctetString[{len(self)}]({self.hex_repr()[1:-1]})"

    def to_int(self) -> int:
        result = 0
        for it in self[::-1]:
            result <<= OCTET_SIZE
            result |= it
        return result

    @classmethod
    def from_int(cls, value: int) -> OctetString:
        result = cls()
        while value:
            result.append(value & OCTET_MAX)
            value >>= OCTET_SIZE
        return result

    @classmethod
    def random(cls, length: int) -> OctetString:
        return cls(random_octet() for _ in range(length))

    def __xor__(self, mask: OctetString) -> OctetString:
        return OctetString(it ^ m for it, m in zip(self, mask))
