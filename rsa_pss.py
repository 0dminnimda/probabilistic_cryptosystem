from __future__ import annotations

import hashlib
import itertools
import random
from collections import UserList
from typing import Any, Iterable, TypeVar, Sequence


SequenceT = TypeVar("SequenceT", bound=Sequence[Any])


def separate(
    value: SequenceT, *indices, accumulate: bool = True
) -> Iterable[SequenceT]:
    """
    >>> s = "0123456789" * 3
    >>> first, second, third = separate(s, 10, 10)
    >>> first, second, third
    ('0123456789', '0123456789', '0123456789')
    >>> list(separate(s, 0, 10, 2))
    ['', '0123456789', '01', '234567890123456789']
    >>> list(separate(s, 0, 10, 12, accumulate=False))
    ['', '0123456789', '01', '234567890123456789']
    """

    if accumulate:
        indices = tuple(itertools.accumulate(indices))

    if indices:
        yield value[:indices[0]]  # type: ignore[misc]

    for ind1, ind2 in zip(indices, indices[1:]):
        yield value[ind1:ind2]  # type: ignore[misc]

    if indices:
        yield value[indices[-1]:]  # type: ignore[misc]


Octet = int


class OctetString(UserList[Octet]):
    def as_str(self) -> str:
        return "".join(chr(it) for it in self)

    def as_bytearray(self) -> bytearray:
        return bytearray(it for it in self)

    def oct_repr(self) -> str:
        return "[" + ", ".join(oct(it) for it in self) + "]"

    def hex_repr(self) -> str:
        return "[" + " ".join(hex(it)[2:].rjust(2, "0") for it in self) + "]"

    def diagnostic(self) -> str:
        return f"OctetString[{len(self)}]({self.hex_repr()[1:-1]})"


def random_octet() -> Octet:
    return random.randint(0, 2**8 - 1)


def random_octet_string(length: int) -> OctetString:
    return OctetString(random_octet() for i in range(length))


def MGF(value: OctetString, out_len: int) -> OctetString:
    """Mask Generation Function implementation using the SHA-256 hash"""

    hash_len = hashlib.sha256().digest_size
    if out_len > (2**32 * hash_len):
        raise ValueError("Output length too large")

    num_blocks = -(-out_len // hash_len)
    byte_value = bytes(value)

    result = OctetString()
    for i in range(num_blocks):
        c = byte_value + i.to_bytes(4, "big")
        h = hashlib.sha256(c).digest()
        result.extend(h[: out_len - len(result)])
        if len(result) >= out_len:
            break

    return result[:out_len]


def apply_mask(value: OctetString, mask: OctetString) -> OctetString:
    return OctetString(it ^ m for it, m in zip(value, mask))


W_LEN = 20
SEED_LEN = 20


def pss_sign(message: OctetString, max_len: int) -> OctetString:
    if max_len < W_LEN + SEED_LEN:
        raise ValueError("Yall ar stupid, make max_len bigger!")
    if len(message) >= 2**61 - SEED_LEN - 1:
        raise ValueError("Yall ar stupid, make message smaller!")

    seed = random_octet_string(SEED_LEN)
    w = MGF(seed + message, W_LEN)

    expanded_w = MGF(w, max_len - W_LEN)
    seed_mask, remain_mask = separate(expanded_w, SEED_LEN)
    masked_seed = apply_mask(seed, seed_mask)
    return w + masked_seed + remain_mask


def pss_verify(message: OctetString, max_len: int, signature: OctetString) -> bool:
    if max_len < W_LEN + SEED_LEN:
        raise ValueError("Yall ar stupid, make max_len bigger!")
    if len(message) >= 2**61 - SEED_LEN - 1:
        raise ValueError("Yall ar stupid, make message smaller!")

    w, masked_seed, remain_mask = separate(signature, W_LEN, SEED_LEN)

    expanded_w = MGF(w, max_len - W_LEN)
    seed_mask, remain_mask_current = separate(expanded_w, SEED_LEN)
    seed = apply_mask(masked_seed, seed_mask)

    w_current = MGF(seed + message, W_LEN)
    if w != w_current:
        print(
            "ERROR: 'w' is different for signature and current: "
            + f"{w.diagnostic()} != {w_current.diagnostic()}"
        )
        return False

    if remain_mask != remain_mask_current:
        print(
            "ERROR: 'remain_mask' is different for signature and current: "
            + f"{remain_mask.diagnostic()} != {remain_mask_current.diagnostic()}"
        )
        return False

    return True


MAX_SIGN_LEN = 50

print()
inp = random_octet_string(69)
print(inp.diagnostic())

print()
signature = pss_sign(inp, MAX_SIGN_LEN)
print(signature.diagnostic())

print()
is_valid = pss_verify(inp, MAX_SIGN_LEN, signature)
print(is_valid)

print()
is_valid2 = pss_verify(OctetString([inp[0] + 1, *inp[1:]]), MAX_SIGN_LEN, signature)
print(is_valid2)

print()
is_valid2 = pss_verify(
    inp, MAX_SIGN_LEN, OctetString([signature[0] + 1, *signature[1:]])
)
print(is_valid2)

print()
is_valid3 = pss_verify(
    inp, MAX_SIGN_LEN, OctetString([*signature[:-1], signature[-1] + 1])
)
print(is_valid3)
