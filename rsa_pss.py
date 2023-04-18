py
from future import annotations

import hashlib
import random
import itertools
from collections import UserList


def separate(value, *indices, accum: bool = False):
    """
    >>> s = "0123456789" * 3
    >>> list(separate(s, 0, 10, 12))
    ['', '0123456789', '01', '234567890123456789']
    >>> list(separate(s, 0, 10, 2, accum=True))
    ['', '0123456789', '01', '234567890123456789']
    """

    if accumulate:
        indices = tuple(itertools.accumulate(indices))

    if indices:
        yield value[:indices[0]]

    for ind1, ind2 in zip(indices, indices[1:]):
        yield value[ind1 : ind2]

    if indices:
        yield value[indices[-1]:]


Octet = int


class OctetString(UserList[Octet]):
    def as_str(self) -> str:
        return "".join(chr(it) for it in self)

    def as_bytearray(self) -> bytearray:
        return bytearray(it for it in self)


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
        result.extend(h[:out_len - len(result)])
        if len(result) >= out_len:
            break

    return result[:out_len]


def apply_mask(value: OctetString, mask: OctetString) -> OctetString:
    return OctetString(it^m for it, m in zip(value, mask))


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
    seed_mask = expanded_w[:SEED_LEN]
    remain_mask = expanded_w[SEED_LEN:]
    masked_seed = apply_mask(seed, seed_mask)
    return w + masked_seed + remain_mask


def pss_verify(
    message: OctetString, max_len: int, signature: OctetString
) -> OctetString:

    if max_len < W_LEN + SEED_LEN:
        raise ValueError("Yall ar stupid, make max_len bigger!")
    if len(message) >= 2**61 - SEED_LEN - 1:
        raise ValueError("Yall ar stupid, make message smaller!")

    w_sign = signature[:W_LEN]
    masked_seed_sign = signature[W_LEN : W_LEN + SEED_LEN]
    remain_mask_sign = signature[W_LEN + SEED_LEN:]

    # w, masked_seed, remain_mask = separate(signature, W_LEN, SEED_LEN, accumulate=True)

    expanded_w = MGF(w_sign, max_len - W_LEN)
    seed_mask = expanded_w[:SEED_LEN]
    remain_mask = expanded_w[SEED_LEN:]
    seed = apply_mask(masked_seed_sign, seed_mask)

    w = MGF(seed + message, W_LEN)
    if w != w_sign:
        print(
            "w != w_sign: "
            + f"{w=}, {w_sign=}"
        )
        return False

    if remain_mask != remain_mask_sign:
        print(
            "remain_mask != remain_mask_sign: "
            + f"{remain_mask=}, {remain_mask_sign=}"
        )
        return False

    return True


def diagnostics(value: OctetString) -> None:
    print(f"OctetString[{len(value)}]:")
    print(value, repr(value.as_str()), sep="\n")


MAX_SIGN_LEN = 50
inp = random_octet_string(69)
signature = pss_sign(inp, MAX_SIGN_LEN)
is_valid = pss_verify(inp, MAX_SIGN_LEN, signature)

inp[0] += 1
is_valid2 = pss_verify(inp, MAX_SIGN_LEN, signature)

print("\n")
diagnostics(inp)
print("\n")
diagnostics(signature)
print("\n")
print(is_valid)
print(is_valid2)
