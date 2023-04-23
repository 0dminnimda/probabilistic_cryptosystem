import hashlib

from .helpers import separate
from .octet_string import OctetString


def MGF(value: OctetString, out_len: int) -> OctetString:
    """Mask Generation Function implementation using the SHA-256 hash"""

    hash_len = hashlib.sha256().digest_size
    if out_len > (2**32 * hash_len):
        raise ValueError("Output length too large")

    num_blocks = -(-out_len // hash_len)
    byte_value = value.to_bytes()

    result = OctetString()
    for i in range(num_blocks):
        c = byte_value + i.to_bytes(4, "big")
        h = hashlib.sha256(c).digest()
        result.extend(h[: out_len - len(result)])
        if len(result) >= out_len:
            break

    assert len(result) == out_len
    return result


W_LEN = 20
SEED_LEN = 20
MAX_SIGN_LEN = 50


def sign(message: OctetString, max_len: int) -> OctetString:
    if max_len < W_LEN + SEED_LEN:
        raise ValueError("Yall ar stupid, make max_len bigger!")
    if len(message) >= 2**61 - SEED_LEN - 1:
        raise ValueError("Yall ar stupid, make message smaller!")

    seed = OctetString.random(SEED_LEN)
    w = MGF(seed + message, W_LEN)

    expanded_w = MGF(w, max_len - W_LEN)
    seed_mask, remain_mask = separate(expanded_w, SEED_LEN)
    masked_seed = seed ^ seed_mask
    return w + masked_seed + remain_mask


def verify(message: OctetString, max_len: int, signature: OctetString) -> bool:
    if max_len < W_LEN + SEED_LEN:
        raise ValueError("Yall ar stupid, make max_len bigger!")
    if len(message) >= 2**61 - SEED_LEN - 1:
        raise ValueError("Yall ar stupid, make message smaller!")

    w, masked_seed, remain_mask = separate(signature, W_LEN, SEED_LEN)

    expanded_w = MGF(w, max_len - W_LEN)
    seed_mask, remain_mask_current = separate(expanded_w, SEED_LEN)
    seed = masked_seed ^ seed_mask

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
