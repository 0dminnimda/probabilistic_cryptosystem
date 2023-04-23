from __future__ import annotations
import ast

import hashlib
import itertools
import random
import math
from collections import UserList
from typing import Any, Iterable, TypeVar, Sequence
import numpy as np


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
        yield value[: indices[0]]  # type: ignore[misc]

    for ind1, ind2 in zip(indices, indices[1:]):
        yield value[ind1:ind2]  # type: ignore[misc]

    if indices:
        yield value[indices[-1] :]  # type: ignore[misc]


### PSS ###


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

    seed = OctetString.random(SEED_LEN)
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


### Primality ###


def Miller_Rabin_test(n: int, s: int, d: int) -> bool:
    a = random.randint(2, n - 2)
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
        if x == 1:
            return False
    return False


def is_prime_Miller_Rabin(n: int, ntests: int = 10) -> bool:
    """Tests if n is prime using the probabilistic Miller-Rabin primality test."""

    # Ensure input requirements
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    # Compute s and d such that n - 1 = d * 2^s, where d is odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Perform ntests iterations of the Miller-Rabin test
    return all(Miller_Rabin_test(n, s, d) for _ in range(ntests))


def integer_root_guess(
    n: int, p: int = 2, upper_bound: bool = False, lower_bound: bool = False
) -> int:
    """
    Creates a good guess for integer_root(n, p).
    """
    shift = math.log(n, p) / p
    if upper_bound:
        return p ** math.ceil(shift)
    if lower_bound:
        return p ** math.floor(shift)
    # minimize the average error
    return (p ** math.ceil(shift) + p ** math.floor(shift)) // 2


def integer_root(n: int, p: int = 2) -> int:
    """
    Computes the integer square root (i.e., the largest integer x such that x^p <= n)
    using the Newton's method.
    """
    if n < 0:
        raise ValueError("math domain error")
    if n <= 1:
        return n

    p1 = p - 1
    # it needs to be an upper bound,
    # because I don't know what is the termination condition
    # for guesses wich can be on both sides of the solution
    x = integer_root_guess(n, upper_bound=True)
    while 1:
        y = (p1*x + n // x**p1) // p
        if y >= x:
            break
        x = y
    return x


def is_prime_trial_division(n: int) -> bool:
    """Tests if n is prime using the deterministic Trial Division primality test."""

    # Ensure input requirements
    if n <= 2:
        return n == 2
    if n % 2 == 0:
        return False

    # Check odd divisors up to the square root of n
    for i in range(3, integer_root(n) + 1, 2):
        if n % i == 0:
            return False

    return True


def is_perfect_power(n: int) -> bool:
    """
    Returns True if n is a perfect power (i.e. n=m^k for some integers m>1 and k>1).
    False otherwise.
    """
    if n <= 2:
        return False

    return any(
        base ** int(math.log(n, base)) == n for base in range(2, n.bit_length() + 1)
    )


def is_perfect_power_helper(n: int, p: int) -> bool:
    left, right = 1, integer_root_guess(n, p)
    while left <= right:
        mid = (left + right) // 2
        mid_pow = mid**p
        if mid_pow < n:
            left = mid + 1
        elif mid_pow > n:
            right = mid - 1
        else:
            return True
    return False


def is_perfect_power2(n: int) -> bool:
    if n <= 2:
        return False

    return any(
        is_perfect_power_helper(n, base) for base in range(2, n.bit_length() + 1)
    )


def is_perfect_power_binary_search(n):
    if n <= 2:
        return False

    low = 2
    high = n.bit_length()
    while low <= high:
        mid = (low + high) // 2
        exped = integer_root(n, mid) ** mid
        if exped < n:
            low = mid + 1
        elif exped > n:
            high = mid - 1
        else:
            return True
    return False


def is_prime(n: int) -> bool:
    # still probabilistic, but is really unlikely
    # if 64 iterations is cryptographically accepted for 512 bits
    # as well as 128 iterations for 1024 bits
    # then the min(10, bits // 8) is an ok general rule
    return (
        is_prime_Miller_Rabin(n, max(10, n.bit_length() // 8))
        and not is_perfect_power(n)
    )


# for i in range(10**7):
#     a = is_prime_trial_division(i)
#     b = is_prime(i)
#     if a != b:
#         print(i, a, b)
#     if i % 50000 == 0:
#         print(i)


def generate_prime_candidate(nbits: int) -> Iterable[int]:
    """Generates a random candidate prime number in the form 6k ± 1 with nbits bits."""
    while True:
        candidate = 6 * random.getrandbits(nbits - 2) + random.choice((-1, 1))
        candidate |= 1  # Make sure the number is odd
        candidate |= 1 << (nbits - 1)  # Make sure the number has nbits bits
        yield candidate


def generate_prime(nbits: int) -> int:
    """Generates a random prime number in the form 6k ± 1 with nbits bits."""
    for candidate in generate_prime_candidate(nbits):
        if is_prime(candidate):
            return candidate
    assert False, "Unreachable"


### RSA ###


def xgcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm."""
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = divmod(b, a)
        b, a = a, r
        x, y, u, v = u, v, x - u * q, y - v * q
    return b, x, y


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm."""
    if a == 0:
        return (b, 0, 1)
    else:
        g, y, x = egcd(b % a, a)
        return (g, x - (b // a) * y, y)


def modinv(a: int, m: int) -> int:
    """Calculates the modular multiplicative inverse of a modulo m."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m


def rsa_choose_public_exponent(phi: int) -> int:
    """Chooses a random prime number as the public exponent."""
    while True:
        e = random.randrange(3, phi, 2)  # Choose a random odd number between 3 and phi
        if math.gcd(e, phi) == 1:
            return e


Key = tuple[int, int]


def rsa_generate_keypair(p: int, q: int) -> tuple[Key, Key]:
    """Generates an RSA keypair with the given prime numbers p and q."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = rsa_choose_public_exponent(phi)
    d = modinv(e, phi)
    return ((e, n), (d, n))


def rsa_generate_keypair_of_sizes(s1: int, s2: int) -> tuple[Key, Key]:
    return rsa_generate_keypair(generate_prime(s1), generate_prime(s2))


def rsa_encode(number: int, private_key: Key) -> int:
    return pow(number, *private_key)


def rsa_decode(number: int, public_key: Key) -> int:
    return pow(number, *public_key)


MAX_SIGN_LEN = 50


def send(message: bytes) -> tuple[bytes, int, Key]:
    print("=" * 15 + " Sender " + "=" * 15)

    oct_msg = OctetString.from_bytes(message)
    print(message)
    print(oct_msg.diagnostic())

    pss_signature = pss_sign(oct_msg, MAX_SIGN_LEN)
    print(pss_signature.diagnostic())

    numeric_repr = pss_signature.to_int()
    print(numeric_repr)

    prime_size = numeric_repr.bit_length() // 2 + 1
    public, private = rsa_generate_keypair_of_sizes(prime_size, prime_size)
    print(public)
    print(private)

    rsa_signature = rsa_encode(numeric_repr, private)
    print(rsa_signature)

    return message, rsa_signature, public


def recieve(message: bytes, rsa_signature: int, public: Key) -> bool:
    print("=" * 15 + " Reciever " + "=" * 15)

    numeric_repr = rsa_decode(rsa_signature, public)
    print(numeric_repr)

    oct_msg = OctetString.from_bytes(message)
    print(oct_msg.diagnostic())

    pss_signature = OctetString.from_int(numeric_repr)
    print(pss_signature.diagnostic())

    is_valid = pss_verify(oct_msg, MAX_SIGN_LEN, pss_signature)
    print("Valid" if is_valid else "Invalid")
    try:
        print(message.decode("utf-8"))
    except UnicodeDecodeError:
        print(message)

    return is_valid


def error_test(message: bytes) -> None:
    print("=" * 15 + " Error tests " + "=" * 15)
    inp = OctetString.from_bytes(message)
    pss_signature = pss_sign(inp, MAX_SIGN_LEN)

    is_valid = pss_verify(
        OctetString([inp[0] + 1, *inp[1:]]), MAX_SIGN_LEN, pss_signature
    )
    print("Valid" if is_valid else "Invalid")

    is_valid = pss_verify(
        inp, MAX_SIGN_LEN, OctetString([pss_signature[0] + 1, *pss_signature[1:]])
    )
    print("Valid" if is_valid else "Invalid")

    is_valid = pss_verify(
        inp, MAX_SIGN_LEN, OctetString([*pss_signature[:-1], pss_signature[-1] + 1])
    )
    print("Valid" if is_valid else "Invalid")


operation = input("Send message/Recieve message/Both? (s/r/b) [b]: ") or "b"

if "b" in operation:
    operation = "sr"

data: tuple[bytes, int, Key]
if "s" in operation:
    if int(input("Do you want to use random message? (0/1) [1]: ") or "1"):
        message = OctetString.random(69).to_bytes()
    else:
        message = input("Then input the message: ").encode("utf-8")

    data = send(message)
    print("Sending:", data)
else:
    data = ast.literal_eval(input("Then input the sent data: "))
    assert type(data) is tuple
    assert len(data) == 3

if "r" in operation:
    assert recieve(*data)

error_test(data[0])
