from __future__ import annotations

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


### RSA ###


def generate_prime_candidate(nbits: int) -> Iterable[int]:
    """Generates a random candidate prime number in the form 6k ± 1 with nbits bits."""
    while True:
        candidate = 6 * random.getrandbits(nbits - 2) + random.choice((-1, 1))
        candidate |= 1  # Make sure the number is odd
        candidate |= 1 << (nbits - 1)  # Make sure the number has nbits bits
        yield candidate


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
    if n <= 2:
        return n == 2
    if n % 2 == 0:
        return False

    # Compute s and d such that n - 1 = d * 2^s, where d is odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Perform ntests iterations of the Miller-Rabin test
    return all(Miller_Rabin_test(n, s, d) for _ in range(ntests))


def is_prime_trial_division(n: int) -> bool:
    """Tests if n is prime using the deterministic Trial Division primality test."""

    # Ensure input requirements
    if n <= 2:
        return n == 2
    if n % 2 == 0:
        return False

    # Check odd divisors up to the square root of n
    for i in range(3, int(n**0.5) + 1, 2):
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

    for base in range(2, n.bit_length() + 1):
        exponent = round(math.log(n, base))
        if base**exponent == n:
            return True
    return False


def multiplicative_order(a: int, n: int) -> int:
    """
    Returns the smallest positive integer k such that a^k ≡ 1 (mod n),
    or -1 if no such integer exists.
    """
    if math.gcd(a, n) != 1:
        # a and n are not coprime, so no multiplicative order exists
        return -1
    order = 1
    while pow(a, order, n) != 1:
        order += 1
    return order


# def poly_mod_n(r, n):
#     # computes the value of the polynomial (x-1)^n - (x^n - 1) modulo (x^r - 1, n)
#     f = [0] * (r + 1)
#     f[0] = -1
#     f[r] = 1
#     g = [0] * (r + 1)
#     g[0] = 1
#     g[n % (r + 1)] = -1
#     prod = [0] * (2 * r + 1)
#     for i in range(r + 1):
#         for j in range(r + 1):
#             prod[i + j] += f[i] * g[j]
#     for i in range(r, 0, -1):
#         prod[i] = prod[i - 1] - prod[i] * n
#     prod[0] = -prod[0] * n
#     return prod[r]


# def poly_mod(r: int, n: int, a: int) -> int:
#     """
#     Computes the value of the polynomial (x+a)^n - (x^n + a) modulo (x^r - 1, n)
#     """
#     f = [0] * (r + 1)
#     f[0] = -a
#     f[r] = 1
#     g = [0] * (r + 1)
#     g[0] = 1
#     g[n % (r + 1)] = -1
#     prod = [0] * (2 * r + 1)
#     for i in range(r + 1):
#         for j in range(r + 1):
#             prod[i + j] += f[i] * g[j]
#     for i in range(r, 0, -1):
#         prod[i] = prod[i - 1] - prod[i] * n
#     prod[0] = -prod[0] * n
#     return prod[r] + a

'''
def poly_mod(r: int, n: int, a: int) -> int:
    """
    Computes the value of the polynomial (x+a)^n - (x^n + a) modulo (x^r - 1, n)
    """
    # Calculate (x+a)^n
    poly1 = [(a**n)%n, 1]    # (a^n + 1*x^0)
    for i in range(n):
        poly1 = poly_mul(poly1, [(a%n), 1])   # (a^n + nC1*a^(n-1)*x + ...)

    # Calculate x^n + a
    poly2 = [(a%n), 1]    # (a + 1*x^0)
    for i in range(n):
        poly2 = poly_mul(poly2, [0, 1])   # (0*x^(n+1) + a*x^n + ...)

    # Calculate (x^r - 1)
    poly3 = [1] + [0]*(r-1)   # (1*x^r-1 + 0*x^(r-2) + ...)
    poly3[-1] = -1   # (1*x^r-1 + 0*x^(r-2) + ... - 1)

    # Multiply (x+a)^n by -1 and subtract x^n + a
    result = poly_sub(poly_mul(poly1, [-1, 1]), poly2)

    # Take the result modulo (x^r - 1, n)
    result = poly_div(result, poly3)[1]
    return result[0] % n


def poly_mul(poly1, poly2):
    """
    Multiplies two polynomials and returns the result
    """
    result = [0]*(len(poly1)+len(poly2)-1)
    for i in range(len(poly1)):
        for j in range(len(poly2)):
            result[i+j] += poly1[i]*poly2[j]
    return result


def poly_sub(poly1, poly2):
    """
    Subtracts two polynomials and returns the result
    """
    result = [0]*max(len(poly1), len(poly2))
    for i in range(len(poly1)):
        result[i] += poly1[i]
    for i in range(len(poly2)):
        result[i] -= poly2[i]
    return result


def poly_div(poly1, poly2):
    """
    Divides two polynomials and returns the quotient and remainder
    """
    if len(poly1) < len(poly2):
        return [], poly1
    elif len(poly2) == 1:
        return [poly1[i]//poly2[0] for i in range(len(poly1))], [poly1[i]%poly2[0] for i in range(len(poly1))]
    else:
        q = [0]*(len(poly1)-len(poly2)+1)
        r = poly1[:]
        for i in range(len(q)-1, -1, -1):
            q[i] = r[i+len(poly2)-1] // poly2[-1]
            for j in range(len(poly2)):
                r[i+j+len(poly2)-1] -= q[i] * poly2[j]
        return q, r

'''


def poly_mod(r: int, n: int, a: int) -> int:
    """
    Computes the value of the polynomial (x+a)^n - (x^n + a) modulo (x^r - 1, n)
    """
    sub = np.poly1d([1, a])**n - (np.poly1d([1] + [0]*n) + np.poly1d([a]))
    _, rem = sub / (np.poly1d([1] + [0]*r) - np.poly1d([1]))
    return rem.c(1) % n

    # f = [0] * (r + 1)
    # f[0] = -1
    # f[r] = 1
    # g = [0] * (r + 1)
    # g[0] = 1
    # for i in range(n + 1):
    #     g[i % (r + 1)] += binomial_coefficient(n, i) * a**(n-i)
    # prod = [0] * (2 * r + 1)
    # for i in range(r + 1):
    #     for j in range(r + 1):
    #         prod[i + j] += f[i] * g[j]
    # for i in range(r, 0, -1):
    #     prod[i] = prod[i - 1] - prod[i] * n
    # prod[0] = -prod[0] * n
    # return (prod[r] - a**n) % n


def binomial_coefficient(n: int, k: int) -> int:
    """
    Computes the binomial coefficient n choose k
    """
    if k < 0 or k > n:
        return 0
    if k == 0 or k == n:
        return 1
    k = min(k, n - k)
    c = 1
    for i in range(k):
        c = c * (n - i) // (i + 1)
    return c


def is_prime_AKS(n: int) -> bool:
    """Tests if n is prime using the deterministic AKS primality test"""

    if n == 2:
        return True
    if n % 2 == 0 or n < 2:
        return False

    # Check if n is a perfect power
    if is_perfect_power(n):
        return False

    # Find the smallest r such that ord_r(n) > floor(log2(n))^2
    # r = 2
    # while multiplicative_order(r, n) <= (n.bit_length() - 1) ** 2:
    #     r += 1
    cap_k = (n.bit_length() - 1) ** 2
    r = 2
    # run = True
    while any(pow(n, k, r) in {0, 1} for k in range(1, cap_k + 1)):
        # run = False
        # for k in range(1, cap_k):
        #     if run:
        #         break
        #     run = pow(n, k, r) in {0, 1}
        r += 1
    # r -= 1  # the loop over increments by one

    for a in range(r, 1, -1):
        if 1 < math.gcd(a, n) < n:
            return False

    if n <= r:
        return True

    # Check if n is composite using the polynomial function
    # for a in range(1, 2 * math.ceil(r**0.5) * math.ceil(math.log2(n)) + 1):
    for a in range(1, int(r**0.5 * math.log2(n)) + 1):
        if poly_mod(r, n, a) != 0:
            return False

    return True

    # # Ensure input requirements
    # if n < 2:
    #     return False

    # # Step 1: Find the smallest r such that ord_r(n) > log^2(n)
    # r = 3
    # while r < n:
    #     if math.gcd(r, n) != 1:
    #         return False

    #     for k in range(1, n.bit_length() + 1):
    #         if pow(r, n // 2**k, n) == 1:
    #             break
    #     else:
    #         return True
    #     r += 1

    # return False


def is_prime_deterministic(n: int) -> bool:
    if n <= 5:
        return n == 2 or n == 3 or n == 5
    if n % 2 == 0 or n % 3 == 0 or n % 5 == 0:
        return False

    if is_perfect_power(n):
        return False

    # Step 2: Find the smallest r such that ord_r(n) > log^2(n)
    r = 2
    while r <= n:
        if math.gcd(r, n) == 1:
            for k in range(1, n.bit_length() + 1):
                if pow(r, n // 2**k, n) == 1:
                    break
            else:
                break
        r += 1
    print("#", r, n - r)
    if r > n.bit_length() ** 2:
        print("first")
        return True

    # Step 3: Check if f(x) is divisible by (x-r)
    # f = [0] * (r + 1)
    # f[0] = 1
    # for i in range(1, r // 2 + 1):
    #     f[i] = f[i - 1] * (n - i + 1) // i % n
    # for i in range(r // 2 + 1, r + 1):
    #     f[i] = f[r - i]
    # f[0] -= 1
    # f[-1] -= a % n
    # for i in range(1, r):
    #     if f[i] % (r, n) != 0:
    #         return False

    print("second")
    return True


is_prime_AKS(31)


for i in range(10**6):
    a = is_prime_trial_division(i)
    # print(a)
    b = is_prime_AKS(i)
    # print(b)
    if a != b:
        print(i, a, b)
    # print(i)


"""
Input: integer n > 1.
1. If (n /* if perfect power */ = a^b for a > 1 and b > 1), output COMPOSITE.
2. Find the smallest r such that ord_r(n) > log_2(n)^2. (if r and n are not coprime, then skip this r)
3. If any 2 ≤ a ≤ min(r, n−1) divide n, output COMPOSITE.
4. If n ≤ r, output PRIME.
5. For a = 1 to floor(sqrt(φ(r))*log_2(n)) do
   if ((X + a)^n ≠ X^n + a (mod X^r - 1, n)), output COMPOSITE;
6. Output PRIME.


1. if (n is of the form ab, b > 1) output "COMPOSITE";
2. r = 2;
3. while (r < n) {
4.     if (gcd(n, r) != 1) output "COMPOSITE";
5.     if (r is prime) {
6.         let q be the largest prime factor of r - 1;
7.         if (q >= 4 * sqrt(r) * log(n)) and ((n ^ ((r-1)/q) mod r) != 1)) {
8.             break;
9.         }
10.     }
11.     r = r + 1;
12.     for a = 1 to 2 * sqrt(r) * log(n) {
13.         if (((a**n) % n) != ((a**(n % (r-1))) % n)) output "COMPOSITE";
14.     }
15.     output "P";
16. }


1. if ( n = a^b for some a, b ≥ 2 ) then return "composite";
2. r ← 2;
3. while ( r < n ) do
4.     if ( r divides n ) then return "composite";
5.     if ( r is a prime number ) then
6.         if ( n^i mod r ≠ 1 for all i, 1 ≤ i ≤ 4*log₂(n)^2 ) then
7.             break;
8.         r ← r + 1;
9.     if ( r = n ) then return "prime";
10.     for a from 1 to 2*ceil(sqrt(r))*ceil(log₂(n)) do
11.         if (in Zn[X]) (X + a)^n mod (X^r - 1) ≠ X^(n mod r) + a then
12.             return "composite";
13.     return "prime";

"""


def is_prime(n: int, ntests: int = 10) -> bool:
    """Tests if p is prime using the Miller-Rabin primality test."""

    if n <= 2:
        return n == 2
    if n % 2 == 0:
        return False

    # Compute s and d such that p-1 = 2^s * d, where d is odd
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2

    # Perform ntests iterations of the Miller-Rabin test
    for _ in range(ntests):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        if x == 1 or x == n - 1:
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def generate_prime(nbits: int) -> int:
    """Generates a random prime number in the form 6k ± 1 with nbits bits."""
    for candidate in generate_prime_candidate(nbits):
        if is_prime(candidate):
            return candidate
    assert False, "Unreachable"


# def poly_mod(r: int, n: int, a: int) -> int:
#     # Compute (x+a)^n mod (x^r - 1, n)
#     poly1 = pow(a + 1, n, xgcd((2 << r) - 1, n)[0], n)
#     # Compute x^n + a mod n
#     poly2 = (pow(2, n * r, n) - 2**(n * r - r) + a) % n
#     # Subtract the two polynomials and take mod n
#     return (poly1 - poly2) % n


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


MIN_PRIME_BITS = 20
MAX_PRIME_BITS = 40


def rsa_generate_random_keypair() -> tuple[Key, Key]:
    return rsa_generate_keypair_of_sizes(
        random.randrange(MIN_PRIME_BITS, MAX_PRIME_BITS),
        random.randrange(MIN_PRIME_BITS, MAX_PRIME_BITS),
    )


def rsa_encode(number: int, private_key: Key) -> int:
    return pow(number, *private_key)


def rsa_decode(number: int, public_key: Key) -> int:
    return pow(number, *public_key)


MAX_SIGN_LEN = 50

if int(input("Do you want to use random message? [0/1]: ")):
    inp = OctetString.random(69)
else:
    inp = OctetString.from_str(input("Then input the message: "))

# Sender
print("=" * 15 + " Sender " + "=" * 15)

print(inp.diagnostic())

pss_signature = pss_sign(inp, MAX_SIGN_LEN)
print(pss_signature.diagnostic())

numeric_repr = pss_signature.to_int()
print(numeric_repr)

num_size = math.ceil(math.log2(numeric_repr))
public, private = rsa_generate_keypair_of_sizes(num_size, num_size)
print(public)
print(private)

rsa_signature = rsa_encode(numeric_repr, private)
print(rsa_signature)

# Reciever
print("=" * 15 + " Reciever " + "=" * 15)

decoded = rsa_decode(rsa_signature, public)
print(decoded)

signature = OctetString.from_int(decoded)
print(signature.diagnostic())

is_valid = pss_verify(inp, MAX_SIGN_LEN, signature)
print("Valid" if is_valid else "Invalid")
try:
    print(inp.to_str())
except UnicodeDecodeError:
    print(inp.to_bytes())

# Reciever
print("=" * 15 + " Error tests " + "=" * 15)

is_valid = pss_verify(OctetString([inp[0] + 1, *inp[1:]]), MAX_SIGN_LEN, signature)
print("Valid" if is_valid else "Invalid")

is_valid = pss_verify(
    inp, MAX_SIGN_LEN, OctetString([signature[0] + 1, *signature[1:]])
)
print("Valid" if is_valid else "Invalid")

is_valid = pss_verify(
    inp, MAX_SIGN_LEN, OctetString([*signature[:-1], signature[-1] + 1])
)
print("Valid" if is_valid else "Invalid")
