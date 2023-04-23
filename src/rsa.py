import random
import math

from .primes import random_prime


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
    while 1:
        e = random.randrange(3, phi, 2)  # Choose a random odd number between 3 and phi
        if math.gcd(e, phi) == 1:
            return e
    assert False, "Unreachable"


Key = tuple[int, int]


def rsa_generate_keypair(p: int, q: int) -> tuple[Key, Key]:
    """Generates an RSA keypair with the given prime numbers p and q."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = rsa_choose_public_exponent(phi)
    d = modinv(e, phi)
    return ((e, n), (d, n))


def rsa_generate_keypair_of_sizes(s1: int, s2: int) -> tuple[Key, Key]:
    return rsa_generate_keypair(random_prime(s1), random_prime(s2))


def rsa_encode(number: int, private_key: Key) -> int:
    return pow(number, *private_key)


def rsa_decode(number: int, public_key: Key) -> int:
    return pow(number, *public_key)
