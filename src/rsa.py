import random
import math

from .algorithms import modinv
from .primes import random_prime


Key = tuple[int, int]


def choose_public_exponent(phi: int) -> int:
    """Chooses a random prime number as the public exponent."""
    while 1:
        e = random.randrange(3, phi, 2)  # Choose a random odd number between 3 and phi
        if math.gcd(e, phi) == 1:
            return e
    assert False, "Unreachable"


def generate_keypair(p: int, q: int) -> tuple[Key, Key]:
    """Generates an RSA keypair with the given prime numbers p and q."""
    n = p * q
    phi = (p - 1) * (q - 1)
    e = choose_public_exponent(phi)
    d = modinv(e, phi)
    return ((e, n), (d, n))


def generate_keypair_of_sizes(s1: int, s2: int) -> tuple[Key, Key]:
    return generate_keypair(random_prime(s1), random_prime(s2))


def encode(number: int, private_key: Key) -> int:
    return pow(number, *private_key)


def decode(number: int, public_key: Key) -> int:
    return pow(number, *public_key)
