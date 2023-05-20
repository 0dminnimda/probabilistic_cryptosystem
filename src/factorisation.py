from math import gcd
from random import randint

from .algorithms import integer_root
from .primes import is_prime


def smallest_prime_divisor_trial_division(n: int) -> int:
    """Find smallest prime divisor of n
    using the deterministic Trial Division algorithm."""

    # Ensure input requirements
    if n <= 1:
        return -1
    if n % 2 == 0:
        return 2

    # Check odd divisors up to the square root of n
    for i in range(3, integer_root(n) + 1, 2):
        if n % i == 0:
            return i
    return n


def pollard_rho(n: int) -> int:
    """Find possible(!) smallest prime divisor of n
    using the probabilistic Pollard's Rho algorithm."""

    y = x = randint(1, n - 1)
    c = randint(1, n - 1)
    d = 1
    while d == 1:  # hopefully will not stall, if not prime
        x = (pow(x, 2, n) + c) % n
        y = (pow(y, 2, n) + c) % n
        y = (pow(y, 2, n) + c) % n
        d = gcd(abs(x - y), n)
    return d


def smallest_prime_divisor_pollard_rho(n: int, max_iterations: int = 100) -> int:
    """Find smallest prime divisor of n
    using the probabilistic Pollard's Rho algorithm."""

    # Ensure input requirements
    if n <= 1:
        return -1
    if n % 2 == 0:
        return 2

    # it seems to stall on primes
    if is_prime(n):
        return n

    # is it probabilistic, thus try multiple times
    divisor = n
    for _ in range(max_iterations):
        divisor = pollard_rho(n)
        # divisor == n is the fail condition
        if divisor != n:
            break

    # algorithm can produce non-prime numbers
    if is_prime(divisor):
        return divisor

    # if it does, apply it again to get the true divisor
    # those are usually really small
    return smallest_prime_divisor_pollard_rho(divisor)


def smallest_prime_divisor(n: int) -> int:
    return smallest_prime_divisor_pollard_rho(n)
