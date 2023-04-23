import math
import random
from typing import Iterable

from .algorithms import is_square, jacobi_symbol, integer_root


def miller_rabin_test(n: int, s: int, d: int, a: int = 0) -> bool:
    """
    Tests if `n` is composite with respect to a base `a`,
    and constatnts `s` and `d` using the Miller-Rabin test.
    Returns True if n is probably prime, False otherwise.
    """
    a = a or random.randint(2, n - 2)
    x = pow(a, d, n)
    if x == 1 or x == n - 1:
        return True
    for _ in range(s - 1):
        x = pow(x, 2, n)
        if x == n - 1:
            return True
        if x <= 1:
            return False
    return False


def miller_rabin_iterations(n: int) -> int:
    # if 64 iterations is cryptographically accepted for 512 bits
    # as well as 128 iterations for 1024 bits
    # then the min(10, bits // 8) is an ok general rule
    return max(10, n.bit_length() // 8)


def miller_rabin_constants(n: int) -> tuple[int, int]:
    """Compute s and d such that n - 1 = d * 2^s, where d is odd."""
    s, d = 0, n - 1
    while d % 2 == 0:
        s += 1
        d //= 2
    return s, d


def is_prime_miller_rabin(n: int, k: int = 0) -> bool:
    """Tests if n is prime using the probabilistic Miller-Rabin primality test."""

    # Ensure input requirements
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    # Set all the variables
    s, d = miller_rabin_constants(n)
    k = k or miller_rabin_iterations(n)

    # Perform k iterations of the Miller-Rabin test
    return all(miller_rabin_test(n, s, d) for _ in range(k))


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


def lucas_v(p: int, q: int, n: int) -> int:
    """Computes the nth Lucas V sequence number modulo n."""
    if n == 0:
        return 2 % q
    elif n == 1:
        return p % q
    else:
        v_n_minus_1 = lucas_v(p, q, n - 1)
        v_n_minus_2 = lucas_v(p, q, n - 2)
        return (p * v_n_minus_1 - q * v_n_minus_2) % q


def is_probable_prime_lucas_test(n: int) -> bool:
    """Tests if n is prime using the determenistic Lucas probable primality test."""

    # Find the first element in the Fibonacci sequence greater than n
    f0, f1 = 0, 1
    while f1 <= n:
        f0, f1 = f1, f0 + f1

    # Compute the parameters for the Lucas sequence
    p, q = 1 - f0, 1 + f0

    # Compute the Lucas sequence modulo n until an element with Jacobi symbol 1 is found
    for i in range(1, n + 1):
        v_i = lucas_v(p, q, i) % n
        if v_i == 0 or is_square(jacobi_symbol(v_i, n)):
            return True

    return False


def is_prime_baillie_psw(n: int) -> bool:
    """Tests if n is prime using the probabilistic Baillie-PSW primality test."""

    # Ensure input requirements
    if n <= 3:
        return n == 2 or n == 3
    if n % 2 == 0:
        return False

    k = 2
    s, d = miller_rabin_constants(n)
    return (
        miller_rabin_test(n, s, d, 2)
        and is_probable_prime_lucas_test(n)
        and all(miller_rabin_test(n, s, d) for _ in range(k))
    )


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


def is_prime(n: int) -> bool:
    # probabilistic test, but it is an open question if false positives are possible
    # also SEE: https://crypto.stackexchange.com/q/103085/108971
    return is_prime_baillie_psw(n)  # and not is_perfect_power(n)


def generate_prime_candidate(nbits: int) -> Iterable[int]:
    """Generates a random candidate prime number in the form 6k ± 1 with nbits bits."""
    while 1:
        candidate = 6 * random.getrandbits(nbits - 2) + random.choice((-1, 1))
        candidate |= 1  # Make sure the number is odd
        candidate |= 1 << (nbits - 1)  # Make sure the number has nbits bits
        yield candidate


def random_prime(nbits: int) -> int:
    """Generates a random prime number in the form 6k ± 1 with nbits bits."""
    for candidate in generate_prime_candidate(nbits):
        if is_prime(candidate):
            return candidate
    assert False, "Unreachable"
