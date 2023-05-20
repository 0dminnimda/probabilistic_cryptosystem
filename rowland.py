from math import gcd
from random import getrandbits
from time import perf_counter

from src.factorisation import smallest_prime_divisor
from src.primes import is_prime, random_prime, random_prime_candidate_6k_1


def steps_to_skip(divisor):
    return (divisor - 1) // 2


def calculate(i, n):
    return gcd(i, n)


def generate(*, trivial=True, init=7):
    n = init
    i = 1
    yield i, n, n
    while 1:
        i += 1
        change = calculate(i, n)
        n += change
        if trivial or change != 1:
            yield i, change, n


def generate_n(number, *, trivial=True, init=7):
    for t, _ in zip(generate(trivial=trivial, init=init), range(number)):
        yield t


def nth(number):
    n = 0
    for _, _, n in generate_n(number):
        pass
    return n


def generate_n_nontrivial_fast(number, seed=5):
    """Generate first `n` numbers in Rowland's Sequence"""
    i = seed
    for _ in range(number):
        n = smallest_prime_divisor(2 * i - 1)
        i += steps_to_skip(n)
        yield i, n


def generate_nontrivial(nbits):
    """Generate first `n` numbers in Rowland's Sequence"""
    while 1:
        i = getrandbits(nbits)
        for _ in range(10):
            n = smallest_prime_divisor(2 * i - 1)
            i += steps_to_skip(n)
            if n.bit_length() > nbits:
                break
            yield n


print(*generate_n(30, trivial=False))
print(nth(467))
print(*generate_n(30))
print(*generate_n_nontrivial_fast(100, 467))


def measure_destribution(number, generator):
    primes = 0
    first = 0
    for count, n in zip(range(number), generator):
        print(n, end=" ")
        if is_prime(n):
            print(end="P ")
            primes += 1
            if first == 0:
                first = count
    print()
    print(first, primes, number)


size = 48
seed = random_prime_candidate_6k_1(size)
# measure_destribution(100, (n for i, n in generate_n_nontrivial_fast(100, seed)))
# measure_destribution(100, generate_nontrivial(size))
# measure_destribution(100, (random_prime_candidate_6k_1(size) for _ in range(100)))


def random_prime_rowland(nbits: int, seed: int, max_iterations: int = 1000) -> int:
    i = seed
    for _ in range(max_iterations):
        n = smallest_prime_divisor(2 * i - 1)
        i += steps_to_skip(n)
        if n.bit_length() >= nbits:
            return n
    return -1


def my_random_prime(nbits: int) -> int:
    for _ in range(100):
        # seed = getrandbits(size)
        # seed = 2**size
        # seed = int(10**log10(size))
        seed = random_prime_candidate_6k_1(size)  # seems to have the best performance
        v = random_prime_rowland(nbits, seed)
        if v != -1:
            return v
    raise RuntimeError("ran out of iterations")


def my_random_prime2(nbits):
    while 1:
        i = getrandbits(nbits)
        for _ in range(10):
            n = 2 * i - 1
            # if is_prime(n):
            #     # print("1")
            #     return n
            # n = n * 3 // 2
            if n.bit_length() > nbits:
                break
            i += steps_to_skip(n)
            if n.bit_length() < nbits:
                continue
            if is_prime(n):
                # print("2")
                return n


def test_timing(iterations, size, funciton):
    start = perf_counter()
    for i in range(iterations):
        funciton(size)
    t = perf_counter() - start
    print(t)


its = int(10**3)
test_timing(its, size, random_prime)
test_timing(its, size, my_random_prime2)
test_timing(its, size, my_random_prime)
