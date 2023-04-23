import math


def egcd(a: int, b: int) -> tuple[int, int, int]:
    """Extended Euclidean algorithm."""
    y0, y1, x0, x1 = 0, 1, 1, 0
    while b != 0:
        q, b, a = *divmod(a, b), b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def modinv(a: int, m: int) -> int:
    """Calculates the modular multiplicative inverse of a modulo m."""
    g, x, y = egcd(a, m)
    if g != 1:
        raise ValueError("Modular inverse does not exist")
    else:
        return x % m


def integer_root_guess(
    n: int, p: int = 2, upper_bound: bool = False, lower_bound: bool = False
) -> int:
    """Creates a good guess for integer_root(n, p)."""
    shift = math.log(n, p) / p
    if upper_bound:
        return p ** math.ceil(shift)
    if lower_bound:
        return p ** math.floor(shift)
    # minimize the average error
    return (p ** math.ceil(shift) + p ** math.floor(shift)) // 2


def integer_root(n: int, p: int = 2, k: int = -1) -> int:
    """
    Computes the integer square root (i.e., the largest integer x such that x^p <= n)
    using the Newton's method.
    `k` - the number of iterations to do. If `k` is negative, iterations are not limited
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
    while k != 0:
        y = (p1 * x + n // x**p1) // p
        if y >= x:
            break
        x = y
        k -= 1
    return x


def is_square(n: int) -> bool:
    """Tests if n is a perfect square."""
    return integer_root(n) ** 2 == n


def jacobi_symbol(a: int, b: int) -> int:
    """Computes the Jacobi symbol (a/b) using the algorithm of Euler."""
    if b == 1:
        return 1
    elif a == 0:
        return 0
    elif b % 2 == 0:
        return jacobi_symbol(a, b // 2) * pow(-1, (b**2 - 1) // 8)
    elif a % 2 == 0:
        return jacobi_symbol(a // 2, b) * pow(
            -1, ((a**2 - 1) // 8) * ((b**2 - 1) // 8)
        )
    elif a < b:
        return jacobi_symbol(b, a) * pow(-1, (a - 1) * (b - 1) // 4)
    else:
        return jacobi_symbol(b, a % b) * pow(-1, ((a - 1) // 2) * ((b - 1) // 2))


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
