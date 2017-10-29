def xgcd(b, n):
    """
    Extended euclidean algorithm according to [https://en.wikibooks.org/wiki/Algorithm_Implementation/Mathematics/Extended_Euclidean_algorithm#Python]
    :return: tuple (g, x0, y0) such that g is equal to gcd(b,n) and g = b*x0 + n*y0
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while n != 0:
        q, b, n = b // n, n, b % n
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return b, x0, y0


def mul_inv(x: int, n: int) -> int:
    """
    This function will compute the multiplicative inverse of x in Zn
    :param x: int to find the multiplicative inverse of
    :param n: size of the cyclic group
    :return: x^-1 mod n, if it exists
    """
    g, s, t = xgcd(x, n)
    if g == 1:
        return s % n