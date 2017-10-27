from typing import List

from src.Utils import Parameters


def conv_prod(F: List[int], G: List[int]) -> List[int]:
    """
    This function implements the `star` multiplication as specified in:
    :param F: int list containing the coefficients of polynomial F
    :param G: int list containing the coefficients of polynomial G
    :return: cyclic convolutional product of the polynomials F and G
    """
    N = Parameters.Parameters.N
    H = [0 for i in range(N)]
    for i in range(N):
        for j in range(N):
            H[(i+j) % N] += F[i]*G[j]
    return H


def reduce(F: List[int], q: int) -> List[int]:
    """
    This function reduces a polynomial F by factor q
    :param F: int list containing the coefficients of polynomial F
    :param q: int factor by which to reduce the polynomial
    :return: polynomial reduction of F by q (F `mod` q)
    """
    return [i % q for i in F]


def degree(F: List[int]) -> int:
    """
    This function calculates the degree of the polynomial specified by F
    :param F: int list containing the coefficients of polynomial F
    :return: The degree of polynomial F (deg(F))
    """
    for i in range(len(F)-1, -1, -1):
        if F[i] != 0:
            return i


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

def poly_div(p: int, a: List[int], b: List[int]) -> (List[int], List[int]):
    """
    This function divides polynomial a by polynomial b in the ring of polynomials with
    integer coefficients modulo prime p. The leading coefficient of B, Bn, must be non-zero
    :param p: int prime
    :param a: int list containing the coefficients of polynomial A
    :param b: int list containing the coefficients of polynomial B
    :return: polynomial tuple (q,r) where q and r are in the ring of polynomials with integer coefficients
    modulo p, satisfying a = b x q + r and deg(r) < deg(q)
    """
    N = Parameters.Parameters.N

    r = a                       # a
    q = [0 for i in range(N)]   # a
    u = mul_inv(b[-1], p)       # b
    while degree(r) >= N:       # c
        d = degree(r)           # 1
        v = u * r[d]            # 2
        r[d-N] -= v             # 3
        r = conv_prod(r, b)     # 3
        q[d-N] += v             # 4
    return q, r                 # d






if __name__ == "__main__":
    f = [-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1]
    g = [-1, 0, 1, 1, 0, 1, 0, 0, -1, 0, -1]
    fp = [1, 2, 0, 2, 2, 1, 0, 2, 1, 2, 0]
    fq = [5, 9, 6, 16, 4, 15, 16, 22, 20, 18, 30]
    print(degree(f))
    print(degree(fp))
    print(degree(reduce(conv_prod(f, fq), Parameters.Parameters.q)))