from typing import List
from copy import deepcopy
import math
from src.Utils.Parameters import Parameters
from src.Utils.Arithmetic import *
"""
[1]: IEEE Std 1363.1 - IEEE Standard Specification for Public Key Cryptographic Techniques Based on Hard Problems over Lattices (http://ieeexplore.ieee.org/document/4800404/)
[2]: Almost Inverses and Fast NTRU Key Creation (https://assets.onboardsecurity.com/static/downloads/NTRU/resources/NTRUTech014.pdf)
"""


class PolynomialError(Exception):
    """
    This class will be used to represent errors that have to do with
    the polynomial object specified below
    """
    pass


class Polynomial:
    """
    This class will be used to represent polynomials.
    The coefficients of these polynomials will be represented by an integer list
    """
    def __init__(self, coef: List[int]):
        """
        This constructor will construct an Polynomial object with len(coef) coefficients.
        :param coef: int list containing the coefficients of the polynomial
        """
        N = Parameters.N

        self._coef = coef

    def __str__(self):
        """
        :return: String representation of the polynomial
        """
        string = str(self._coef[0])
        for i in range(1, len(self._coef)):
            if self._coef[i] != 0:
                string += " + {}X^{}".format(self._coef[i], i)
        return string

    def __add__(self, other: "Polynomial/ int") -> "Polynomial":
        """
        This function will add (the coefficients of) two polynomials of length N together.
        This function will return a new Polynomial object
        :param other: Polynomial to add to self
        :return: A new polynomial where the coefficients of self and other are added together
        """
        if isinstance(other, int):
            other = Polynomial([other])
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        if len(self) >= len(other):
            p1, p2 = self, other
        else:
            p1, p2 = other, self
        new_coef = [self[i] + other[i] for i in range(len(p2))]                         # add the respective coefficients together and store the result in a new list
        if len(p1) > len(p2):
            new_coef += p1[(len(p2)-len(p1)):]
        return Polynomial(new_coef)                                                     # return a new Polynomial object with the added coefficients

    def __iadd__(self, other: "Polynomial"):
        """
        This function will add (the coefficients of) two polynomials of length N together.
        This function will store the result of the addition in it's own object
        :param other: Polynomial to add to self
        """
        if isinstance(other, int):
            other = Polynomial([other])
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        if len(self) >= len(other):
            p1, p2 = self, other
        else:
            p1, p2 = other, self
        new_coef = [self[i] + other[i] for i in range(len(p2))]                         # add the respective coefficients together and store the result in a new list
        if len(p1) > len(p2):
            new_coef += p1[(len(p2)-len(p1)):]
        self._coef = new_coef                                                           # replace the coefficients of self with the newly calculated coefficients

    def __sub__(self, other: "Polynomial") -> "Polynomial":
        """
                This function will subtract (the coefficients of) two polynomials of length N from each other.
                This function will return a new Polynomial object
                :param other: Polynomial to subtract from itself
                :return: A new polynomial where the coefficients of self and other are subtracted from each other
                """
        if isinstance(other, int):
            other = Polynomial([other])
        elif not isinstance(other, Polynomial):  # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        if len(self) >= len(other):
            p1, p2 = self, other
        else:
            p1, p2 = other, self
        new_coef = [self[i] - other[i] for i in range(len(p2))]                         # subtract the respective coefficients from each other and store the result in a new list
        if len(p1) > len(p2):
            new_coef += [-i for i in p1[(len(p2)-len(p1)):]]
        return Polynomial(new_coef)

    def __isub__(self, other: "Polynomial"):
        """
        This function will subtract (the coefficients of) two polynomials of length N from each other.
        This function will store the result of the subtraction in it's own object
        :param other: Polynomial to subtract from self
        """
        if isinstance(other, int):
            other = Polynomial([other])
        elif not isinstance(other, Polynomial):  # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        if len(self) >= len(other):
            p1, p2 = self, other
        else:
            p1, p2 = other, self
        new_coef = [self[i] - other[i] for i in range(
            len(p2))]  # subtract the respective coefficients from each other and store the result in a new list
        if len(p1) > len(p2):
            new_coef += p1[(len(p2) - len(p1)):]
        self._coef = new_coef

    def __mul__(self, other: "Polynomial") -> "Polynomial":
        """
        This function implements the `star` multiplication as specified in:
        This function will return a new Polynomial object
        :param other: int list containing the coefficients of the polynomial that needs to be multiplied with self
        :return: A new polynomial according to the cyclic convolutional product of self and other
        """
        N = Parameters.N

        if isinstance(other, int):
            other = Polynomial([other])
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot multiply a Polynomial and a {} together!".format(other.__class__.__name__))

        H = [0] * N                                                 # initialize the new coefficients list with zeroes
        for i, a in enumerate(self):
            for j, b in enumerate(other):
                H[(i + j) % N] += a * b                             # do the summation as specified in the IEEE document
        return Polynomial(H)

    def __imul__(self, other: "Polynomial"):
        """
        This function implements the `star` multiplication as specified in:
        This function will store the result in itself
        :param other: int list containing the coefficients of the polynomial that needs to be multiplied with self
        """
        N = Parameters.N

        if isinstance(other, int):
            other = Polynomial([other])
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot multiply a Polynomial and a {} together!".format(other.__class__.__name__))

        H = [0 for i in range(N)]  # initialize the new coefficients list with zeroes
        for i in range(len(self)):
            for j in range(len(other)):
                H[(i + j) % N] += self[i] * other[j]              # do the summation as specified in the IEEE document
        self._coef = H                                            # replace the coefficients of self with the newly calculated coefficients

    def __mod__(self, other: int) -> "Polynomial":
        """
        This function reduces a polynomial F by factor `other`
        This function will return a new Polynomial object
        :param other: int factor by which to reduce self
        :return: a new Polynomial object with the coefficients modulo other (self `mod` other)
        """
        if not isinstance(other, int):                          # if other is not an integer, throw an error
            raise PolynomialError("You cannot reduce the coefficients of a Polynomial by a {}".format(other.__class__.__name__))
        return Polynomial([i % other for i in self._coef])      # return a new Polynomial object with all the coefficients of self `mod` other

    def __len__(self) -> int:
        """
        This function will return the length of the coefficients list
        :return: len(coefficients list)
        """
        return len(self._coef)

    def __getitem__(self, item: int) -> int:
        """
        This function will return the coefficient corresponding with X^<i>item</i> of this polynomial
        :param item: integer index of the coefficient that is to be retrieved
        :return: coefficient corresponding to X^item
        """

        # if isinstance(item, int):                                 # if item is an integer
        #     if item > len(self):                                  # if the index is larger than the degree of the polynomial, throw an error
        #         raise PolynomialError("Index is larger than the degree of the polynomial")
        # elif isinstance(item, slice):                             # if item is a slice
        #     if item.start < -len(self) or (item.stop is not None and item.stop > len(self)):    # if the range of the slice falls outside of the polynomial, throw an error
        #         raise PolynomialError("Slice range is out of bounds")
        # else:                                                     # if item is something else than integer or slice, throw an error
        #     raise PolynomialError("Index has to be an integer, found {}".format(item.__class__.__name__))

        return self._coef[item]                                   # return the coefficient corresponding to X^item

    def __setitem__(self, key: int, value: int):
        """
        This function will set the coefficient of X^<i>key</i> of this polynomial to value.
        :param key: integer index of the coefficient that needs to be updated.
        :param value: integer value of new coefficient
        """
        if isinstance(key, int):                                # if item is an integer
            if key > len(self):                                 # if the index is larger than the degree of the polynomial, throw an error
                raise PolynomialError("Index is larger than the degree of the polynomial")
        elif isinstance(key, slice):                            # if item is a slice
            if key.start < -len(self) or key.stop > len(self):  # if the range of the slice falls outside of the polynomial, throw an error
                raise PolynomialError("Slice range is out of bounds")
        else:                                                   # if item is something else than integer or slice, throw an error
            raise PolynomialError("Index has to be an integer, found {}".format(key.__class__.__name__))

        if not isinstance(value, int):                          # if the value is not an integer, throw an error
            raise PolynomialError("Value has to be an integer, found {}".format(key.__class__.__name__))

        self._coef[key] = value                                 # update the coefficient corresponding to x^key

    def __deepcopy__(self, memo):
        """
        This function will return a new Polynomial object where the list
        of the coefficients is deepcopied.
        :param memo:
        :return:
        """
        cls = self.__class__
        result = cls.__new__(cls)
        memo[id(self)] = result
        for k, v in self.__dict__.items():
            setattr(result, k, deepcopy(v, memo=memo))
        return result

    def toBSP(self, q: int) -> str:
        """
        Convert the polynomial (Ring Element) to a bit string.
        All elements of the polynomial will be done modulo q.
        This algorithm is specified in section 7.5.1 in [1]
        :param q: int to reduce the coefficients by
        :return: bit string representing the `self` polynomial
        """
        coefs = [x % q for x in self._coef]  # a 1
        size = math.ceil(math.log2(q))
        bits = ["{0:0{1}b}".format(x, size) for x in coefs]
        return ''.join(bits)

    def toOSP(self, q: int) -> str:
        """
        Convert the polynomial (Ring Element) to a bit string.
        All elements of the polynomial will be done modulo q
        This algorithm is specified in section 7.6.1
        :param q: int to reduce the coefficients by
        :return: bit string representing the `self` polynomial
        """
        bitstring = self.toBSP(q)
        octetstring = []
        for i in range(len(bitstring) // 8):
            octetstring.append("{0:02X}".format(int(bitstring[8*i:8*(i+1)], 2)))
        octetstring.append("{0:02X}".format(int("{0:0<8}".format(bitstring[8*(len(bitstring) // 8)]), 2)))
        return ''.join(octetstring)

    @staticmethod
    def fromBSP(B: str, N: int=Parameters.N, q: int=Parameters.q):
        """
        Construct a Polynomial object of degree N and all coefficients modulo q from a bitstring B
        This algorithm is specified in section 7.5.2
        :param B: bitstring to construct the polynomial from
        :param N: degree of the polynomial
        :param q: factor to reduce the coefficients of the polynomial by
        :return: Polynomial object of degree N constructed from B
        """
        if len(B) != N*math.ceil(math.log2(q)):         # check if the bitstring contains the right amount of information
            raise PolynomialError("The length of the bitstring does not match the degree of the polynomial")
        coefs = []                                      # initialize a list for the coefficients of the polynomial
        size = math.ceil(math.log2(q))                  # check how many bits represent one coefficient
        for i in range(len(B) // size):
            coefs.append(int(B[size*i:size*(i+1)], 2))  # convert the bits to integers and add them to the coefficient list
        return Polynomial(coefs)                        # return a polynomial with the coefficients from the bitstring

    @staticmethod
    def fromOSP(O: str, N: int=Parameters.N, q: int=Parameters.q):
        """
        Construct a Polynomial object of degree N and all coefficients modulo q from a octetstring B
        This algorithm is specified in section 7.6.2
        :param O: octetstring to construct the polynomial from
        :param N: degree of the polynomial
        :param q: factor to reduce the coefficients of the polynomial by
        :return: Polynomial object of degree N constructed from O
        """
        if len(O) != 2*N*math.ceil(math.log(q, 256)):               # a
            raise PolynomialError("The length of the octetstring does not match the degree of the polynomial")

        bitstring = ""                                              # b
        for i in range(len(O) // 2):
            bitstring += "{0:08b}".format(int(O[i*2:(i+1)*2], 16))  # b
        bitstring = bitstring[:N*math.ceil(math.log2(q))]           # b
        return Polynomial.fromBSP(bitstring, N, q)                  # c & d

    def poly_div(self, p: int, b: "Polynomial") -> ("Polynomial", "Polynomial"):
        """
        This function divides self by polynomial b in the ring of polynomials with
        integer coefficients modulo prime p. The leading coefficient of B, Bn, must be non-zero.
        This algorithm is defined in section 6.3.3.1 of [1]
        :param p: int prime
        :param b: Polynomial object representing polynomial B
        :return: polynomial tuple (q,r) where q and r are in the ring of polynomials with integer coefficients
        modulo p, satisfying self = b x q + r and deg(r) < deg(q)
        """
        oldN = Parameters.N                                         # in order for the star multiplication to work properly,
        N = degree(b)                                               # N needs to be set to degree(b) temporarily
        Parameters.N = degree(self) + 1
        b %= p

        r = self % p                                                # a
        q = Polynomial([0 for i in range(Parameters.N)])            # a
        u = mul_inv(b[N], p)                                        # b
        while degree(r) >= N:                                       # c
            d = degree(r)                                               # 1
            v = Polynomial([0 for i in range(d-N)] + [u * r[d]])        # 2
            r = (r - v * b) % p                                         # 3
            q = (q + v) % p                                             # 4
            if d == 0:
                break
        Parameters.N = oldN                                         # restore Parameters.N
        return q, r                                                 # d

    def inverse(self, p: int):
        """
        This function will calculate the inverse of the polynomial in Zp[X]/(X^N – 1) if the inverse exists.
        The condition for the inverse to exist is that GCD(a, X N – 1) should be a polynomial of degree 0.
        This algorithm is specified in section 6.3.3.3 in [1]
        :param p: prime int
        :param r: power to raise p to. Standard 0
        :return: if it exists a new Polynomial object containing the inverse of self in Zp[X]/(X^N – 1), or
        false if the inverse does not exist
        """
        N = Parameters.N
        u, v, d = EEA(p, self, Polynomial([-1] + [0 for i in range(N-1)] + [1]))    # a
        if degree(d) == 0:                                                          # b
            d1 = mul_inv(d[0], p)                                                   # c
            return Polynomial([d1]) * u                                             # c
        else:                                                                       # d
            return False                                                            # d

    def inverse_2(self):
        k = 0
        b = Polynomial([1])
        c = Polynomial([0])
        f = deepcopy(self) % 2
        g = Polynomial([-1] + ([0] * (Parameters.N-1)) + [1])

        while True:
            while f[0] == 0:
                f._coef = f._coef[1:]
                c._coef = [0] + c._coef
                k += 1
            if f[0] == 1 and f[1:] == ([0] * (len(f) - 1)):
                b._coef = [0] * k + b._coef
                return b
            if degree(f) < degree(g):
                f,g = g,f
                b, c = c, b
            f = (f + g) % 2
            b = (b + c) % 2

    def inverse_pow_2(self, p: int, e: int):
        """
        This function will calculate the inverse of the polynomial in Z(p^r)[X]/(X^N – 1) if the inverse exists.
        once an inverse is determined module a prime p, a simple method based on Newton iteration allows one to
        rapidly compute the inverse module powers p^r. The following algorithm converges doubly exponentially, in
        the sense that it requires only about log2(r) steps to find the inverse of a(x) module p^r, once once
        knows an inverse modulo p.
        This algorithm is specified in the third algorithm in [2] (inversion in Z/p^r Z)
        :param p: prime int
        :param e: exponent int
        :return: if it exists a new Polynomial object containing the inverse of self in Z(p^r)[X]/(X^N – 1), or
        false if the inverse does not exist
        """
        b = self.inverse_2()                            # 0
        if not isinstance(b, Polynomial):               # 0
            return False                                # 0
        q = p                                           # 1
        pe = p**e                                       # 2
        while q < pe:                                   # 2
            q *= q                                      # 3
            b = (b * (Polynomial([2]) - self*b)) % q    # 4
        return b % pe                                   # 5


def degree(F: Polynomial) -> int:
    """
    This function calculates the degree of the polynomial specified by F
    :param F: int list containing the coefficients of polynomial F
    :return: The degree of polynomial F (deg(F))
    """
    for i in range(len(F)-1, -1, -1):
        if F[i] != 0:
            return i
    return 0


def EEA(p: int, a: Polynomial, b: Polynomial) -> (Polynomial, Polynomial, Polynomial):
    """
    This Extended Euclidean Algorithm finds a greatest common divisor d (there may be more than one that are
    constant multiples of each other) of two polynomials a and b in Zp[X] and polynomials u and v such that
    a × u + b × v = d. All convolution operations occur in the ring Zp[X] in this algorithm.
    This algorithm is specified in section 6.3.3.2 of [1]
    :param p: int prime
    :param a: Polynomial object representing polynomial a
    :param b: Polynomial object representing polynomial b
    :return: Polynomials u,v and d such that a × u + b × v = d
    """
    if not (isinstance(a, Polynomial) and isinstance(b, Polynomial)):       # if a or b is not a polynomial raise an error
        raise PolynomialError("Both a and b need to be polynomial objects")

    if b._coef.count(b[0]) == len(b) and b[0] == 0:                         # a
        return Polynomial([1]), Polynomial([0]), a                          # a

    u = Polynomial([1])                                                     # b
    d = a % p                                                               # c
    v1 = Polynomial([0])                                                    # d
    v3 = b % p                                                              # e
    while not (v3[0] == 0 and v3._coef.count(v3[0]) == len(v3)):            # f
        q, t3 = d.poly_div(p, v3)                                               # 1
        t1 = (u - q * v1) % p                                                   # 2
        u = v1                                                                  # 3
        d = v3                                                                  # 4
        v1 = t1                                                                 # 5
        v3 = t3                                                                 # 6
    v, vr = ((a*u % p) % p).poly_div(p, b)                                  # g
    return u, v, d                                                          # h


if __name__ == "__main__":
    # a = Polynomial([1, 1, 0, 2, 1, 0, 2])
    # b = Polynomial([1, 0, 0, 2])
    # print(a+b)
    f = Polynomial([-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1])
    g = Polynomial([-1, 0, 1, 1, 0, 1, 0, 0, -1, 0, -1])
    fp = Polynomial([1, 2, 0, 2, 2, 1, 0, 2, 1, 2])
    fq = Polynomial([5, 9, 6, 16, 4, 15, 16, 22, 20, 18, 30])
    # print(f)
    # print(fq)
    # print(f*fq % Parameters.q)
    # print(f.inverse(Parameters.p))
    # print(fp)
    # print("-------------------------------------")
    print(f.inverse_pow_2(2, 5))
    print(fq)

    # a = Polynomial([45, 2, 77, 103, 12])
    # print(a)
    # print(Polynomial.fromBSP(a.toBSP(128), N=5, q=128))
    # print(Polynomial.fromOSP(a.toOSP(128), N=5, q=128))
