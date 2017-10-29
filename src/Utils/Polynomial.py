from typing import List
from src.Utils.Parameters import Parameters


class PolynomialError(Exception):
    """
    This class will be used to represent errors that have to do with
    the polynomial object specified below
    """
    pass


class Polynomial:
    """
    This class will be used to represent polynomials of size N specified in Utils/Parameters.py.
    The coefficients of these polynomials will be represented by an integer list
    """
    def __init__(self, coef: List[int]):
        """
        This constructor will construct an Polynomial object with N coefficients.
        N is specified in Utils/Parameters
        :param coef: int list containing the coefficients of the polynomial
        """
        N = Parameters.N

        self._coef = [0 for i in range(N)]          # initialize the coefficients list to N zeroes
        if len(coef) > N:                           # if the length of provided coefficients list is greater than N throw an error
            raise PolynomialError("The length of the provided coefficients ({}) is greater than N ({})".format(len(coef), N))
        else:
            self._coef[:len(coef)] = coef           # copy the provided coefficients to the internal list

    def __str__(self):
        """
        :return: String representation of the polynomial
        """
        string = str(self._coef[0])
        for i in range(1,len(self._coef)):
            if self._coef[i] != 0:
                string += " + {}X^{}".format(self._coef[i], i)
        return string

    def __add__(self, other: "Polynomial") -> "Polynomial":
        """
        This function will add (the coefficients of) two polynomials of length N together.
        This function will return a new Polynomial object
        :param other: Polynomials to add to self
        :return: A new polynomial where the coefficients of self and other are added together
        """
        if not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        new_coef = [self[i] + other[i] for i in range(Parameters.N)]                    # add the respective coefficients together and store the result in a new list
        return Polynomial(new_coef)                                                     # return a new Polynomial object with the added coefficients

    def __iadd__(self, other: "Polynomial"):
        """
        This function will add (the coefficients of) two polynomials of length N together.
        This function will store the addition in it's own object
        :param other: Polynomials to add to self
        """
        if not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        new_coef = [self[i] + other[i] for i in range(Parameters.N)]                    # add the respective coefficients together and store the result in a new list
        self._coef = new_coef                                                           # replace the coefficients of self with the newly calculated coefficients

    def __mul__(self, other: "Polynomial") -> "Polynomial":
        """
        This function implements the `star` multiplication as specified in:
        This function will return a new Polynomial object
        :param other: int list containing the coefficients of the polynomial that needs to be multiplied with self
        :return: A new polynomial according to the cyclic convolutional product of self and other
        """
        N = Parameters.N

        if not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot multiply a Polynomial and a {} together!".format(other.__class__.__name__))

        H = [0 for i in range(N)]                                   # initialize the new coefficients list with zeroes
        for i in range(N):
            for j in range(N):
                H[(i + j) % N] += self[i] * other[j]                # do the summation as specified in the IEEE document
        return Polynomial(H)

    def __imul__(self, other: "Polynomial"):
        """
        This function implements the `star` multiplication as specified in:
        This function will store the result in itself
        :param other: int list containing the coefficients of the polynomial that needs to be multiplied with self
        """
        N = Parameters.N

        if not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot multiply a Polynomial and a {} together!".format(other.__class__.__name__))

        H = [0 for i in range(N)]  # initialize the new coefficients list with zeroes
        for i in range(N):
            for j in range(N):
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

        if isinstance(item, int):                           # if item is an integer
            if item > Parameters.N:                         # if the index is larger than the degree of the polynomial, throw an error
                raise PolynomialError("Index is larger than the degree of the polynomial")
        elif isinstance(item, slice):                       # if item is a slice
            if item.start < 0 or item.stop > Parameters.N:  # if the range of the slice falls outside of the polynomial, throw an error
                raise PolynomialError("Slice range is out of bounds")
        else:                                               # if item is something else than integer or slice, throw an error
            raise PolynomialError("Index has to be an integer, found {}".format(item.__class__.__name__))

        return self._coef[item]                                # return the coefficient corresponding to X^item

    def __setitem__(self, key: int, value: int):
        """
        This function will set the coefficient of X^<i>key</i> of this polynomial to value.
        :param key: integer index of the coefficient that needs to be updated.
        :param value: integer value of new coefficient
        """
        if isinstance(key, int):                            # if item is an integer
            if key > Parameters.N:                          # if the index is larger than the degree of the polynomial, throw an error
                raise PolynomialError("Index is larger than the degree of the polynomial")
        elif isinstance(key, slice):                        # if item is a slice
            if key.start < 0 or key.stop > Parameters.N:    # if the range of the slice falls outside of the polynomial, throw an error
                raise PolynomialError("Slice range is out of bounds")
        else:                                               # if item is something else than integer or slice, throw an error
            raise PolynomialError("Index has to be an integer, found {}".format(key.__class__.__name__))

        if not isinstance(value, int):      # if the value is not an integer, throw an error
            raise PolynomialError("Value has to be an integer, found {}".format(key.__class__.__name__))

        self._coef[key] = value             # update the coefficient corresponding to x^key


def poly_div(p: int, a: Polynomial, b: Polynomial) -> (Polynomial, Polynomial):
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

    r = a                                   # a
    q = Polynomial([0 for i in range(N)])   # a
    u = mul_inv(b[-1], p)                   # b
    while degree(r) >= N:                   # c
        d = degree(r)                           # 1
        v = u * r[d]                            # 2
        r[d-N] -= v                             # 3
        r *= b                                  # 3
        q[d-N] += v                             # 4
    return q, r                             # d


def degree(F: Polynomial) -> int:
    """
    This function calculates the degree of the polynomial specified by F
    :param F: int list containing the coefficients of polynomial F
    :return: The degree of polynomial F (deg(F))
    """
    for i in range(len(F)-1, -1, -1):
        if F[i] != 0:
            return i


if __name__ == "__main__":
    f = Polynomial([-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1])
    g = Polynomial([-1, 0, 1, 1, 0, 1, 0, 0, -1, 0, -1])
    fp = Polynomial([1, 2, 0, 2, 2, 1, 0, 2, 1, 2, 0])
    fq = Polynomial([5, 9, 6, 16, 4, 15, 16, 22, 20, 18, 30])
    print(f)
    print(fq)
    print(f*fq % Parameters.q)