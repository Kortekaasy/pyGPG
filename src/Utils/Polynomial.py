import math
from copy import deepcopy
from typing import List
import numpy as np
from numpy import asarray

from src.NTRUCrypt.EncryptionParameters import Parameters
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
    def __init__(self, coef: np.ndarray, N: int):
        """
        This constructor will construct an Polynomial object with len(coef) coefficients.
        :param coef: int list containing the coefficients of the polynomial
        :param N: int specifying the degree of the polynomial
        """
        self.N = N

        self._coef = np.concatenate((coef,  np.zeros(N - len(coef)))).astype(int)

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
            other = Polynomial(np.array([other]), self.N)
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        # make sure the length of both coefficient arrays are equal, by appending zeroes
        if len(self) > len(other):
            p1, p2 = self._coef, np.concatenate((other._coef, np.zeros(len(self._coef) - len(other._coef))))
        elif len(other) > len(self):
            p1, p2 = other._coef, np.concatenate((self._coef, np.zeros(len(other._coef) - len(self._coef))))
        else:
            p1, p2 = self._coef, other._coef
        return Polynomial(p1 + p2, len(p1))                                            # return a new Polynomial object with the added coefficients

    def __iadd__(self, other: "Polynomial"):
        """
        This function will add (the coefficients of) two polynomials of length N together.
        This function will store the result of the addition in it's own object
        :param other: Polynomial to add to self
        """
        if isinstance(other, int):
            other = Polynomial(np.array([other]), 1)
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        # make sure the length of both coefficient arrays are equal, by appending zeroes
        if len(self) > len(other):
            p1, p2 = self._coef, np.concatenate((other._coef, np.zeros(len(self._coef) - len(other._coef))))
        elif len(other) > len(self):
            p1, p2 = other._coef, np.concatenate((self._coef, np.zeros(len(other._coef) - len(self._coef))))
        else:
            p1, p2 = self._coef, other._coef
        # replace own coefficient array with the updated array
        self._coef = p1 + p2

    def __sub__(self, other: "Polynomial") -> "Polynomial":
        """
                This function will subtract (the coefficients of) two polynomials of length N from each other.
                This function will return a new Polynomial object
                :param other: Polynomial to subtract from itself
                :return: A new polynomial where the coefficients of self and other are subtracted from each other
                """
        if isinstance(other, int):
            other = Polynomial(np.array([other]), self.N)
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        # make sure the length of both coefficient arrays are equal, by appending zeroes
        if len(self) > len(other):
            p1, p2 = self._coef, np.concatenate((other._coef, np.zeros(len(self._coef) - len(other._coef))))
        elif len(other) > len(self):
            p1, p2 = other._coef, np.concatenate((self._coef, np.zeros(len(other._coef) - len(self._coef))))
        else:
            p1, p2 = self._coef, other._coef
        return Polynomial(p1 - p2, len(p1))                                            # return a new Polynomial object with the subbed coefficients

    def __isub__(self, other: "Polynomial"):
        """
        This function will subtract (the coefficients of) two polynomials of length N from each other.
        This function will store the result of the subtraction in it's own object
        :param other: Polynomial to subtract from self
        """
        if isinstance(other, int):
            other = Polynomial(np.array([other]), 1)
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot add a Polynomial and a {} together!".format(other.__class__.__name__))
        # make sure the length of both coefficient arrays are equal, by appending zeroes
        if len(self) > len(other):
            p1, p2 = self._coef, np.concatenate((other._coef, np.zeros(len(self._coef) - len(other._coef))))
        elif len(other) > len(self):
            p1, p2 = other._coef, np.concatenate((self._coef, np.zeros(len(other._coef) - len(self._coef))))
        else:
            p1, p2 = self._coef, other._coef
        # replace own coefficient array with the updated array
        self._coef = p1 - p2

    def __mul__(self, other: "Polynomial") -> "Polynomial":
        """
        This function implements the `star` multiplication as specified in:
        This function will return a new Polynomial object
        :param other: int list containing the coefficients of the polynomial that needs to be multiplied with self
        :return: A new polynomial according to the cyclic convolutional product of self and other
        """
        N = self.N

        if isinstance(other, int):
            other = Polynomial(np.array([other]),1)
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot multiply a Polynomial and a {} together!".format(other.__class__.__name__))

        H = np.zeros(N)                                             # initialize the new coefficients list with zeroes
        p = self._coef
        q = other._coef
        for a in p:
            H += a * q
            q = np.roll(q, 1)
        # for i, a in enumerate(self):
        #     for j, b in enumerate(other):
        #         H[(i + j) % N] += a * b                             # do the summation as specified in the IEEE document
        return Polynomial(H, N)

    def __imul__(self, other: "Polynomial"):
        """
        This function implements the `star` multiplication as specified in:
        This function will store the result in itself
        :param other: int list containing the coefficients of the polynomial that needs to be multiplied with self
        """
        N = self.N

        if isinstance(other, int):
            other = Polynomial(np.array([other]),1)
        elif not isinstance(other, Polynomial):                                           # if other is not a polynomials throw an error
            raise PolynomialError("You cannot multiply a Polynomial and a {} together!".format(other.__class__.__name__))

        H = np.zeros(N)  # initialize the new coefficients list with zeroes
        p = self._coef
        q = other._coef
        for a in p:
            H += a * q
            q = np.roll(q, 1)
        # for i in range(len(self)):
        #     for j in range(len(other)):
        #         H[(i + j) % N] += self[i] * other[j]              # do the summation as specified in the IEEE document
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
        return Polynomial(self._coef % other, self.N)      # return a new Polynomial object with all the coefficients of self `mod` other

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
        # if isinstance(key, int):                                # if item is an integer
        #     if key > len(self):                                 # if the index is larger than the degree of the polynomial, throw an error
        #         raise PolynomialError("Index is larger than the degree of the polynomial")
        # elif isinstance(key, slice):                            # if item is a slice
        #     if key.start < -len(self) or key.stop > len(self):  # if the range of the slice falls outside of the polynomial, throw an error
        #         raise PolynomialError("Slice range is out of bounds")
        # else:                                                   # if item is something else than integer or slice, throw an error
        #     raise PolynomialError("Index has to be an integer, found {}".format(key.__class__.__name__))
        #
        # if not isinstance(value, int):                          # if the value is not an integer, throw an error
        #     raise PolynomialError("Value has to be an integer, found {}".format(key.__class__.__name__))

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
        bits = ["{0:0{1}b}".format(int(x), size) for x in coefs]
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
        octetstring = bytearray()
        for i in range(len(bitstring) // 8):
            octetstring.append(int(bitstring[8*i:8*(i+1)], 2))
        if (len(bitstring) % 8) != 0:
            octetstring.append(int("{0:0<8}".format(bitstring[8*(len(bitstring) // 8):]), 2))
        return octetstring

    @staticmethod
    def fromBSP(B: str, N: int, q: int):
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
        return Polynomial(np.array(coefs), N)                     # return a polynomial with the coefficients from the bitstring

    @staticmethod
    def fromOSP(O: bytearray, N: int, q: int):
        """
        Construct a Polynomial object of degree N and all coefficients modulo q from a octetstring B
        This algorithm is specified in section 7.6.2
        :param O: octetstring to construct the polynomial from
        :param N: degree of the polynomial
        :param q: factor to reduce the coefficients of the polynomial by
        :return: Polynomial object of degree N constructed from O
        """
        if len(O) != math.ceil(N*math.ceil(math.log2(q))/8):          # a
            raise PolynomialError("The length of the octetstring does not match the degree of the polynomial")

        bitstring = ""                                              # b
        for i in range(len(O)):
            bitstring += "{0:08b}".format(O[i])                     # b
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
        # print("I'm used!")
        # oldN = Parameters.N                                         # in order for the star multiplication to work properly,
        N = degree(b)                                               # N needs to be set to degree(b) temporarily
        self.N += 1
        b %= p

        print("a: {}".format(self))
        print("b: {}".format(b))

        r = self % p                                                # a
        q = Polynomial(np.zeros(N), N)            # a
        u = mul_inv(b[N], p)                                        # b
        if degree(r) >= N and u is None:
            raise PolynomialError("Cannot calculate inverse of b[N]")
        while degree(r) >= N:                                       # c
            # print("ping")
            d = degree(r)                                               # 1
            print("krakakaka")
            print("d-N  : {}".format(d-N))
            print("u    : {}".format(u))
            print("r[d] : {}".format(r[d]))
            v = Polynomial(np.concatenate((np.zeros(d-N), np.repeat(r[d], u))), self.N)        # 2
            r = (r - v * b) % p                                         # 3
            q = (q + v) % p                                             # 4
            if d == 0:
                break
        self.N -= 1                                         # restore Parameters.N
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
        N = self.N
        u, v, d = EEA(p, self, Polynomial(np.concatenate((np.array([-1]), np.zeros(N-1), np.array([1]))), N+1))    # a
        if degree(d) == 0:                                                               # b
            d1 = mul_inv(d[0], p)                                                        # c
            return Polynomial(np.array([d1]), N) * u                                                  # c
        else:                                                                            # d
            return False                                                                 # d

    def inverse_3(self):
        N = self.N
        k = 0
        b = Polynomial(np.array([1]), N)
        c = Polynomial(np.array([0]), N)
        f = deepcopy(self) % 3
        f._coef += [0]
        g = Polynomial(np.concatenate((np.array([-1]), np.zeros(N-1), np.array([1]))), N+1)

        while True:
            f.center0(3)
            g.center0(3)
            while f[0] == 0:
                f._coef = f._coef[1:]
                c._coef = [0] + c._coef
                k += 1
                if len(f) == 0:
                    return False
            if abs(f[0]) == 1 and f[1:] == ([0] * (len(f) - 1)):
                k %= N
                kpol = Polynomial(np.concatenate((np.zeros(N-k), np.array([f[0]]))), N)  # X^N-k
                return kpol * b
            if degree(f) < degree(g):
                f,g = g,f
                b, c = c, b
            if f[0] == g[0]:
                f = (f-g) % 3
                b = (b-c) % 3
            else:
                f = (f+g) % 3
                b = (b+c) % 3

    def inverse_2(self):
        N = self.N
        k = 0
        b = Polynomial(np.array([1]), N)
        c = Polynomial(np.array([0]), N)
        f = deepcopy(self) % 2
        g = Polynomial(np.concatenate((np.array([-1]), np.zeros(N-1), np.array([1]))), N+1)

        while True:
            while f[0] == 0:
                f._coef = f._coef[1:]
                c._coef = [0] + c._coef
                k += 1
            if f[0] == 1 and (f._coef[1:] == 0).all():
                # b._coef = [0] * k + b._coef
                k %= N
                kpol = Polynomial(np.concatenate((np.zeros(N-k), np.array([1]))), N)  # X^N-k
                return kpol * b
            if degree(f) < degree(g):
                f, g = g, f
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
            b = (b * (Polynomial(np.array([2]), self.N) - self*b)) % q    # 4
        return b % pe                                   # 5

    def center0(self, q: int):
        if q == 2048:
            for i in range(len(self)):
                c = int(self[i]) & 2047
                if c >= 1024:
                    c -= 2048
                self[i] = c
        else:
            for i in range(len(self)):
                while self[i] < -q / 2:
                    self[i] += q
                while self[i] > q / 2:
                    self[i] -= q

    def resultant_p(self, p: int):
        """
        This function will calculate the resultant of this polynomial object with
        the polynomial X^N - 1 modulo p.
        :param p: prime integer
        :return: Polynomial rhoP in (Z/pZ)[X]/(X^N –1) and an integer resultant
        satisfying resultant = rhoP * self + rhox * (X^N -1) for some rhox in Zp[x]
        """
        N = self.N

        A = Polynomial([-1] + [0] * (N - 1) + [1], N + 1)
        # B = deepcopy(self)
        B = Polynomial(self[:], N+1)
        V1, V2, Temp = Polynomial([0], N+1), Polynomial([1], N+1), Polynomial([0], N+1)
        a, b, tempa, c, resultant = degree(A), degree(B), degree(A), 0, 1
        while b > 0:
            c = (mul_inv(B[b] % p, p) * A[a]) % p
            A = (A - B * Polynomial([0]*(a-b) + [c], N+1)) % p
            V1 = (V1 - V2 * Polynomial([0]*(a-b) + [c], N+1)) % p
            if degree(A) < b:
                resultant = (resultant * B[b]**(tempa-degree(A))) % p
                if (tempa % 2) == 1 and (b % 2) == 1:
                    resultant = (resultant * -1) % p
                A, B = B, A
                V1, V2 = V2, V1
                tempa = b
            a, b = degree(A), degree(B)
        resultant = (resultant * B[0]**a) % p
        if B[0] == 0:
            A, B = B, A
            V1, V2 = V2, V1
            print("shiiiit")
        c = mul_inv(B[0], p) % p
        rhoP = (V2 * Polynomial([c*resultant], N)) % p
        return rhoP, resultant

    def resultant(self) -> ("Polynomial", int):
        """
        This function will calculate the resultant of this polynomial with
        the polynomial X^N - 1
        :return: Polynomial rhoP in Z[X]/(X^N –1) and an integer resultant satisfying
        resultant = rhoP * P + rhox*(X^N –1) in Zp[X] for some rhox in Zp[X].
        """
        N = self.N
        # Take as max the actual resultant of self and X^N - 1, calculated using the determinant of the sylvester matrix
        Max = sylvester_resultant(self, Polynomial([-1] + [0] * (N - 1) + [1], N + 1))
        print("Max: {}".format(Max))

        primes = []
        Max2, i = Max * 2, 0
        print("Max2 = {}".format(Max2))
        primesprod = 1
        while primesprod < Max2:
            primes.append(PRIMES[i])
            primesprod *= PRIMES[i]
            i += 1

        pproduct, resultant = 1, 1
        rhoP = Polynomial([1], N)
        j, temp = 0, 0
        while j < len(primes):
            print("{0:.2f}".format(j/len(primes)))
            pj = primes[j]
            temp = pj * pproduct
            rhop, resp = self.resultant_p(pj)
            _, alphap, betapprod = xgcd(pj, pproduct)
            resultant = (resultant * alphap * pj + resp * betapprod * pproduct) % temp
            rhoP = (rhoP * Polynomial([alphap * pj], N) + rhop * Polynomial([betapprod * pproduct], N)) % temp
            pproduct = temp
            j += 1
        rhoP %= Max2
        rhoP.center0(Max2)
        return rhoP, resultant

    def resultant2(self) -> ("Polynomial", int):
        """
        This function will calculate the resultant of this polynomial with
        the polynomial X^N - 1
        :return: Polynomial rhoP in Z[X]/(X^N –1) and an integer resultant satisfying
        resultant = rhoP * P + rhox*(X^N –1) in Zp[X] for some rhox in Zp[X].
        """
        N = self.N
        NUM_EQUAL_RESULTANTS = 3

        pproduct, resultant = 1, 1
        j, temp = 0, 0
        numEqual = 1
        modResultants = []
        while True:
            print("while loop: {} - numEqual: {}".format(j, numEqual))
            pj = PRIMES[j]
            modResultants.append(list(self.resultant_p(pj)) + [pj])
            rhop, resp, _ = modResultants[0]

            temp = pj * pproduct
            _, alphap, betapprod = xgcd(pj, pproduct)
            resPrev = resultant
            resultant = (resultant * alphap * pj + resp * betapprod * pproduct) % temp
            # rhoP = (rhoP * Polynomial([alphap * pj], N) + rhop * Polynomial([betapprod * pproduct], N)) % temp
            pproduct = temp
            pproduct2 = pproduct // 2
            pproduct2n = pproduct2 * -1
            if resultant > pproduct2:
                resultant -= pproduct
            elif resultant < pproduct2n:
                resultant += pproduct

            if resultant == resPrev:
                numEqual += 1
                if numEqual > NUM_EQUAL_RESULTANTS:
                    break
            j += 1

        while True:
            if len(modResultants) <= 1:
                break
            modRes1 = modResultants[0]
            modRes2 = modResultants[1]
            modResultants = modResultants[2:] + [combineRho(modRes1, modRes2)]

        rhoP = modResultants[0][0]
        if resultant > pproduct2:
            resultant -= pproduct
        elif resultant < pproduct2n:
            resultant += pproduct

        for i in range(N):
            c = rhoP[i]
            if c > pproduct2:
                rhoP[i] -= pproduct
            if c < pproduct2n:
                rhoP[i] += pproduct

        # rhoP %= Max2
        # rhoP.center0(Max2)
        return rhoP, resultant


def combineRho(modRes1, modRes2):
    # print("modRes1: {}".format(modRes1))
    # print("modRes2: {}".format(modRes2))

    mod1 = modRes1[2]
    # print("mod1: {}".format(mod1))
    mod2 = modRes2[2]
    # print("mod2: {}".format(mod2))

    prod = mod1 * mod2
    # print("prod: {}".format(prod))
    _, x, y = xgcd(mod2, mod1)
    # print("inverses: {}, {}".format(x, y))

    rho1 = modRes1[0]
    # print("rho1: {}".format(rho1))
    rho1 = rho1 * Polynomial([x * mod2], rho1.N)
    # print("rho1-2: {}".format(rho1))
    rho2 = modRes2[0]
    # print("rho2: {}".format(rho2))
    rho2 = rho2 * Polynomial([y * mod1], rho2.N)
    # print("rho2-2: {}".format(rho1))

    return [(rho1 + rho2) % prod, None, prod]




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
    N = a.N
    if not (isinstance(a, Polynomial) and isinstance(b, Polynomial)):       # if a or b is not a polynomial raise an error
        raise PolynomialError("Both a and b need to be polynomial objects")

    if (b._coef == 0).all():                         # a
        return Polynomial(np.array([1]), N), Polynomial(np.array([0]), N), a                          # a

    u = Polynomial(np.array([1]), N + 1)                                                     # b
    d = a % p                                                               # c
    v1 = Polynomial(np.array([0]), N + 1)                                                    # d
    v3 = b % p                                                              # e
    while not (v3._coef == 0).all():            # f
        q, t3 = d.poly_div(p, v3)                                               # 1
        t1 = (u - q * v1) % p                                                   # 2
        u = v1                                                                  # 3
        d = v3                                                                  # 4
        v1 = t1                                                                 # 5
        v3 = t3                                                                 # 6
    v, vr = ((a*u) % p).poly_div(p, b)                                      # g
    return u, v, d                                                          # h


def sylvester_resultant(p: Polynomial, q: Polynomial) -> int:
    """
    This function will calculate the resultant of 2 polynomials
    by calculating the determinant of the sylvestermatrix formed by
    these 2 polynomials
    :return: resultant of p and q
    """
    from numpy.linalg import det
    pRev = list(reversed(p[:]))
    while pRev[0] == 0:
        pRev = pRev[1:]
    qRev = list(reversed(q[:]))
    while qRev[0] == 0:
        qRev = qRev[1:]
    m = len(pRev) - 1
    n = len(qRev) - 1
    syl = [[0] * (m+n)] * (m+n)
    for row in range(n):
        syl[row] = ([0] * row) + pRev + ([0] * (n-1-row))
    for row in range(m):
        syl[row+n] = ([0] * row) + qRev + ([0] * (m-1-row))
    return int(det(syl))

###
# Prime numbers > 4500 for resultant computation. Starting them below ~4400 causes incorrect results occasionally.
# Fortunately, 4500 is about the optimum number for performance.
# This array contains enough prime numbers so primes never have to be computed on-line for any Signing Parameter standard
#
# I copied this list from the NTRUJava implementation, which can be found at: https://github.com/tbuktu/ntru
###
PRIMES = [
        4507, 4513, 4517, 4519, 4523, 4547, 4549, 4561, 4567, 4583,
        4591, 4597, 4603, 4621, 4637, 4639, 4643, 4649, 4651, 4657,
        4663, 4673, 4679, 4691, 4703, 4721, 4723, 4729, 4733, 4751,
        4759, 4783, 4787, 4789, 4793, 4799, 4801, 4813, 4817, 4831,
        4861, 4871, 4877, 4889, 4903, 4909, 4919, 4931, 4933, 4937,
        4943, 4951, 4957, 4967, 4969, 4973, 4987, 4993, 4999, 5003,
        5009, 5011, 5021, 5023, 5039, 5051, 5059, 5077, 5081, 5087,
        5099, 5101, 5107, 5113, 5119, 5147, 5153, 5167, 5171, 5179,
        5189, 5197, 5209, 5227, 5231, 5233, 5237, 5261, 5273, 5279,
        5281, 5297, 5303, 5309, 5323, 5333, 5347, 5351, 5381, 5387,
        5393, 5399, 5407, 5413, 5417, 5419, 5431, 5437, 5441, 5443,
        5449, 5471, 5477, 5479, 5483, 5501, 5503, 5507, 5519, 5521,
        5527, 5531, 5557, 5563, 5569, 5573, 5581, 5591, 5623, 5639,
        5641, 5647, 5651, 5653, 5657, 5659, 5669, 5683, 5689, 5693,
        5701, 5711, 5717, 5737, 5741, 5743, 5749, 5779, 5783, 5791,
        5801, 5807, 5813, 5821, 5827, 5839, 5843, 5849, 5851, 5857,
        5861, 5867, 5869, 5879, 5881, 5897, 5903, 5923, 5927, 5939,
        5953, 5981, 5987, 6007, 6011, 6029, 6037, 6043, 6047, 6053,
        6067, 6073, 6079, 6089, 6091, 6101, 6113, 6121, 6131, 6133,
        6143, 6151, 6163, 6173, 6197, 6199, 6203, 6211, 6217, 6221,
        6229, 6247, 6257, 6263, 6269, 6271, 6277, 6287, 6299, 6301,
        6311, 6317, 6323, 6329, 6337, 6343, 6353, 6359, 6361, 6367,
        6373, 6379, 6389, 6397, 6421, 6427, 6449, 6451, 6469, 6473,
        6481, 6491, 6521, 6529, 6547, 6551, 6553, 6563, 6569, 6571,
        6577, 6581, 6599, 6607, 6619, 6637, 6653, 6659, 6661, 6673,
        6679, 6689, 6691, 6701, 6703, 6709, 6719, 6733, 6737, 6761,
        6763, 6779, 6781, 6791, 6793, 6803, 6823, 6827, 6829, 6833,
        6841, 6857, 6863, 6869, 6871, 6883, 6899, 6907, 6911, 6917,
        6947, 6949, 6959, 6961, 6967, 6971, 6977, 6983, 6991, 6997,
        7001, 7013, 7019, 7027, 7039, 7043, 7057, 7069, 7079, 7103,
        7109, 7121, 7127, 7129, 7151, 7159, 7177, 7187, 7193, 7207,
        7211, 7213, 7219, 7229, 7237, 7243, 7247, 7253, 7283, 7297,
        7307, 7309, 7321, 7331, 7333, 7349, 7351, 7369, 7393, 7411,
        7417, 7433, 7451, 7457, 7459, 7477, 7481, 7487, 7489, 7499,
        7507, 7517, 7523, 7529, 7537, 7541, 7547, 7549, 7559, 7561,
        7573, 7577, 7583, 7589, 7591, 7603, 7607, 7621, 7639, 7643,
        7649, 7669, 7673, 7681, 7687, 7691, 7699, 7703, 7717, 7723,
        7727, 7741, 7753, 7757, 7759, 7789, 7793, 7817, 7823, 7829,
        7841, 7853, 7867, 7873, 7877, 7879, 7883, 7901, 7907, 7919,
        7927, 7933, 7937, 7949, 7951, 7963, 7993, 8009, 8011, 8017,
        8039, 8053, 8059, 8069, 8081, 8087, 8089, 8093, 8101, 8111,
        8117, 8123, 8147, 8161, 8167, 8171, 8179, 8191, 8209, 8219,
        8221, 8231, 8233, 8237, 8243, 8263, 8269, 8273, 8287, 8291,
        8293, 8297, 8311, 8317, 8329, 8353, 8363, 8369, 8377, 8387,
        8389, 8419, 8423, 8429, 8431, 8443, 8447, 8461, 8467, 8501,
        8513, 8521, 8527, 8537, 8539, 8543, 8563, 8573, 8581, 8597,
        8599, 8609, 8623, 8627, 8629, 8641, 8647, 8663, 8669, 8677,
        8681, 8689, 8693, 8699, 8707, 8713, 8719, 8731, 8737, 8741,
        8747, 8753, 8761, 8779, 8783, 8803, 8807, 8819, 8821, 8831,
        8837, 8839, 8849, 8861, 8863, 8867, 8887, 8893, 8923, 8929,
        8933, 8941, 8951, 8963, 8969, 8971, 8999, 9001, 9007, 9011,
        9013, 9029, 9041, 9043, 9049, 9059, 9067, 9091, 9103, 9109,
        9127, 9133, 9137, 9151, 9157, 9161, 9173, 9181, 9187, 9199,
        9203, 9209, 9221, 9227, 9239, 9241, 9257, 9277, 9281, 9283,
        9293, 9311, 9319, 9323, 9337, 9341, 9343, 9349, 9371, 9377,
        9391, 9397, 9403, 9413, 9419, 9421, 9431, 9433, 9437, 9439,
        9461, 9463, 9467, 9473, 9479, 9491, 9497, 9511, 9521, 9533,
        9539, 9547, 9551, 9587, 9601, 9613, 9619, 9623, 9629, 9631,
        9643, 9649, 9661, 9677, 9679, 9689, 9697, 9719, 9721, 9733,
        9739, 9743, 9749, 9767, 9769, 9781, 9787, 9791, 9803, 9811,
        9817, 9829, 9833, 9839, 9851, 9857, 9859, 9871, 9883, 9887,
        9901, 9907, 9923, 9929, 9931, 9941, 9949, 9967, 9973]

#
# a = Polynomial([4, 2, 2, 1], 4)
# b = Polynomial([-1, 0, 0, 0, 1], 5)
# print(sylvester_resultant(a, b))
# print(a.resultant_p(503))
# f, g, d = EEA(503, a, b)
# print(f)
# print(g)
# print(d)
# if __name__ == "__main__":
# a = Polynomial([1, 1, 0, 2, 1, 0, 2], 11)
# b = Polynomial([0, 0, 0, 2], 11)
# print(a.poly_div(3, b))
# # print(a+b)
# f = Polynomial([-1, 1, 1, 0, -1, 0, 1, 0, 0, 1, -1], 11)
# g = Polynomial([-1, 0, 1, 1, 0, 1, 0, 0, -1, 0, -1], 11)
# fp = Polynomial([1, 2, 0, 2, 2, 1, 0, 2, 1, 2], 11)
# fq = Polynomial([5, 9, 6, 16, 4, 15, 16, 22, 20, 18, 30], 11)
# print(f)
# print(fq)
# print(f*fq % 32)
# print(f.inverse(3))
# a, b, c = EEA(3, f, fp)
# print(a)
# print(b)
# print(c)
# print(fp)
#     # print("-------------------------------------")
#     # print(f.inverse_pow_2(2, 5))
#     # print(fq)
#
#     # a = Polynomial([45, 2, 77, 103, 12])
#     # print(a)
#     # print(Polynomial.fromBSP(a.toBSP(128), N=5, q=128))
#     Parameters.N = 11
#     Parameters.p = 3
#     Parameters.q = 32
#     print((f.inverse_pow_2(2,5) * f) % 32)
#     os = (f % 3).toOSP(32)
#     print(Polynomial.fromOSP(os, N=11, q=32))
