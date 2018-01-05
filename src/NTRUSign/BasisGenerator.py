import math
from src.Utils.Polynomial import Polynomial, PolynomialError, EEA, degree
from src.Utils.Arithmetic import *
from src.NTRUSign.SigningParameters import Parameters
import secrets

"""
These classes will be used to implement a "index generation function", while keeping track
of the current internal state for the next generation

[1]: Efficient Embedded Security Standards - Implementation Aspects of NTRUEncrypt and NTRUSign (http://grouper.ieee.org/groups/1363/lattPK/submissions/EESS1v2.pdf)
[2]: NTRUSIGN: Digital Signatures Using the NTRU Lattice (http://www.math.brown.edu/~jpipher/NTRUSign-preV2.pdf)
"""


class BasisGeneratorError(Exception):
    """
    This class will be used to represent errors that have to do with
    the IGF object specified below
    """
    pass


class BasisGenerator:

    @staticmethod
    def generateBasis():
        """
        This function will generate a NTRUSign basis according to the specification in section 3.5.1.1
        of [1].
        :return: An NTRUSign basis consisting of the polynomials (f, g, F, G)
        """
        N = Parameters.N
        q = Parameters.q
        df = Parameters.df
        dg = Parameters.dg
        maxAdjustment = Parameters.maxAdjustment

        i = 0                               # generating a polynomial f with df coefficients 1
        f = Polynomial([0], N)
        print("generating f")
        while i < df:
            pos = secrets.randbelow(N)
            if f[pos] == 0:
                f[pos] = 1
                i += 1

        i = 0                               # generating a polynomial g with dg coefficients 1
        g = Polynomial([0], N)
        print("generating g")
        while i < dg:
            pos = secrets.randbelow(N)
            if g[pos] == 0:
                g[pos] = 1
                i += 1

        # optional if 2N + 1 is prime (All parameters have N = 251, and 2*251 + 1 = 503, which is prime)
        _, resf1 = f.resultant_p(2*N + 1)
        # exit(0)
        print("ping")
        _, resg1 = g.resultant_p(2*N + 1)
        if resf1 == 0 and resg1 == 0:
            return BasisGenerator.generateBasis()
        print("f, g okay")

        rhof, resf = f.resultant2()
        print("calculated resultant f")
        rhog, resg = g.resultant2()
        print("calculated resultant g")
        gcd, alpha, beta = xgcd(resf, resg)
        if gcd != 1:
            return BasisGenerator.generateBasis()
        print("gcd ok")
        finv = f.inverse_pow_2(2, int(math.floor(math.log2(q))))
        if not isinstance(finv, Polynomial):
            return BasisGenerator.generateBasis()
        print("inverse ok")

        F = rhog * Polynomial([beta * q * -1], N)
        print("F: {}".format(F))
        G = rhof * Polynomial([alpha * q], N)
        print("G: {}".format(G))
        print("F: {}".format(F))
        frev, grev = Polynomial(list(reversed(f[:])), N), Polynomial(list(reversed(g[:])), N)
        print("frev: {}".format(frev))
        print("grev: {}".format(grev))
        print("F: {}".format(F))
        t = f*frev + g*grev
        print("t: {}".format(t))
        print("F: {}".format(F))
        rhot, rest = t.resultant2()
        print("rho t: {}".format(rhot))
        print("res t: {}".format(rest))
        print("F: {}".format(F))

        c = rhot * (frev*F + grev*G)
        print("c: {}".format(c))
        print("F: {}".format(F))
        i, j, k = 0, 0, 0
        while j < N:
            c[j] = int(math.floor(c[j] / rest + 0.5))
            j += 1
        print("c: {}".format(c))
        print("F: {}".format(F))
        print("c*f = {}".format(c*f))
        print("F - c*f = {}".format(F - c*f))
        F = F - c*f
        print("F: {}".format(F))
        G = G - c*g
        print("c*g = {}".format(c*g))
        print("G - c*g = {}".format(F - c*g))
        print("F: {}".format(F))
        print("G: {}".format(G))

        f, g, F, G = map(lambda x: x % q, [f, g, F, G])
        return f, g, F, G

    @staticmethod
    def myGenerateBasis():
        """
        This function will generate a NTRUSign basis according to the specification in section 3.5.1.1
        of [1].
        :return: An NTRUSign basis consisting of the polynomials (f, g, F, G)
        """
        N = Parameters.N
        q = Parameters.q
        df = Parameters.df
        dg = Parameters.dg
        maxAdjustment = Parameters.maxAdjustment

        i = 0  # generating a polynomial f with df coefficients 1
        f = Polynomial([0], N)
        print("generating f")
        while i < df:
            pos = secrets.randbelow(N)
            if f[pos] == 0:
                f[pos] = 1
                i += 1

        i = 0  # generating a polynomial g with dg coefficients 1
        g = Polynomial([0], N)
        print("generating g")
        while i < dg:
            pos = secrets.randbelow(N)
            if g[pos] == 0:
                g[pos] = 1
                i += 1

        # optional if 2N + 1 is prime (All parameters have N = 251, and 2*251 + 1 = 503, which is prime)
        print("ping")
        _, resf1 = f.resultant_p(2 * N + 1)
        # exit(0)
        print("pong")
        _, resg1 = g.resultant_p(2 * N + 1)
        if resf1 == 0 and resg1 == 0:
            return BasisGenerator.myGenerateBasis()
        print("f, g okay")

        gminus = g * Polynomial([-1], 1)
        try:
            G1, F1, d = EEA(q, f, gminus)
        except PolynomialError:
            BasisGenerator.myGenerateBasis()
        if degree(d) != 0:
            return BasisGenerator.myGenerateBasis()

        Fq = F1 * Polynomial([q], 1)
        Gq = G1 * Polynomial([q], 1)

        f, g, F, G = map(lambda x: x % q, [f, g, Fq, Gq])
        return f, g, F, G
