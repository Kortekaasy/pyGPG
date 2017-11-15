from src.NTRUCrypt.IndexGenerator import *
import time
from src.Utils.Parameters import *
from src.Utils.Polynomial import *
import secrets

class NTRUCrypt:

    def __init__(self):
        # Parameters.initParameters("ees401ep1")
        Parameters.initParameters("ees1499ep1")
        pass

    def blindingPolynomial(self, seed: str):
        """
        This function will be used to generate a blinding polynomial r.
        This algorithm is specified in section 8.3.2.2 in [1]
        :param seed: octet string seed for the index generating function
        :return: blinding polynomial r
        """
        # a
        igf = IGF(seed, True)

        r = Polynomial([0 for i in range(Parameters.N)])        # b
        t = 0                                                   # c
        while t < Parameters.dr:                                # d
            i = igf.generateIndex()                                 # 1
            if r[i] == 0:                                           # 2
                r[i] = 1                                                # I
                t += 1                                                  # II
        t = 0                                                   # e
        while t < Parameters.dr:                                # f
            i = igf.generateIndex()                                 # 1
            if r[i] == 0:                                           # 2
                r[i] = -1                                               # I
                t += 1                                                  # II
        return r                                                # g

    def keygen(self) -> (Polynomial, Polynomial):
        """
        A key pair shall be generated using the following or a mathematically equivalent set of steps. Note that the
        algorithm below outputs only the values f and h. In some applications it may be desirable to store the values
        f^–1 and g as well. This standard does not specify the output format for the key as long as it is unambiguous.
        :return: a keypair consisting of private key f and public key h
        """
        N = Parameters.N
        f = Polynomial([0] * N)
        g = Polynomial([0] * N)                                     # g
        f_invertible = False
        g_invertible = False

        print("generating f")
        while not f_invertible:
            F = Polynomial([0 for i in range(N)])                   # a
            t = 0                                                   # b
            while t < Parameters.df:                                # c
                i = self._getRand_(N)                                   # 1
                if F[i] == 0:                                           # 2
                    F[i] = 1                                                # I
                    t += 1                                                  # II
            t = 0                                                   # d
            while t < Parameters.df:                                # d
                i = self._getRand_(N)                                   # 1
                if F[i] == 0:                                           # 2
                    F[i] = -1                                               # I
                    t += 1                                                  # II
            f = Polynomial([1]) + (Polynomial([Parameters.p]) * F)  # e
            f_inv = f.inverse_pow_2(2, int(math.log2(Parameters.q)))    # f
            f_invertible = isinstance(f_inv, Polynomial)            # f
            print("f invertible: {}".format(f_invertible))

        print("generating g")
        while not g_invertible:
            t = 0                                                   # h
            while t < Parameters.dg + 1:                            # i
                i = self._getRand_(N)                                   # 1
                if g[i] == 0:                                           # 2
                    g[i] = 1                                                # I
                    t += 1                                                  # II
            t = 0                                                   # j
            while t < Parameters.dg:                                # k
                i = self._getRand_(N)                                   # 1
                if g[i] == 0:                                           # 2
                    g[i] = -1                                               # I
                    t += 1                                                  # II
            g_inv = g.inverse_pow_2(2, int(math.log2(Parameters.q)))    # l
            g_invertible = isinstance(g_inv, Polynomial)            # l
        h = f_inv * g * Polynomial([Parameters.p])                  # m
        return f, h




    def _getRand_(self, max=-1):
        """
        Generate and return a random number below max
        :param max: upper bound for random number, if max = -1 => max = 2^32
        :return: random number bounded by max
        """
        if max == -1:
            max = 2**32
        return secrets.randbelow(max)


crypt = NTRUCrypt()
t0 = time.clock()
priv, pub = crypt.keygen()
t1 = time.clock()
print(priv % Parameters.q)
print(pub % Parameters.q)
print("done in {} seconds".format(t1-t0))