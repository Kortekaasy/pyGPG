from src.NTRUCrypt.IndexGenerator import *
from src.Utils.Parameters import *
from src.Utils.Polynomial import *

class NTRUCrypt:

    def __init__(self):
        pass

    def blindingPolynomial(self, seed: str):
        """
        This function will be used to generate a blinding polynomial r.
        This algorithm is specified in section 8.3.2.2 in [1]
        :param seed: octet string seed for the index generating function
        :return: blinding polynomial r
        """
        # a
        igf = IGF(seed, Parameters.q, Parameters.hashSeed, Parameters.c, Parameters.minCallsR)

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
