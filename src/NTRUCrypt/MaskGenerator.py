import math

from src.NTRUCrypt.EncryptionParameters import Parameters
from src.Utils.Arithmetic import i2osp
from src.Utils.Polynomial import Polynomial

"""
These classes will be used to implement a "index generation function", while keeping track
of the current internal state for the next generation

[1]: IEEE Std 1363.1 - IEEE Standard Specification for Public Key Cryptographic Techniques Based on Hard Problems over Lattices (http://ieeexplore.ieee.org/document/4800404/)
"""


class MGFError(Exception):
    """
    This class will be used to represent errors that have to do with
    the IGF object specified below
    """
    pass


class MGF:

    @staticmethod
    def generateMask(seed: bytearray, N: int=Parameters.N, hashSeed: bool=True):
        """
        This function takes as input an octet string and the desired degree of the output, and produces
        a ternary polynomial of the appropriate degree. The only hash functions supported for use with mask
        generating functions are SHA-1 and SHA-256.
        This algorithm is implemented according to section 8.4.1.1 in [1]
        :param seed: octet list of length seedLen octets
        :param N: degree of the output polynomial, an integer
        :param hashSeed: boolean specifying if the seed needs to be hashed
        :return: a ternary polynomial of degree N
        """
        if not Parameters.initialized:
            raise MGFError("Initialize the parameters before generating a mask!")
        minCallsMask = Parameters.minCallsMask

        if len(seed) > (2**61 - 1):                                             # a
            raise MGFError("Length of the seed is too long (> 2^64 bytes)")     # a
        if minCallsMask > 2**32:                                                # b
            raise MGFError("Value of minCallsMask exceeds 2^32!")               # b
        if isinstance(seed, str):
            seed = bytearray(seed.encode('utf-8'))
        if hashSeed:                                                            # c
            Z = MGF._hashString_(seed)                                              # 1
            zLen = MGF.hLen()                                                       # 1
        else:
            Z = seed                                                                # 2
            zLen = len(seed)                                                        # 2
        buf = bytearray()                                                       # d
        counter = 0                                                             # e
        c, cLen = Parameters.c, math.ceil(Parameters.c / 8)                     # f
        while counter < minCallsMask:                                           # g
            C = i2osp(counter, 4)                                                   # 1
            H = MGF._hashString_(Z+C)                                               # 2
            buf.extend(H)                                                           # 3
            counter += 1                                                            # 4
        i, cur = Polynomial([0] * N), 0                                         # h
        loopCond = True
        while loopCond:
            for o in buf:                                                           # i    - o is already an int
                if o >= 243:                                                            # 2
                    continue                                                            # 2
                for k in range(4):                                                      # do step i(3-6)
                    i[cur] = o % 3                                                       # 3-6
                    cur += 1                                                         # 3-6
                    if cur == N:                                                        # 3-6
                        return i                                                          # 3-6
                    o = (o - (o % 3)) // 3                                              # 3-6
                i[cur] = o                                                              # 7
                cur += 1                                                                # 7
                if cur == N:                                                            # 7
                    return i                                                            # 7
            if cur < N:                                                              # j
                C = i2osp(counter, 4)                                                   # 1
                H = MGF._hashString_(Z + C)                                             # 2
                buf = bytearray(H)                                                      # 3
                counter += 1                                                            # 4
            else:
                loopCond = False                                                        # 5   - implement return with a while loop
        return i

    @staticmethod
    def hLen():
        return Parameters.igfhash().digest_size

    @staticmethod
    def _hashString_(value) -> str:
        """
        This function will hash the string value and return the hex output
        :param value: string to hash
        :return: hex output of the string hash
        """
        if isinstance(value, str):
            value = value.encode('utf-8')

        m = Parameters.mgfhash()            # get a hash instance specified by EncryptionParameters.py
        m.update(value)                     # add the string to the buffer of the hash, this has to be a bytestring, not a normal string
        return bytearray(m.digest())        # return the hex output of the hash function


