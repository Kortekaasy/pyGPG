import math
from src.Utils.Polynomial import Polynomial
from src.Utils.Arithmetic import i2osp

"""
These classes will be used to implement a "index generation function", while keeping track
of the current internal state for the next generation

[1]: IEEE Std 1363.1 - IEEE Standard Specification for Public Key Cryptographic Techniques Based on Hard Problems over Lattices (http://ieeexplore.ieee.org/document/4800404/)
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
        pass




