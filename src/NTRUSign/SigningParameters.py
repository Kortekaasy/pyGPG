import hashlib


class Parameters:
    initialized = False

    # NTRUSign Domain Parameters (required)
    N = 0
    q = 0

    # NTRUSign Security Parameters (recommended)
    df = 0
    dg = 0
    maxAdjustment = 0
    signFailTolerance = 0
    keyNormBound = None
    # KGP-NTRUSign1
    pertubationBases = 0
    basisType = ""

    # NTRUSign Scheme Options (required)
    normBound = 0
    lr = 0
    # MRGM-NTRUSign2 with
    NTRUSign2 = False
    c = 0
    numGroups = 0
    numElements = 0
    hashFunc = None
    prng = None  # PRNG-MGF1 with MDC-NTRU (PRNG)

    pset = ""

    @staticmethod
    def initParameters(parameterset: str):
        if parameterset == "ees251sp2":
            Parameters.setParameters(251, 127, 73, 71, 200, 0, 0, "standard", 310, 1, hashlib.sha1, "PRNG-MGF1 with SHA-1 (PRNG)", "ees251sp2", 8, 13, 3)
        elif parameterset == "ees251sp3":
            Parameters.setParameters(251, 128, 73, 71, 200, 0, 0, "standard", 310, 1, hashlib.sha1, "PRNG-MGF1 with MDC-NTRU (PRNG)", "ees251sp3", 8, 13, 3)
        elif parameterset == "ees251sp4":
            Parameters.setParameters(251, 128, 73, 71, 200, 0, 0, "standard", 310, 1, hashlib.sha1, "PRNG-MGF1 with SHA-1 (PRNG)", "ees251sp4")
        elif parameterset == "ees251sp5":
            Parameters.setParameters(251, 128, 73, 71, 200, 0, 0, "standard", 310, 1, hashlib.sha1, "PRNG-MGF1 with MDC-NTRU (PRNG)", "ees251sp5")
        elif parameterset == "ees251sp6":
            Parameters.setParameters(251, 128, 73, 71, 200, 0, 1, "transpose", 310, 1, hashlib.sha1, "PRNG-MGF1 with SHA-1 (PRNG)", "ees251sp6", 8, 13, 3)
        elif parameterset == "ees251sp7":
            Parameters.setParameters(251, 128, 73, 71, 200, 0, 1, "transpose", 310, 1, hashlib.sha1, "PRNG-MGF1 with MDC-NTRU (PRNG)", "ees251sp7", 8, 13, 3)
        elif parameterset == "ees251sp8":
            Parameters.setParameters(251, 128, 73, 71, 200, 0, 1, "transpose", 310, 1, hashlib.sha1, "PRNG-MGF1 with SHA-1 (PRNG)", "ees251sp8")
        elif parameterset == "ees251sp9":
            Parameters.setParameters(251, 128, 73, 71, 200, 0, 1, "transpose", 310, 1, hashlib.sha1, "PRNG-MGF1 with MDC-NTRU (PRNG)", "ees251sp9")
        else:
            return False
        return True


    @staticmethod
    def setParameters(N: int, q: int, df: int, dg: int, maxAdjustment: int, signFailTolerance: int,
                      pertubationBases: int, basisType: str, normBound: int, lr: int, hashFunc,
                      prng, pset: str, c: int=-1, numGroups: int=-1, numElements: int=-1):
        Parameters.N = N
        Parameters.q = q
        Parameters.df = df
        Parameters.dg = dg
        Parameters.maxAdjustment = maxAdjustment
        Parameters.signFailTolerance = signFailTolerance
        Parameters.pertubationBases = pertubationBases
        Parameters.basisType = basisType
        Parameters.normBound = normBound
        Parameters.lr = lr
        Parameters.hashFunc = hashFunc
        Parameters.prng = prng

        # optional depending on parameter set
        Parameters.NTRUSign2 = c != -1
        Parameters.c = c
        Parameters.numGroups = numGroups
        Parameters.numElements = numElements

        Parameters.pset = pset
        Parameters.initialized = True

