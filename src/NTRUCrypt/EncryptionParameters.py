import hashlib


class Parameters:
    initialized = False

    N = 0
    p = 0
    q = 0

    # keygen: KGP-3
    df = 0
    dg = 0

    lLen = 0
    db = 0
    maxMsgLenBytes = 0
    bufferLenBits = 0
    bufferLenTrits = 0
    dm = 0

    #MGF-TP-1
    mgfhash = None

    #BPGM3
    igfhash = None
    dr = 0
    c = 0
    minCallsR = 0
    minCallsMask = 0

    OID = ""
    pkLen = 0

    pset = ""

    @staticmethod
    def initParameters(parameterset: str):
        if parameterset == "ees401ep1":
            Parameters.setParameters(401, 3, 2048, 113, 133, 1, 112, 60, 600, 400, 113, hashlib.sha1, hashlib.sha1, 113, 11, 32, 9, bytearray([0, 2, 4]), 114, "ees401ep1")
        elif parameterset == "ees449ep1":
            Parameters.setParameters(449, 3, 2048, 134, 149, 1, 128, 67, 672, 448, 134, hashlib.sha1, hashlib.sha1, 134, 9, 31, 9, bytearray([0, 3, 3]), 128, "ees449ep1")
        elif parameterset == "ees677ep1":
            Parameters.setParameters(677, 3, 2048, 157, 225, 1, 192, 101, 1008, 676, 157, hashlib.sha256, hashlib.sha256, 157, 11, 27, 9, bytearray([0, 5, 3]), 192, "ees677ep1")
        elif parameterset == "ees1087ep2":
            Parameters.setParameters(1087, 3, 2048, 120, 362, 1, 256, 170, 1624, 1086, 120, hashlib.sha256, hashlib.sha256, 120, 13, 25, 14, bytearray([0, 6, 3]), 256, "ees1087ep2")
        elif parameterset == "ees541ep1":
            Parameters.setParameters(541, 3, 2048, 49, 180, 1, 112, 86, 808, 540, 49, hashlib.sha1, hashlib.sha1, 49, 12, 15, 11, bytearray([0, 2, 5]), 112, "ees541ep1")
        elif parameterset == "ees613ep1":
            Parameters.setParameters(613, 3, 2048, 55, 204, 1, 128, 97, 912, 612, 55, hashlib.sha1, hashlib.sha1, 55, 11, 16, 13, bytearray([0, 3, 4]), 128, "ees613ep1")
        elif parameterset == "ees887ep1":
            Parameters.setParameters(887, 3, 2048, 81, 295, 1, 192, 141, 1328, 886, 81, hashlib.sha256, hashlib.sha256, 81, 10, 13, 12, bytearray([0, 5, 4]), 192, "ees887ep1")
        elif parameterset == "ees1171ep1":
            Parameters.setParameters(1171, 3, 2048, 106, 390, 1, 256, 186, 1752, 1170, 106, hashlib.sha256, hashlib.sha256, 106, 10, 20, 15, bytearray([0, 6, 4]), 256, "ees1171ep1")
        elif parameterset == "ees659ep1":
            Parameters.setParameters(659, 3, 2048, 38, 219, 1, 112, 108, 984, 658, 38, hashlib.sha1, hashlib.sha1, 38, 11, 11, 14, bytearray([0, 2, 6]), 112, "ees659ep1")
        elif parameterset == "ees791ep1":
            Parameters.setParameters(761, 3, 2048, 42, 253, 1, 128, 125, 1136, 760, 42, hashlib.sha1, hashlib.sha1, 42, 12, 13, 16, bytearray([0, 3, 5]), 128, "ees791ep1")
        elif parameterset == "ees1087ep1":
            Parameters.setParameters(1087, 3, 2048, 63, 362, 1, 192, 178, 1624, 1086, 63, hashlib.sha256, hashlib.sha256, 63, 13, 13, 14, bytearray([0, 5, 5]), 192, "ees1087ep1")
        elif parameterset == "ees1499ep1":
            Parameters.setParameters(1499, 3, 2048, 79, 499, 1, 256, 247, 2240, 1498, 79, hashlib.sha512, hashlib.sha512, 79, 13, 17, 19, bytearray([0, 6, 5]), 256, "ees1499ep1")
        else:
            return False
        return True


    @staticmethod
    def setParameters(N: int, p: int, q: int, df: int, dg: int,
                      lLen: int, db: int, maxMsgLenBytes: int, bufferLenBits: int,
                      bufferLenTrits: int, dm: int, mgfhash, igfhash, dr: int, c: int,
                      minCallsR: int, minCallsMask: int, OID: bytearray, pkLen: int, pset: str):
        Parameters.N = N
        Parameters.p = p
        Parameters.q = q
        Parameters.df = df
        Parameters.dg = dg
        Parameters.lLen = lLen
        Parameters.db = db
        Parameters.maxMsgLenBytes = maxMsgLenBytes
        Parameters.bufferLenBits = bufferLenBits
        Parameters.bufferLenTrits = bufferLenTrits
        Parameters.dm = dm
        Parameters.mgfhash = mgfhash
        Parameters.igfhash = igfhash
        Parameters.dr = dr
        Parameters.c = c
        Parameters.minCallsR = minCallsR
        Parameters.minCallsMask = minCallsMask
        Parameters.OID = OID
        Parameters.pkLen = pkLen

        Parameters.pset = pset
        Parameters.initialized = True

