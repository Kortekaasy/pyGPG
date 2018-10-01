import secrets
import time

from src.NTRUCrypt.MaskGenerator import MGF
from src.Utils.Polynomial import *


class KeyPair:

    def __init__(self, f, fp, fq, g, h):
        self.f = f
        self.fp = fp
        self.fq = fq
        self.g = g
        self.h = h

    def save(self, password: str, path: str):
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
        import base64
        import hmac, hashlib
        import os

        backend = default_backend()
        salt = secrets.token_bytes(16)

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2**14,
            r=8,
            p=1,
            backend=backend
        )
        key = kdf.derive(password.encode('utf-8'))
        f = Fernet(base64.urlsafe_b64encode(key))
        ftoken = f.encrypt(bytes(self.f.toOSP(Parameters.q)))
        fptoken = f.encrypt(bytes(self.fp.toOSP(Parameters.q)))
        fqtoken = f.encrypt(bytes(self.fq.toOSP(Parameters.q)))
        gtoken = f.encrypt(bytes(self.g.toOSP(Parameters.q)))
        htoken = bytes(self.h.toOSP(Parameters.q))

        fhmac = hmac.new(key, self.f.toOSP(Parameters.q)).digest()
        fphmac = hmac.new(key, self.fp.toOSP(Parameters.q)).digest()
        fqhmac = hmac.new(key, self.fq.toOSP(Parameters.q)).digest()
        ghmac = hmac.new(key, self.g.toOSP(Parameters.q)).digest()
        hhmac = hmac.new(key, self.h.toOSP(Parameters.q)).digest()

        toSave = {
            'salt': [x for x in salt],
            'version': Parameters.pset,
            'tokens': {
                'f':  [x for x in ftoken],
                'fp': [x for x in fptoken],
                'fq': [x for x in fqtoken],
                'g':  [x for x in gtoken],
                'h':  [x for x in htoken]
            },
            'hmacs': {
                'f': [x for x in fhmac],
                'fp': [x for x in fphmac],
                'fq': [x for x in fqhmac],
                'g': [x for x in ghmac],
                'h': [x for x in hhmac]
            }
        }

        md = hashlib.sha256(str(toSave).encode('utf-8'))
        filepath = os.path.join(path, str(md.hexdigest())[:8] + ".key")

        with open(filepath, 'w') as fp:
            import json
            json.dump(toSave, fp)
        return filepath

    @staticmethod
    def load(file: str, password: str, publicOnly = False):
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
        import base64
        import hmac

        if publicOnly:
            return KeyPair._loadPublic(file)

        with open(file, 'rb') as fp:
            import json
            contents = json.load(fp)
        salt = bytes(contents['salt'])
        version = contents['version']

        backend = default_backend()

        kdf = Scrypt(
            salt=salt,
            length=32,
            n=2 ** 14,
            r=8,
            p=1,
            backend=backend
        )
        key = kdf.derive(password.encode('utf-8'))
        f = Fernet(base64.urlsafe_b64encode(key))

        fbytes = f.decrypt(bytes(contents['tokens']['f']))
        fpbytes = f.decrypt(bytes(contents['tokens']['fp']))
        fqbytes = f.decrypt(bytes(contents['tokens']['fq']))
        gbytes = f.decrypt(bytes(contents['tokens']['g']))
        hbytes = bytes(contents['tokens']['h'])

        fhmac = hmac.compare_digest(bytes(contents['hmacs']['f']), hmac.new(key, fbytes).digest())
        fphmac = hmac.compare_digest(bytes(contents['hmacs']['fp']), hmac.new(key, fpbytes).digest())
        fqhmac = hmac.compare_digest(bytes(contents['hmacs']['fq']), hmac.new(key, fqbytes).digest())
        ghmac = hmac.compare_digest(bytes(contents['hmacs']['g']), hmac.new(key, gbytes).digest())
        hhmac = hmac.compare_digest(bytes(contents['hmacs']['h']), hmac.new(key, hbytes).digest())

        if not (fhmac and fphmac and fqhmac and ghmac and hhmac):
            print("key has been altered, aborting...")
        else:
            Parameters.initParameters(version)
            return KeyPair(
                Polynomial.fromOSP(fbytes, Parameters.N, Parameters.q),
                Polynomial.fromOSP(fpbytes, Parameters.N, Parameters.q),
                Polynomial.fromOSP(fqbytes, Parameters.N, Parameters.q),
                Polynomial.fromOSP(gbytes, Parameters.N, Parameters.q),
                Polynomial.fromOSP(hbytes, Parameters.N, Parameters.q),
            )

    @staticmethod
    def _loadPublic(file: str):
        with open(file, 'rb') as fp:
            import json
            contents = json.load(fp)
        version = contents['version']

        hbytes = bytearray(bytes(contents['tokens']['h']))
        Parameters.initParameters(version)
        return KeyPair(
            None,
            None,
            None,
            None,
            Polynomial.fromOSP(hbytes, Parameters.N, Parameters.q),
        )


class NTRUCryptError(Exception):
    """
    This class will be used to represent errors that have to do with
    the NTRUCrypt object specified below
    """
    pass


class NTRUCrypt:

    def __init__(self, parameterSet):
        Parameters.initParameters(parameterSet)
        # Parameters.initParameters("ees1499ep1")
        pass

    def blindingPolynomial(self, seed: bytearray):
        """
        This function will be used to generate a blinding polynomial r.
        This algorithm is specified in section 8.3.2.2 in [1]
        :param seed: octet string seed for the index generating function
        :return: blinding polynomial r
        """
        from src.NTRUCrypt.IndexGenerator import IGF

        igf = IGF(seed, False)                                  # a

        r = Polynomial(np.array([0]), Parameters.N)                       # b
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
        f = Polynomial(np.array([0]), N)
        g = Polynomial(np.array([0]), N)                                     # g
        f_invertible = False
        g_invertible = False

        # print("generating f")
        while not f_invertible:
            F = Polynomial(np.array([0]), N)                                  # a
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

            # print("F: {}".format(F))
            # print("Parameters.p: {}".format(Parameters.p))
            # print("p*F: {}".format(Polynomial([Parameters.p], 1) * F))
            f = Polynomial(np.array([1]), N) + (F * Polynomial(np.array([Parameters.p]), 1))       # e
            # print("f: {}".format(f))
            f %= Parameters.q
            # print("f: {}".format(f))
            f_inv_2 = f.inverse_pow_2(2, int(math.log2(Parameters.q)))    # f
            f_inv_3 = Polynomial(np.array([1]), N)
            f_invertible = isinstance(f_inv_2, Polynomial)            # f
            # print("f invertible: {}".format(f_invertible))

        # print("generating g")
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
            # print("g invertible: {}".format(g_invertible))
        h = f_inv_2 * g * Polynomial(np.array([Parameters.p]), 1)                  # m
        h %= Parameters.q
        kp = KeyPair(f, f_inv_3, f_inv_2, g, h)
        return kp

    conversiontableE = {
            0: [0, 0],
            1: [0, 1],
            2: [0, -1],
            3: [1, 0],
            4: [1, 1],
            5: [1, -1],
            6: [-1, 0],
            7: [-1, 1]
        }

    def encrypt(self, m: bytearray, pubkey: Polynomial):
        """
        This algorithm implements the SVES encryption operation as specified in section 9.2.2 of [1]
        :param: m: message to encrypt
        :param pubkey: public key of the recipient
        :return: ciphertext e, which is a ring element
        """
        if len(m) > Parameters.maxMsgLenBytes:                              # b
            raise Exception  # create an exception for this
        while True:
            b = bytearray()                                                     # c
            for i in range(Parameters.db // 8):                                 # c ( I think it should be Parameters.db // 8, but that results in failing the ifcondition of p)
                b.append(self._getRand_(256))                                   # c
            p0 = [0] * (Parameters.maxMsgLenBytes - 1 - len(m))                 # d
            M = bytearray()                                                     # e
            M.extend(b)                                                         # e
            M.append(len(m))                                                    # e
            M.extend(m)                                                         # e
            M.extend(p0)                                                        # e
            Mbin = "".join(["{0:08b}".format(b) for b in M])                    # f
            if len(Mbin) % 3 != 0:
                Mbin += ("0" * ((3 - len(Mbin)) % 3))                           # g
            Mtrin = []                                                          # h
            for i in range(len(Mbin) // 3):                                     # h
                Mtrin.extend(self.conversiontableE[int(Mbin[i * 3:(i + 1) * 3], 2)])   # h
            Mtrin = Polynomial(np.array(Mtrin), Parameters.N)                             # h
            bh = pubkey.toBSP(Parameters.q)                                     # i
            bhTrunc = bh[:Parameters.pkLen]                                     # i
            hTrunc = []                                                         # i
            for i in range(Parameters.pkLen // 8):                              # i
                hTrunc.append(int(bhTrunc[i*8:(i+1)*8], 2))                     # i
            sData = bytearray()                                                 # i
            sData.extend(Parameters.OID)                                        # i
            sData.extend(m)                                                     # i
            sData.extend(b)                                                     # i
            sData.extend(hTrunc)                                                # i
            r = self.blindingPolynomial(sData)                                  # j
            R = (r * pubkey) % Parameters.q                                     # k
            R4 = R % 4                                                          # l
            oR4 = R4.toOSP(q=4)                                                 # m
            mask = MGF.generateMask(oR4, Parameters.N)                          # n
            mp = Mtrin + mask                                                   # o
            mp.center0(Parameters.p)                                            # o
            no_1 = len(list(filter(lambda i: i == 1, mp)))                      # p     - number of ones in mp
            no_m1 = len(list(filter(lambda i: i == -1, mp)))                    # p     - number of minus ones in mp
            no_0 = len(list(filter(lambda i: i == 0, mp)))                      # p     - number of zeroes in mp
            if not (no_1 < Parameters.dm or                                     # p
                            no_m1 < Parameters.dm or
                            no_0 < Parameters.dm):
                break                                                           # p
            else:
                print("-1: {}\n 0: {}\n 1: {}\n".format(no_m1, no_0, no_1))
        e = (R + mp) % Parameters.q                                             # q
        return e.toOSP(Parameters.q)                                            # r

    def simple_encrypt(self, m: bytearray, pub: Polynomial):
        randBytes = 16

        mBits = ["{0:08b}".format(x) for x in i2osp(len(m)+1, 1) + m]
        mBits = "".join(mBits)
        if len(mBits) % 3 != 0:
            mBits += "0" * (3 - (len(mBits) % 3))
        Mtrin = []
        for i in range(len(mBits) // 3):
            Mtrin.extend(self.conversiontableE[int(mBits[i * 3:(i + 1) * 3], 2)])
        Mtrin = Polynomial(np.array(Mtrin))


        b = bytearray()
        for i in range(randBytes):
            b.append(self._getRand_(256))
        r = self.blindingPolynomial(b)

        e = (r*pub + Mtrin) % Parameters.q
        return e.toOSP(Parameters.q)

    def simple_decrypt(self, c: bytearray, priv: Polynomial):
        e = Polynomial.fromOSP(c, Parameters.N, Parameters.q)
        a = (priv * e) % Parameters.q
        a.center0(Parameters.q)
        a.center0(Parameters.p)

        mBin = ""  # h
        for i in range(len(a) // 2):  # h
            i *= 2
            key = (a[i], a[i + 1])  # h
            if key == (2, 2):
                print(i)
                pass  # create error class and raise an error
            mBin += "{0:03b}".format(self.conversiontableD[key])
        mBin = mBin[Parameters.db:]
        msgLen = int(mBin[:8], 2)
        msgBin = mBin[8:(8*(msgLen+1))]
        msgBytes = [int(msgBin[k*8:(k+1)*8], 2) for k in range(len(msgBin) // 8)]
        return bytearray(msgBytes)

    conversiontableD = {(y[0], y[1]): x for x, y in conversiontableE.items()}

    def decrypt(self, c: bytearray, priv: Polynomial, pub: Polynomial):
        """
        This algorithm implements the SVES decryption operation as specified in section 9.2.3 of [1]
        :param c: ciphertext, which is a polynomial of degree N - 1
        :param priv: private key, a polynomial
        :param pub: public key, a polynomial
        :return: message m as an octet string
        """
        e = Polynomial.fromOSP(c, Parameters.N, Parameters.q)
        nLen = math.ceil(Parameters.N / 8)                                      # a-1
        bLen = Parameters.db // 8                                               # a-2
        a = (priv * e) % Parameters.q                                           # b
        a.center0(Parameters.q)
        a.center0(Parameters.p)
        ci = a
        no_1 = len(list(filter(lambda i: i == 1, ci)))                          # c     - number of ones in ci
        no_2 = len(list(filter(lambda i: i == 2, ci)))                          # c     - number of minus ones (twos) in ci
        no_0 = len(list(filter(lambda i: i == 0, ci)))                          # c     - number of zeroes in ci
        if not (no_1 < Parameters.dm or                                         # c
                        no_2 < Parameters.dm or
                        no_0 < Parameters.dm):
                    raise NTRUCryptError("The number of 1s, -1s or 0s in ci is less than dm0!")
        cR = (e - ci) % Parameters.q                                            # d
        cR4 = cR % 4                                                            # e
        coR4 = cR4.toOSP(4)                                                     # s
        mask = MGF.generateMask(coR4, Parameters.N)                             # f
        cMTrin = (ci - mask) % 3                                                # g
        cMTrin.center0(3) # gokje
        cMBin = ""                                                              # h
        for i in range(len(cMTrin) // 2):                                       # h
            i *= 2
            key = (cMTrin[i], cMTrin[i+1])                                      # h
            if key == (2,2):
                raise NTRUCryptError("cMTrin contains illegal ternary encoding!")
            cMBin += "{0:03b}".format(self.conversiontableD[key])               # h
        if (len(cMBin) % 8) != 0:                                               # i
            cMBin = cMBin[:(len(cMBin) - (len(cMBin) % 8))]                     # i
        cM = bytearray()                                                        # j
        for i in range(len(cMBin) // 8):                                        # j
            cM.append(int(cMBin[i*8:(i+1)*8], 2))                               # j
        cb, cM = cM[:bLen], cM[bLen:]                                           # k-1
        cl, cM = cM[0], cM[1:]                                                  # k-2
        if cl > Parameters.maxMsgLenBytes:                                      # k-2
            raise NTRUCryptError("Length of the send message is too large to handle!")
        cm, cM = cM[:cl], cM[cl:]                                               # k-3
        if not all(x == 0 for x in cM):                                         # k-3
            raise NTRUCryptError("Message is not padded with all zeroes!")
        bh = pub.toBSP(Parameters.q)                                            # l
        bhTrunc = bh[:Parameters.pkLen]                                         # l
        hTrunc = bytearray()                                                    # l
        for i in range(Parameters.pkLen // 8):                                  # l
            hTrunc.append(int(bhTrunc[i*8:(i*8+8)], 2))                         # l
        sData = Parameters.OID + cm + cb + hTrunc                               # l
        cr = self.blindingPolynomial(sData)                                     # m
        cRp = (pub * cr) % Parameters.q                                         # n
        if not all(cR[i] == cRp[i] for i in range(len(cR))):                    # o
            raise NTRUCryptError("Received and calculated r*h do not match!")
        return cm




    def _getRand_(self, max=-1):
        """
        Generate and return a random number below max
        :param max: upper bound for random number, if max = -1 => max = 2^32
        :return: random number bounded by max
        """
        if max == -1:
            max = 2**32
        return secrets.randbelow(max)

"""
ees659ep1
ees791ep1
ees1087ep1
ees1499ep1
"""
if __name__ == "__main__":
    import sys
    sys.setrecursionlimit(10000)
    crypt = NTRUCrypt("ees659ep1")
    t0 = time.clock()
    # kp = crypt.keygen()
    kp = KeyPair.load('819218ce.key', "My great pass")
    print("f: {}, len: {}".format(kp.f, len(kp.f)))
    print("fp: {}, len: {}".format(kp.fp, len(kp.fp)))
    print("fq: {}, len: {}".format(kp.fq, len(kp.fq)))
    print("g: {}, len: {}".format(kp.g, len(kp.g)))
    print("h: {}, len: {}".format(kp.h, len(kp.h)))
    # kp.save("My great pass", "./")
    t1 = time.clock()
    print("keygen in {} seconds".format(t1-t0))

    t0 = time.clock()
    msg = bytearray("Hello World!".encode('utf-8'))
    cipher = crypt.encrypt(msg, kp.h)
    t1 = time.clock()
    print("encryption in {} seconds".format(t1-t0))

    t0 = time.clock()
    print(crypt.decrypt(cipher, kp.f, kp.h).decode('utf-8'))
    t1 = time.clock()
    print("decryption in {} seconds".format(t1-t0))
