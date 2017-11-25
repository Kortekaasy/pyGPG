import time

from src.NTRUCrypt.MaskGenerator import MGF
from src.Utils.Parameters import *
from src.Utils.Polynomial import *
import secrets


class KeyPair:

    def __init__(self, f, fp, fq, g, h):
        self.f = f
        self.fp = fp
        self.fq = fq
        self.g = g
        self.h = h

    def save(self, password: str):
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
        import base64
        import hmac

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
        htoken = f.encrypt(bytes(self.h.toOSP(Parameters.q)))

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

        with open('test1499.key', 'w') as fp:
            import json
            json.dump(toSave,fp)

    @staticmethod
    def load(file: str, password: str):
        from cryptography.hazmat.primitives.kdf.scrypt import Scrypt
        from cryptography.hazmat.backends import default_backend
        from cryptography.fernet import Fernet
        import base64
        import hmac

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
        hbytes = f.decrypt(bytes(contents['tokens']['h']))

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


class NTRUCrypt:

    def __init__(self):
        # Parameters.initParameters("ees401ep1")
        Parameters.initParameters("ees1499ep1")
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
            F = Polynomial([0] * N)                   # a
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
            f = Polynomial([1]) + (Polynomial([Parameters.p]) * F)             # e
            # f.center0(3)
            f %= Parameters.q
            f_inv_2 = f.inverse_pow_2(2, int(math.log2(Parameters.q)))    # f
            f_inv_3 = f.inverse_3()
            f_invertible = isinstance(f_inv_2, Polynomial)            # f
            f_invertible &= isinstance(f_inv_3, Polynomial)
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
            print("g invertible: {}".format(g_invertible))
        h = f_inv_2 * g * Polynomial([Parameters.p])                  # m
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

    def encrypt(self, m: str, pubkey: Polynomial):
        """
        This algorithm implements the SVES encryption operation as specified in section 9.2.2 of [1]
        :param: m: message to encrypt
        :param pubkey: public key of the recipient
        :return: ciphertext e, which is a ring element
        """
        if len(m) > Parameters.maxMsgLenBytes:                              # b
            raise Exception  # create an exception for this
        while True:
            rands = [26, -127, 14, -77, -18, -92, 69, 8, 98, 39, 124, 69, -71, 34, 2, 2, 120, 41, -69, 74, -103, 77, 69, 60, -4, -36, 114, -92, 101, -4, 3, 54]
            b = bytearray([x % 256 for x in rands])                                                     # c
            # for i in range(Parameters.db):                                      # c ( I think it should be Parameters.db // 8, but that results in failing the ifcondition of p)
            #     b.append(self._getRand_(256))                                   # c
            p0 = [0] * (Parameters.maxMsgLenBytes + 1 - len(m))                 # d
            M = bytearray()                                                     # e
            M.extend(b)                                                         # e
            M.append(len(m))                                                    # e
            M.extend(m.encode("utf-8"))                                         # e
            M.extend(p0)                                                        # e
            Mbin = "".join(["{0:08b}".format(b) for b in M])                    # f
            Mbin += ("0" * ((3 - len(Mbin)) % 3))                               # g
            # 000011101000000100011010
            Mtrin = []                                                          # h
            for i in range(len(Mbin) // 3):                                     # h
                Mtrin.extend(self.conversiontableE[int(Mbin[i * 3:(i + 1) * 3], 2)])   # h
            Mtrin = Polynomial(Mtrin)                                           # h
            bh = pubkey.toBSP(Parameters.q)                                     # i
            bhTrunc = bh[:Parameters.pkLen]                                     # i
            hTrunc = []                                                         # i
            for i in range(Parameters.pkLen // 8):                              # i
                hTrunc.append(int(bhTrunc[i*8:(i+1)*8], 2))                     # i
            sData = bytearray()                                                 # i
            sData.extend(Parameters.OID)                                        # i
            sData.extend(m.encode("utf-8"))                                     # i
            sData.extend(b)                                                     # i
            sData.extend(hTrunc)                                                # i
            r = self.blindingPolynomial(sData)                                  # j
            print("sData: {}".format([x for x in sData]))
            print("r: {}".format(r))
            R = (r * pubkey) % Parameters.q                                     # k
            R4 = R % 4                                                          # l
            oR4 = R4.toOSP(q=4)                                                 # m
            print("oR4: {}".format(oR4))
            mask = MGF.generateMask(bytearray([43, 112, 164, 235, 41, 43, 245, 174, 22, 106, 249, 2, 16, 18, 129, 14, 51, 253, 105, 120, 217, 73, 126, 222, 153, 159, 249, 243, 150, 89, 152, 118, 244, 9, 184, 39, 16, 150, 76, 211, 119, 255, 98, 202, 114, 244, 10, 248, 92, 97, 245, 35, 53, 66, 132, 108, 103, 132, 118, 175, 110, 63, 219, 28, 157, 191, 72, 152, 21, 161, 102, 6, 155, 160, 242, 9, 44, 53, 63, 187, 79, 132, 101, 1, 58, 168, 21, 225, 224, 39, 123, 167, 48, 130, 143, 25, 252, 146, 11, 135, 178, 195, 162, 247, 77, 249, 168, 235, 80, 82, 136, 3, 112, 223, 46, 247, 101, 243, 229, 155, 33, 50, 156, 130, 182, 140, 189, 40, 104, 184, 209, 21, 117, 250, 223, 3, 203, 169, 111, 190, 233, 62, 140, 123, 85, 161, 206, 92, 124, 44, 136, 236, 178, 238, 183, 119, 161, 215, 175, 222, 212, 19, 125, 91, 118, 15, 169, 255, 95, 10, 121, 138, 120, 108, 179, 69, 18, 220, 149, 7, 128, 232, 92, 6, 195, 82, 157, 86, 141, 74, 48, 104, 53, 78, 242, 235, 168, 228, 112, 232, 142, 175, 41, 153, 17, 25, 18, 68, 137, 153, 200, 29, 198, 19, 64, 59, 160, 113, 3, 129, 144, 66, 41, 53, 220, 104, 190, 55, 109, 89, 28, 37, 217, 177, 46, 225, 47, 150, 76, 41, 240, 65, 16, 124, 123, 222, 14, 184, 58, 202, 78, 195, 149, 64, 70, 160, 100, 116, 23, 218, 220, 37, 184, 217, 225, 24, 86, 10, 49, 236, 12, 111, 174, 44, 231, 111, 15, 106, 155, 223, 14, 15, 182, 82, 174, 72, 24, 197, 231, 217, 179, 168, 30, 184, 171, 173, 15, 89, 158, 7, 61, 153, 226, 72, 161, 189, 71, 94, 200, 189, 243, 246, 53, 60, 91, 69, 156, 250, 6, 13, 84, 45, 118, 80, 246, 79, 191, 26, 8, 6, 194, 4, 252, 36, 215, 54, 184, 98, 2, 135, 156, 94, 133, 178, 248, 40, 153, 140, 183, 75, 221, 83, 197, 207, 63, 254, 95, 139, 52, 82, 181, 214, 162, 18, 158, 118, 154, 56, 169, 145, 108, 25, 55, 40, 12]), Parameters.N) # n
            # mask = MGF.generateMask(bytearray(oR4.encode('utf-8')), Parameters.N) # n
            mp = Mtrin + mask                                                   # o
            no_1 = len(list(filter(lambda i: i == 1, mp)))                      # p     - number of ones in mp
            no_2 = len(list(filter(lambda i: i == 2, mp)))                      # p     - number of minus ones (twos) in mp
            no_0 = len(list(filter(lambda i: i == 0, mp)))                      # p     - number of zeroes in mp
            if not (no_1 < Parameters.dm or                                     # p
                            no_2 < Parameters.dm or
                            no_0 < Parameters.dm):
                break                                                           # p
        e = (R + mp) % Parameters.q                                             # q
        return e                                                                # r

    def simple_encrypt(self, m: bytearray, pub: Polynomial):
        randBytes = 16

        mBits = ["{0:08b}".format(x) for x in i2osp(len(m)+1, 1) + m]
        mBits = "".join(mBits)
        if len(mBits) % 3 != 0:
            mBits += "0" * (3 - (len(mBits) % 3))
        Mtrin = []
        for i in range(len(mBits) // 3):
            Mtrin.extend(self.conversiontableE[int(mBits[i * 3:(i + 1) * 3], 2)])
        Mtrin = Polynomial(Mtrin)


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
        msgLen = int(mBin[:8], 2)
        msgBin = mBin[8:(8*msgLen)]
        msgBytes = [int(msgBin[k*8:(k+1)*8], 2) for k in range(len(msgBin) // 8)]
        return bytearray(msgBytes)

    conversiontableD = {(y[0], y[1]): x for x, y in conversiontableE.items()}

    def decrypt(self, e: Polynomial, priv: Polynomial, pub: Polynomial, priv_inv: Polynomial):
        """
        This algorithm implements the SVES decryption operation as specified in section 9.2.3 of [1]
        :param e: ciphertext, which is a polynomial of degree N - 1
        :param priv: private key, a polynomial
        :param pub: public key, a polynomial
        :return: message m as an octet string
        """
        nLen = math.ceil(Parameters.N / 8)                                      # a-1
        bLen = Parameters.db // 8                                               # a-2
        print("-------1--------")
        a = (priv * e) % Parameters.q                                           # b
        a.center0(Parameters.q)
        b = a % Parameters.p                                                    # b
        # ci = priv.inverse(Parameters.p) * b                                     # b
        ci = (priv_inv * b) % Parameters.p
        ci.center0(3)
        print("-------2--------")
        no_1 = len(list(filter(lambda i: i == 1, ci)))                          # c     - number of ones in ci
        no_2 = len(list(filter(lambda i: i == 2, ci)))                          # c     - number of minus ones (twos) in ci
        no_0 = len(list(filter(lambda i: i == 0, ci)))                          # c     - number of zeroes in ci
        if not (no_1 < Parameters.dm or                                         # c
                        no_2 < Parameters.dm or
                        no_0 < Parameters.dm):
                    pass  # create error and raise it
        print("-------3--------")
        cR = (e - ci) % Parameters.q                                            # d
        cR4 = cR % 4                                                            # e
        coR4 = cR4.toOSP(4)                                                     # s
        # maskseed = [99, 75, -40, -66, 57, -76, 7, 67, 32, -38, -60, -82, 64, 60, -19, -100, 31, -85, 57, -74, 29, -107,
        #             49, -29, -109, 7, 59, -18, -65, -98, -31, 69, 74, -38, 97, 89, -109, -90, 123, -63, 105, 80, 49, 70,
        #             38, 6, 82, 83, -32, 121, 45, 110, 26, 123, 78, -93, 116, 114, -70, 99, -111, -89, 13, -99, 118, 67,
        #             -28, -78, -42, -106, 46, -69, -36, 112, 97, 2, -2, 37, 92, -37, 110, -64, -32, 5, -76, 44, -45, 32,
        #             120, -20, 32, 81, 24, -66, -16, 24, -25, -66, -123, -38, 59, -41, 72, 127, 104, 111, -17, -18, -51,
        #             12, -116, -11, -31, -6, 49, 40, -51, 113, 63, -1, 5, 4, -89, 31, -13, -64, -65, 3, 29, 118, 45, 127,
        #             -124, -77, -86, -54, -60, -5, -67, 69, -125, -34, 30, 24, 58, -126, 49, 23, -55, 126, -69, 102, -1,
        #             -28, 34, 42, 63, -13, 108, 24, 16, 27, -49, -100, -91, -87, 86, 116, -24, -67, -50, 85, 106, -104,
        #             -29, -16, -54, -37, 81, 86, 14, -127, 62, 12, -92, 48, 66, -82, -94, 112, 118, -36, -33, 42, -7, 64,
        #             70, 36, 59, -25, 113, 88, -47, -75, -5, 26, 92, 104, -27, 13, 44, -59, 64, -20, 40, -125, -115, 27,
        #             -60, -52, 60, -52, -41, 103, -36, 109, -32, -119, -10, 28, -90, 107, 66, -21, -66, -85, 123, 10, 46,
        #             10, -117, 80, 72, -42, 46, 67, 12, -34, -100, 120, -127, 72, 17, 92, 12, -32, -76, 12, -4, 58, 4,
        #             67, 105, -65, -108, 65, 91, 114, -33, -102, -115, -20, 108, -128, 44, 125, -7, 70, -57, -77, -63,
        #             -35, -119, -30, -78, -78, -48, 15, -94, -78, 2, -121, 79, 32, -67, -41, 95, -48, -86, -5, 119, 75,
        #             24, 11, -105, -54, -85, 3, -80, -11, -83, -27, 123, 82, -100, 53, -100, -104, -68, -29, -74, 1, -48,
        #             80, -90, 35, 29, -84, -121, -32, -16, 77, -127, 16, -12, -114, -2, 98, 38, 69, -100, -70, -6, 6, 24,
        #             -6, 54, 77, -108, -82, -29, 60, 67, -63, -13, 79, -93, -75, -63, 0, -67, 122, -84, 51, -67, -113, 6,
        #             57, -40, -30, -14, 86, -114, -123, 45]
        # maskseed = bytearray([b % 256 for b in maskseed])

        mask = MGF.generateMask(bytearray(coR4.encode('utf-8')), Parameters.N)                                           # f
        print("-------4--------")
        cMTrin = (ci - mask) % 3                                                # g
        cMBin = ""                                                              # h
        for i in range(len(cMTrin) // 2):                                       # h
            i *= 2
            key = (cMTrin[i], cMTrin[i+1])                                      # h
            if key == (2,2):
                print(i)
                pass  # create error class and raise an error
            toAdd = "{0:03b}".format(self.conversiontableD[key])
            print("added: {}".format(toAdd))
            cMBin += toAdd#"{0:03b}".format(self.conversiontableD[key])               # h
        if (len(cMBin) % 8) != 0:                                               # i
            cMBin = cMBin[:(len(cMBin) - (len(cMBin) % 8))]                     # i
        print("-------5--------")
        cM = bytearray()                                                        # j
        for i in range(len(cMBin) // 8):                                        # j
            bits = cMBin[i*8:(i+1)*8][::-1]
            num = int(bits, 2)
            print("{} -> {}".format(bits, num))
            cM.append(num)                                   # j
        cb, cM = cM[:bLen], cM[bLen:]                                           # k-1
        cl, cM = cM[0], cM[1:]                                                  # k-2
        if cl > Parameters.maxMsgLenBytes:                                      # k-2
            pass  # create error class and raise an error
        cm, cM = cM[:cl], cM[cl:]                                               # k-3
        if not all(x == 0 for x in cM):                                         # k-3
            pass  # create error class and raise an error
        print("-------6--------")
        bh = pub.toBSP(Parameters.q)                                            # l
        bhTrunc = bh[:Parameters.pkLen]                                         # l
        hTrunc = bytearray([x % 256 for x in hTruncBytes])                                                    # l
        # for i in range(Parameters.pkLen // 8):                                  # l
        #     hTrunc.append(int(bhTrunc[i*8:(i*8+8)][::-1], 2))                             # l
        sData = Parameters.OID + cm + cb + hTrunc                               # l
        print("-------7--------")
        cr = self.blindingPolynomial(sData)                                     # m
        cRp = (pub * cr) % Parameters.q                                         # n
        if not all(cR[i] == cRp[i] for i in range(len(cR))):                    # o
            pass  # create error class and raise an error
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


crypt = NTRUCrypt()
t0 = time.clock()
# kp = crypt.keygen()
# kp.save("My great pass")
kp = KeyPair.load('test1499.key', "My great pass")
t1 = time.clock()
# print(priv % Parameters.q)
# print(pub % Parameters.q)
print("keygen in {} seconds".format(t1-t0))

t0 = time.clock()
msg = bytearray("The quick brown fox jumps over the lazy dog".encode('utf-8'))
e = crypt.simple_encrypt(msg, kp.h)
t1 = time.clock()
# print(e)
print("encryption in {} seconds".format(t1-t0))

t0 = time.clock()
print(crypt.simple_decrypt(e, kp.f).decode('utf-8'))
t1 = time.clock()
print("decryption in {} seconds".format(t1-t0))

hTruncBytes = []
# c = Polynomial(
#     [1064, 1877, 178, 482, 2038, 1342, 275, 992, 479, 1793, 756, 706, 1206, 1020, 128, 350, 1662, 911, 492, 1673, 383,
#      977, 475, 675, 455, 1393, 1807, 511, 1839, 2024, 299, 1046, 1241, 143, 778, 935, 158, 367, 974, 1847, 1301, 1500,
#      285, 1944, 525, 1239, 390, 238, 1439, 1385, 1624, 854, 139, 788, 1638, 965, 1066, 659, 1442, 166, 599, 558, 1909,
#      715, 1351, 1074, 1522, 1867, 1811, 797, 486, 1717, 1209, 1686, 400, 1705, 426, 1108, 923, 1107, 894, 2006, 804,
#      972, 980, 1500, 1882, 1497, 673, 1692, 1375, 165, 1563, 1833, 1246, 1272, 1680, 1525, 1049, 209, 300, 750, 621,
#      307, 835, 1253, 1024, 1775, 1970, 230, 635, 636, 1394, 1862, 450, 1670, 1455, 2032, 289, 1737, 1212, 1380, 387,
#      1380, 1650, 265, 1083, 580, 95, 1737, 1996, 1793, 1025, 637, 169, 1727, 318, 557, 558, 1470, 501, 661, 2002, 833,
#      1296, 1255, 948, 937, 1798, 750, 739, 1654, 36, 1537, 1548, 176, 1188, 1925, 145, 670, 330, 865, 1078, 209, 673,
#      900, 216, 682, 1021, 1916, 487, 796, 186, 1904, 873, 238, 494, 78, 347, 537, 651, 1896, 1340, 1671, 1261, 1540,
#      930, 1108, 1314, 245, 1018, 1924, 1717, 1143, 1, 478, 1770, 1878, 1299, 1269, 392, 1966, 1802, 1723, 870, 280,
#      1566, 1253, 762, 1453, 1344, 751, 1131, 1794, 652, 865, 1529, 1080, 336, 965, 950, 1052, 1365, 1194, 452, 824, 836,
#      1193, 3, 1036, 794, 1908, 167, 1937, 1570, 575, 798, 401, 770, 1562, 528, 1387, 2005, 1922, 1003, 1066, 1145, 1438,
#      516, 1082, 1453, 212, 374, 1166, 1757, 930, 127, 308, 795, 1038, 468, 1005, 633, 997, 51, 286, 1278, 304, 1238,
#      1971, 996, 489, 425, 224, 106, 991, 1262, 958, 1862, 142, 1683, 860, 47, 687, 1696, 170, 1768, 1131, 276, 475, 62,
#      519, 1884, 1223, 74, 1921, 1232, 1225, 33, 1745, 1046, 1428, 236, 615, 997, 963, 36, 1654, 208, 621, 862, 1033,
#      517, 368, 1441, 1981, 1903, 1786, 1900, 764, 1826, 875, 1391, 74, 408, 1903, 828, 1882, 231, 1057, 1190, 1143, 681,
#      1937, 1715, 1568, 1107, 768, 443, 939, 197, 978, 1658, 1765, 1106, 1255, 312, 202, 235, 1933, 1645, 232, 1727,
#      1610, 600, 1276, 929, 1323, 1906, 900, 1965, 580, 83, 743, 1678, 1557, 13, 1514, 1817, 663, 452, 1868, 166, 546,
#      1975, 1982, 1976, 504, 122, 2046, 467, 757, 60, 1, 1559, 1817, 86, 1103, 1614, 1092, 1119, 1573, 1729, 560, 1095,
#      1657, 1973, 1291, 1645, 1143, 1876, 803, 115, 1284, 454, 85, 1861, 1779, 848, 1795, 828, 1198, 51, 1402, 430, 1122,
#      1544, 1209, 274, 1014, 1010, 143, 1714, 788, 436, 599, 306, 231, 369, 1852, 1830, 952, 348, 839, 1823, 736, 1425,
#      1584, 2031, 1435, 532, 695, 459, 1622, 1184, 521, 1867, 1686, 1057, 1941, 386, 1306, 1558, 478, 1748, 1906, 1857,
#      100, 1570, 1211, 1673, 1351, 553, 959, 1461, 43, 816, 631, 846, 860, 647, 1392, 1192, 810, 1308, 1011, 20, 1394,
#      1131, 76, 138, 605, 81, 1796, 729, 1057, 1096, 733, 326, 1678, 883, 634, 500, 1104, 448, 1529, 931, 1951, 1147,
#      1414, 1053, 221, 335, 984, 411, 1183, 803, 393, 6, 1439, 1491, 1065, 385, 239, 325, 359, 330, 1334, 1170, 1793,
#      426, 1800, 479, 369, 1555, 467, 1930, 1878, 885, 952, 1801, 95, 1803, 1548, 1715, 191, 1453, 1479, 1557, 1605,
#      1642, 1007, 1863, 1804, 728, 1160, 901, 1280, 1236, 654, 448, 196, 510, 298, 494, 1589, 404, 1150, 1189, 868, 1468,
#      701, 1624, 1765, 321, 1651, 998, 674, 1241, 912, 1874, 1011, 1263, 1126, 1013, 1297, 1397, 1575, 624, 836, 534,
#      1300, 676, 902, 749, 1741, 454, 667, 1706, 226, 621, 539, 1292, 1914, 1979, 1360, 1227, 307, 135, 1393, 1504, 1581,
#      782, 357, 1913, 750, 1703, 1186, 1558, 1607, 352, 378, 865, 926, 415, 1140, 317, 1965, 1029, 904, 1923, 261, 853,
#      364, 326, 831, 1731, 632, 1440, 1311, 438, 586, 376, 315, 295, 13, 391, 753, 1104, 280, 1571, 1963, 1600, 1920,
#      599, 1697, 974, 1288, 1843, 512, 659, 562, 1843, 1500, 269, 1399, 270, 1914, 1139, 769, 1117, 871, 1026, 1838, 665,
#      2038, 1444, 653, 1417, 413, 611, 642, 16, 235, 442, 910, 464, 1866, 266, 1798, 1785, 1610, 1972, 1238, 1360, 477,
#      1033, 1016, 358, 1331, 1150, 982, 472, 1541, 345, 821, 304, 725, 1461, 219, 1260, 201, 1792, 96, 166, 159, 7, 1696,
#      792, 2046, 597, 1548, 358, 1707, 625, 1784, 1061, 745, 832, 24, 291, 948, 961, 539, 1044, 588, 89, 633, 1670, 376,
#      1894, 393, 952, 512, 1409, 1164, 1384, 1884, 143, 1130, 56, 241, 1868, 1107, 111, 763, 981, 1361, 971, 1488, 1561,
#      1399, 2005, 1863, 1419, 263, 681, 1651, 359, 992, 342, 549, 1439, 798, 868, 1931, 84, 975, 195, 1227, 1801, 542,
#      1777, 1522, 870, 1212, 1200, 147, 870, 590, 668, 1635, 944, 1874, 1071, 2041, 77, 350, 1787, 369, 866, 724, 1918,
#      403, 1331, 1540, 1520, 694, 1631, 944, 832, 660, 1831, 122, 249, 911, 230, 1812, 794, 292, 693, 1438, 934, 10,
#      1984, 133, 726, 313, 1670, 1406, 1623, 1358, 1341, 128, 1001, 43, 1813, 454, 919, 1741, 1290, 1828, 549, 382, 1389,
#      1094, 264, 1019, 283, 547, 1999, 50, 206, 1876, 353, 1194, 812, 440, 417, 1757, 1751, 1681, 909, 847, 1021, 42,
#      1080, 1439, 1733, 1777, 1050, 361, 119, 341, 1090, 31, 1381, 1897, 546, 1458, 1320, 1569, 395, 657, 1405, 1816,
#      1864, 214, 176, 1367, 504, 435, 1352, 921, 752, 1496, 727, 1323, 1972, 1084, 354, 1898, 454, 868, 1317, 1798, 359,
#      506, 2045, 1812, 1604, 1312, 1017, 1184, 905, 1497, 1253, 99, 292, 1962, 557, 1635, 1745, 1682, 1374, 1628, 1565,
#      1320, 78, 275, 535, 30, 493, 1578, 1936, 714, 1773, 277, 59, 1417, 32, 1042, 99, 379, 1306, 1916, 1531, 786, 1602,
#      805, 1815, 1039, 634, 173, 1884, 1427, 1395, 1013, 1229, 662, 1851, 33, 1743, 1976, 1359, 1763, 569, 769, 811, 200,
#      1976, 174, 1059, 1626, 729, 775, 130, 109, 1604, 1635, 1107, 1045, 1673, 1046, 313, 1428, 1758, 704, 1895, 1969,
#      1822, 1519, 1983, 89, 951, 538, 600, 865, 1126, 40, 42, 1118, 1884, 2047, 1582, 1893, 1888, 1973, 1058, 274, 1304,
#      1315, 1153, 1893, 267, 1818, 1508, 896, 1712, 415, 1384, 711, 1209, 443, 1734, 693, 1820, 736, 964, 1084, 1016,
#      1832, 1323, 1280, 617, 1914, 883, 1282, 420, 248, 489, 643, 9, 12, 260, 208, 1774, 1593, 1092, 239, 460, 1017,
#      1868, 1161, 531, 1179, 379, 370, 241, 570, 551, 1034, 496, 1498, 296, 941, 1892, 1114, 301, 990, 1220, 471, 1063,
#      234, 1990, 1899, 1488, 1396, 481, 1501, 480, 1337, 1252, 1863, 842, 2036, 1115, 1947, 1769, 677, 1050, 460, 204,
#      2018, 908, 1652, 710, 1706, 472, 1175, 1669, 873, 1745, 1813, 1207, 23, 927, 512, 1053, 140, 512, 1540, 1124, 1945,
#      390, 887, 1762, 588, 1426, 77, 1052, 1768, 1819, 1144, 1863, 579, 2043, 869, 1134, 137, 1140, 417, 729, 1027, 834,
#      207, 1989, 2002, 274, 609, 257, 135, 962, 1904, 1690, 1795, 1011, 1669, 1347, 1833, 1481, 1315, 16, 1329, 751,
#      2025, 1494, 1723, 1016, 464, 1093, 125, 551, 1841, 1615, 1681, 67, 1828, 1692, 342, 993, 1431, 1364, 688, 1558,
#      1718, 541, 102, 271, 43, 973, 1300, 223, 640, 94, 1831, 1782, 795, 1450, 278, 1351, 1349, 198, 1430, 1576, 1192,
#      2012, 1154, 340, 1317, 1258, 1138, 310, 1977, 65, 155, 1064, 1710, 738, 1675, 1939, 666, 1823, 288, 1232, 1919,
#      899, 773, 341, 1755, 408, 1171, 1344, 673, 527, 316, 1659, 1353, 1009, 878, 1834, 514, 2020, 1134, 248, 93, 602,
#      1411, 567, 1497, 352, 84, 1767, 47, 862, 657, 993, 1566, 1858, 454, 1933, 1790, 1681, 331, 152, 544, 1202, 1995,
#      396, 195, 1462, 1036, 258, 1355, 1096, 1642, 523, 250, 1304, 1049, 1274, 1694, 1048, 1135, 1447, 1735, 601, 1447,
#      211, 1329, 233, 1134, 1007, 1116, 1794, 439, 764, 1611, 1533, 112, 441, 1977, 1799, 1509, 913, 1215, 977, 1791,
#      284, 1101, 848, 794, 1604, 1807, 108, 1486, 1451, 1072, 558, 1833, 1580, 979, 661, 1520, 1892, 658, 560, 1577, 507,
#      1056, 1026, 1543, 318, 2026, 673, 1226, 727, 216, 434, 128, 747, 1895, 56, 255, 1853, 1252, 85, 1745, 97, 1753,
#      1363, 995, 1459, 1699, 348, 1747, 793, 989, 83, 567, 210, 322, 129, 973, 1451, 1022, 323, 692, 99, 1064, 2019,
#      1221, 1734, 1109, 219, 1871, 566, 38, 1219, 1409, 1481, 615, 1273, 1078, 1570, 1363, 748, 427, 1035, 699, 207,
#      1900, 1669, 1473, 907, 977, 1327, 1518, 1688, 1899, 1239, 317, 116, 95, 750, 904, 1586, 885, 1269, 559, 829, 1106,
#      581, 1516, 593, 867, 597, 570, 1653, 431, 702, 2033, 1466, 954, 721, 791, 1670, 728, 1759, 13, 1021, 1257, 965,
#      357, 2047, 522, 1206, 1803, 648, 102, 19, 726, 807, 1886, 187, 1759, 1891, 411, 732, 1741, 611, 1867, 1973, 1593,
#      2043, 992, 1395, 1301, 611, 1419, 1069, 1476, 1015, 2017, 1589, 1342, 1243, 412, 545, 2042, 103, 1566, 1604, 1403,
#      834, 912, 573, 1250, 987, 1777, 1572, 380, 213, 1965, 403, 1658, 1571, 751, 930, 567, 1068, 151, 100, 803, 1045,
#      1254, 409, 135, 1610, 1291, 1965, 1467, 543, 167, 1630, 312, 1773, 1408, 915, 1046, 1601, 810, 850, 1564, 1999,
#      957, 36, 1944, 917])
# pub = Polynomial(
#     [411, 1958, 980, 506, 1273, 17, 947, 605, 1208, 511, 18, 1924, 1067, 1365, 170, 773, 839, 544, 1055, 1754, 711,
#      1761, 899, 580, 1018, 598, 1756, 478, 1878, 1044, 481, 1300, 957, 1258, 834, 382, 2020, 894, 388, 956, 1052, 1469,
#      1314, 668, 384, 985, 43, 987, 1411, 1551, 1683, 1463, 1832, 957, 751, 1389, 1740, 1853, 1968, 1826, 489, 988, 2016,
#      1537, 1310, 1878, 716, 1841, 805, 1929, 347, 1307, 1859, 1839, 1274, 1655, 1254, 323, 301, 1395, 2038, 2043, 705,
#      1329, 915, 1758, 752, 1359, 24, 220, 787, 1479, 1570, 305, 121, 582, 1303, 35, 1949, 1953, 1367, 1891, 975, 153,
#      1930, 1326, 1513, 1694, 1629, 2005, 1319, 40, 1447, 787, 1352, 1780, 111, 183, 700, 764, 1959, 1735, 903, 102, 10,
#      445, 745, 1995, 294, 1273, 1463, 1387, 1095, 1504, 463, 323, 1013, 1535, 471, 79, 1590, 1744, 776, 741, 635, 730,
#      1713, 870, 48, 1058, 58, 708, 1874, 1508, 804, 1099, 693, 400, 704, 705, 29, 1163, 768, 1325, 323, 1761, 64, 1315,
#      865, 1211, 1978, 994, 62, 409, 1428, 1770, 1138, 444, 409, 93, 1989, 360, 1994, 1106, 441, 1932, 631, 914, 701,
#      398, 1725, 601, 1256, 642, 764, 1028, 652, 1053, 1345, 115, 115, 707, 1002, 748, 1549, 1097, 939, 1640, 323, 27,
#      15, 1734, 1574, 590, 169, 1676, 959, 296, 815, 558, 1039, 1, 1762, 1155, 139, 1713, 1164, 1860, 169, 152, 1080,
#      199, 1864, 1862, 1660, 380, 1412, 1731, 1941, 187, 307, 231, 704, 586, 725, 1750, 1765, 825, 1696, 128, 528, 588,
#      98, 1364, 721, 557, 164, 1874, 332, 1074, 114, 1726, 1830, 1645, 1220, 1197, 275, 1599, 1659, 697, 1639, 436, 923,
#      1669, 1774, 916, 1247, 850, 1018, 143, 161, 1345, 398, 1468, 504, 792, 1559, 1381, 1150, 1156, 944, 66, 180, 1349,
#      1535, 1977, 809, 2029, 540, 32, 606, 182, 646, 1103, 1956, 2011, 1065, 45, 868, 1182, 1216, 1145, 1809, 957, 1557,
#      952, 1173, 2019, 1194, 790, 1677, 228, 1009, 1609, 722, 1377, 174, 1370, 1333, 667, 815, 447, 825, 711, 1046, 922,
#      1764, 326, 1858, 563, 1937, 1145, 925, 910, 1881, 1556, 1842, 1497, 888, 484, 1176, 1971, 1861, 1531, 1234, 1170,
#      956, 1027, 245, 416, 676, 1761, 606, 1331, 324, 535, 1227, 1912, 1377, 762, 474, 1480, 151, 76, 1169, 834, 1435,
#      1536, 660, 1595, 409, 470, 746, 724, 562, 1121, 1552, 582, 1322, 1000, 1946, 762, 261, 587, 1190, 674, 1043, 284,
#      38, 1691, 4, 731, 354, 2028, 78, 1034, 1394, 1368, 372, 148, 335, 565, 389, 1732, 1675, 1836, 854, 352, 530, 781,
#      1643, 153, 1910, 1602, 96, 1073, 1468, 146, 803, 1986, 1768, 1660, 1508, 1058, 25, 1072, 373, 1661, 2039, 140,
#      1851, 614, 1275, 643, 1987, 1929, 136, 492, 956, 467, 673, 1179, 1739, 1113, 962, 980, 943, 1757, 1603, 445, 603,
#      798, 312, 183, 1485, 353, 481, 751, 525, 508, 1813, 162, 1216, 316, 802, 623, 2044, 1181, 1074, 836, 1043, 1455,
#      155, 1990, 643, 954, 936, 1471, 20, 1910, 927, 1559, 1533, 1074, 1458, 779, 610, 739, 1389, 121, 1100, 896, 1922,
#      206, 1221, 1045, 1391, 206, 444, 657, 529, 1272, 634, 1634, 1379, 462, 971, 760, 737, 306, 933, 1793, 322, 706,
#      1676, 1385, 704, 316, 1055, 255, 912, 1476, 1931, 77, 33, 1176, 1650, 1360, 1008, 1292, 251, 1583, 1938, 63, 1142,
#      463, 1574, 1640, 779, 667, 1199, 34, 965, 1869, 1986, 954, 108, 1721, 43, 652, 234, 519, 553, 129, 254, 1133, 1281,
#      1134, 1764, 317, 5, 1141, 869, 1460, 1798, 949, 638, 28, 2021, 919, 539, 2030, 1158, 1260, 1738, 672, 558, 1374,
#      1718, 982, 1328, 509, 817, 1292, 193, 2022, 55, 443, 879, 1704, 1755, 219, 1153, 1384, 1032, 377, 1946, 594, 168,
#      616, 229, 4, 1240, 1177, 400, 1576, 1883, 1221, 1980, 1224, 290, 1, 1555, 742, 1544, 34, 1778, 1619, 967, 1029,
#      427, 918, 1251, 1057, 1038, 945, 1552, 1382, 1115, 2008, 1491, 169, 1464, 0, 1691, 279, 1367, 1508, 2037, 1719,
#      898, 96, 1964, 585, 475, 1803, 1341, 1989, 985, 1582, 945, 300, 1626, 160, 452, 613, 941, 1411, 854, 802, 1260,
#      1428, 1610, 1515, 753, 1655, 1000, 1185, 1458, 7, 1500, 322, 167, 1830, 1006, 160, 1897, 1963, 670, 466, 582, 1889,
#      255, 2030, 435, 1393, 692, 554, 1895, 2031, 940, 1275, 725, 1017, 434, 1719, 1401, 58, 350, 1460, 1041, 1560, 1334,
#      1010, 1632, 1434, 1146, 245, 1165, 122, 1467, 1109, 2044, 1403, 1951, 890, 1048, 448, 153, 1640, 202, 1402, 706,
#      622, 2047, 370, 1876, 860, 860, 1827, 1640, 369, 590, 202, 1834, 1284, 1066, 1397, 392, 347, 75, 300, 1078, 1910,
#      160, 971, 79, 707, 1714, 1213, 394, 1888, 1716, 180, 1661, 547, 1342, 416, 835, 981, 1105, 787, 1936, 424, 369,
#      1234, 200, 1732, 1259, 1337, 980, 165, 1330, 1244, 702, 39, 1230, 1631, 550, 153, 840, 693, 166, 642, 1672, 1936,
#      1763, 1507, 1606, 205, 1646, 1943, 364, 364, 453, 1475, 785, 1094, 781, 1179, 257, 1575, 724, 400, 767, 621, 1843,
#      341, 1819, 904, 1918, 380, 1268, 1795, 1444, 501, 599, 1819, 1531, 1784, 481, 101, 623, 56, 156, 1006, 260, 1230,
#      1366, 1304, 739, 631, 1022, 37, 716, 744, 1055, 942, 1154, 1326, 1062, 763, 421, 1763, 1124, 915, 1779, 1098, 1946,
#      1702, 2010, 672, 1245, 1397, 126, 645, 872, 945, 1553, 1952, 988, 1135, 275, 1757, 1544, 1934, 1140, 1421, 971,
#      618, 1911, 1856, 2036, 1516, 479, 977, 1935, 98, 661, 1396, 1224, 1788, 1257, 1055, 224, 848, 246, 1529, 964, 1857,
#      1387, 1440, 549, 751, 1945, 751, 1644, 1549, 1612, 274, 761, 711, 734, 1202, 811, 2043, 622, 889, 1244, 2031, 257,
#      209, 1094, 871, 1323, 102, 223, 1464, 86, 107, 953, 1621, 1274, 1798, 737, 184, 1217, 847, 158, 994, 917, 1384,
#      1679, 1909, 115, 707, 648, 1397, 1449, 1537, 862, 301, 1364, 410, 742, 1867, 1386, 851, 586, 94, 1211, 1882, 721,
#      1505, 1404, 427, 459, 1534, 1286, 625, 1748, 1805, 1357, 604, 1099, 1825, 713, 955, 193, 1887, 501, 88, 1833, 1949,
#      82, 30, 1651, 662, 83, 580, 1615, 812, 1906, 913, 970, 1351, 728, 1173, 1062, 361, 856, 854, 1023, 1699, 1664,
#      1199, 273, 1191, 677, 1431, 440, 951, 738, 233, 385, 1062, 202, 43, 1059, 389, 1351, 65, 1003, 1630, 302, 1026,
#      1485, 1665, 1138, 145, 1469, 1495, 848, 1505, 2010, 1, 419, 2008, 170, 340, 1719, 766, 1610, 1748, 1448, 1844, 239,
#      320, 680, 616, 294, 1566, 1640, 316, 770, 1148, 299, 1285, 1492, 473, 1151, 1887, 21, 512, 1165, 1932, 1892, 1774,
#      1654, 781, 707, 1448, 305, 822, 1226, 1334, 1133, 234, 759, 1206, 925, 322, 285, 1348, 1965, 919, 1998, 641, 534,
#      846, 1988, 915, 1739, 323, 1846, 1945, 1377, 711, 1156, 1074, 1887, 502, 1702, 1641, 1662, 867, 1698, 2026, 594,
#      983, 1739, 207, 1301, 1506, 345, 907, 678, 454, 1894, 75, 693, 1375, 1155, 1275, 825, 1841, 1737, 1317, 1335, 450,
#      306, 771, 219, 173, 545, 1967, 1162, 715, 1658, 349, 2001, 337, 1475, 1263, 865, 557, 1314, 91, 2011, 830, 1926,
#      1402, 632, 1131, 1466, 1701, 114, 1255, 324, 295, 491, 1712, 1234, 843, 236, 221, 1568, 536, 1408, 1213, 69, 1566,
#      788, 83, 1561, 1618, 1645, 281, 581, 900, 705, 994, 1404, 107, 1213, 2022, 69, 583, 597, 768, 817, 1499, 1821,
#      1010, 2043, 1832, 267, 648, 1823, 131, 99, 383, 72, 1156, 1569, 1493, 643, 1442, 501, 1197, 510, 1768, 564, 466,
#      1984, 1833, 542, 1152, 1517, 1262, 333, 876, 130, 2006, 559, 1196, 1604, 991, 1816, 999, 1858, 668, 1407, 1671,
#      232, 349, 976, 1465, 43, 1540, 597, 371, 425, 179, 1691, 1018, 310, 1685, 1875, 1671, 132, 647, 134, 1674, 1861,
#      1196, 146, 802, 1273, 900, 1795, 1715, 775, 1529, 917, 840, 1556, 124, 1181, 1145, 1051, 1880, 1608, 168, 948, 996,
#      852, 1541, 1493, 1724, 1051, 1054, 516, 1102, 1119, 1544, 680, 911, 686, 1921, 385, 1440, 1095, 733, 1954, 1621,
#      1534, 514, 342, 311, 1808, 1303, 1381, 384, 356, 1530, 1859, 990, 1028, 1627, 265, 1532, 1998, 1274, 1425, 869,
#      380, 505, 384, 1728, 297, 1219, 1556, 1661, 1227, 350, 1287, 1688, 1283, 1657, 590, 1190, 1020, 1577, 662, 612,
#      495, 1129, 488, 761, 1790, 1942, 1917, 280, 1124, 1675, 1034, 768, 816, 1407, 620, 768, 492, 195, 431, 484, 762,
#      122, 1954, 1535, 1686, 1159, 441, 1170, 450, 384, 1375, 133, 631, 1074, 1206, 1117, 412, 1438, 460, 1271, 1509,
#      226, 589, 1803, 995, 346, 1321, 588, 136, 1605, 1710, 76, 1970, 111, 1354, 560, 1516, 1038, 238, 1239, 1971, 613,
#      1137, 810, 856, 1468, 1325, 504, 780, 1393, 57, 1762, 379, 631, 1547, 540, 252, 362, 1198, 693, 847, 1380, 825,
#      573, 1864, 1397, 330, 333, 955, 1395, 453, 791, 1300, 1022, 1190, 1271, 1269, 1404, 261, 1597, 1342, 1563, 807,
#      1682, 689, 33, 1348, 1640, 792, 844, 1658, 2017, 1648, 606, 1100, 1980, 563, 1906, 560, 1704, 39, 1474, 128, 1840,
#      635, 233, 131, 1943, 1058, 1191, 1232, 1173, 961, 84, 586, 298, 742, 400, 1904, 1608, 1796, 633, 348, 979, 112,
#      1567, 1093, 1905, 1610, 1520, 1664, 1891, 1175, 1046, 1704, 121, 1707, 1229, 682, 823, 1795, 881, 727])
# priv = Polynomial(
#     [0, 1, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, -1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0,
#      1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1,
#      0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, -1, 0,
#      0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0,
#      1, 0, 0, 0, 1, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1,
#      0, 0, 0, -1, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0,
#      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, -1,
#      0, 0, 0, 0, 1, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      -1, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 1,
#      0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 1, 0, 0,
#      1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, -1, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 1, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, -1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 0, -1, 1, 0, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 1, 0, 0, -1, -1, 0, 0, 0, 0, 0, 0, 0, 0,
#      0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, -1, -1, 0, 0, 0, 0, -1, 0, 0, 0, 1, 0,
#      0, 0, 0, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, -1, 0,
#      -1, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, -1, 1, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, -1, -1, 0, 0,
#      0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 0, 0, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 1, 1, 0, 0, 0,
#      0, 0, -1, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, -1, 0, 0, 0, -1, 0, 0, 0, 0, 0])
# priv_inv = Polynomial(
#     [1, 1, 0, 2, 0, 2, 1, 0, 0, 2, 0, 2, 2, 1, 1, 1, 2, 0, 1, 2, 0, 1, 1, 1, 2, 1, 0, 0, 1, 1, 2, 2, 0, 2, 0, 1, 0, 2,
#      0, 0, 0, 2, 1, 2, 0, 1, 0, 0, 1, 0, 0, 2, 2, 0, 2, 0, 0, 2, 2, 0, 2, 0, 1, 0, 0, 1, 0, 0, 0, 2, 1, 0, 2, 1, 1, 0,
#      0, 1, 0, 2, 1, 0, 1, 2, 0, 2, 2, 1, 0, 0, 2, 1, 0, 2, 0, 2, 0, 0, 2, 0, 0, 1, 0, 1, 1, 2, 2, 0, 2, 0, 2, 2, 2, 1,
#      2, 1, 1, 2, 1, 2, 0, 0, 2, 0, 1, 1, 0, 2, 0, 2, 2, 0, 0, 0, 1, 1, 0, 1, 1, 2, 0, 1, 2, 0, 1, 1, 2, 2, 0, 2, 2, 2,
#      0, 0, 2, 2, 2, 0, 2, 2, 0, 2, 2, 1, 2, 1, 0, 1, 1, 1, 0, 1, 2, 2, 0, 1, 1, 0, 0, 2, 2, 2, 0, 1, 2, 0, 0, 0, 2, 2,
#      0, 2, 2, 0, 1, 0, 0, 0, 2, 0, 1, 1, 2, 0, 0, 0, 1, 2, 0, 1, 2, 0, 0, 0, 0, 2, 2, 0, 0, 0, 2, 0, 0, 0, 0, 2, 0, 2,
#      1, 1, 0, 1, 1, 0, 0, 1, 1, 1, 0, 1, 0, 0, 1, 2, 1, 2, 1, 0, 2, 1, 0, 2, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1, 2, 2, 1, 2,
#      2, 0, 1, 1, 1, 2, 2, 0, 2, 2, 0, 0, 0, 2, 0, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 2, 2, 1, 2, 0, 2, 1, 1, 2, 0, 2, 2, 1,
#      2, 1, 2, 2, 2, 1, 1, 0, 0, 0, 1, 1, 1, 0, 1, 2, 2, 1, 0, 2, 1, 0, 1, 0, 2, 0, 2, 1, 2, 1, 2, 2, 0, 0, 0, 1, 2, 2,
#      2, 0, 0, 1, 0, 0, 0, 2, 2, 1, 2, 1, 2, 1, 2, 2, 2, 1, 0, 1, 1, 1, 1, 2, 1, 0, 2, 2, 1, 0, 2, 1, 0, 0, 1, 0, 0, 2,
#      1, 2, 0, 0, 1, 0, 0, 0, 1, 2, 1, 2, 2, 1, 1, 2, 2, 2, 2, 2, 0, 1, 2, 2, 0, 0, 0, 1, 2, 2, 2, 2, 1, 1, 2, 0, 0, 0,
#      0, 0, 2, 1, 1, 0, 0, 1, 1, 0, 2, 1, 0, 2, 0, 0, 2, 0, 2, 0, 0, 0, 1, 1, 1, 1, 0, 0, 2, 0, 0, 1, 0, 1, 1, 0, 1, 0,
#      1, 0, 1, 1, 0, 0, 0, 1, 2, 1, 1, 0, 1, 2, 1, 0, 1, 1, 0, 1, 2, 1, 0, 0, 1, 2, 0, 1, 2, 0, 0, 1, 2, 0, 0, 0, 1, 0,
#      0, 1, 1, 1, 1, 0, 2, 2, 0, 2, 1, 0, 0, 2, 2, 2, 2, 2, 2, 1, 2, 1, 0, 0, 2, 2, 0, 2, 1, 1, 0, 2, 2, 1, 0, 2, 2, 2,
#      1, 1, 1, 1, 0, 0, 0, 2, 2, 0, 1, 0, 0, 2, 1, 2, 2, 0, 2, 0, 1, 2, 2, 2, 1, 0, 1, 2, 1, 0, 2, 1, 0, 1, 0, 2, 1, 1,
#      0, 2, 2, 1, 1, 0, 1, 2, 2, 1, 0, 0, 1, 1, 1, 2, 0, 2, 0, 2, 1, 0, 1, 1, 0, 2, 1, 0, 2, 1, 1, 0, 0, 0, 1, 2, 0, 0,
#      0, 2, 0, 0, 0, 0, 2, 2, 2, 1, 2, 2, 1, 1, 0, 0, 2, 0, 2, 2, 2, 2, 2, 0, 0, 0, 0, 2, 0, 2, 1, 2, 1, 0, 2, 1, 0, 2,
#      1, 1, 0, 0, 1, 1, 2, 0, 1, 2, 1, 1, 1, 1, 0, 1, 1, 1, 2, 1, 2, 2, 1, 2, 1, 0, 2, 1, 0, 0, 1, 0, 0, 0, 1, 0, 2, 2,
#      1, 2, 1, 1, 1, 1, 2, 2, 0, 1, 2, 1, 1, 1, 2, 1, 2, 0, 0, 2, 1, 2, 0, 0, 1, 1, 1, 1, 0, 2, 2, 0, 2, 2, 1, 1, 1, 0,
#      1, 0, 2, 1, 0, 2, 0, 1, 2, 0, 1, 0, 0, 1, 2, 2, 0, 1, 0, 1, 2, 2, 0, 0, 0, 0, 2, 1, 0, 0, 1, 2, 1, 2, 1, 0, 2, 1,
#      1, 2, 2, 2, 0, 1, 0, 2, 0, 0, 2, 0, 1, 0, 1, 2, 1, 2, 2, 2, 2, 0, 0, 2, 2, 2, 0, 0, 0, 2, 0, 1, 0, 0, 2, 2, 2, 0,
#      0, 2, 1, 1, 2, 1, 2, 0, 2, 0, 2, 1, 2, 0, 2, 2, 0, 1, 1, 0, 1, 1, 1, 2, 1, 2, 2, 2, 1, 0, 1, 0, 1, 0, 0, 1, 0, 1,
#      2, 1, 2, 0, 2, 0, 0, 1, 2, 0, 0, 0, 0, 2, 0, 1, 0, 1, 0, 2, 2, 2, 1, 1, 1, 1, 2, 0, 1, 1, 2, 0, 1, 1, 2, 1, 0, 2,
#      0, 0, 0, 2, 0, 0, 1, 1, 0, 2, 0, 0, 1, 1, 1, 0, 1, 2, 2, 0, 2, 2, 1, 0, 2, 1, 1, 0, 1, 1, 2, 1, 1, 2, 1, 0, 2, 2,
#      0, 1, 2, 2, 0, 0, 0, 2, 0, 0, 1, 2, 0, 2, 1, 1, 0, 1, 0, 1, 0, 0, 2, 2, 2, 2, 1, 1, 1, 0, 1, 1, 2, 0, 2, 2, 1, 2,
#      0, 0, 1, 2, 0, 2, 1, 2, 0, 2, 0, 1, 2, 1, 2, 0, 1, 1, 0, 1, 1, 0, 1, 2, 0, 0, 2, 0, 0, 2, 2, 2, 1, 0, 1, 2, 1, 2,
#      2, 0, 2, 0, 0, 2, 0, 2, 0, 1, 0, 2, 1, 1, 1, 2, 2, 2, 0, 1, 1, 0, 0, 1, 0, 2, 2, 2, 2, 0, 1, 2, 0, 2, 0, 0, 0, 0,
#      0, 0, 2, 0, 0, 0, 1, 1, 1, 0, 0, 1, 2, 0, 1, 1, 0, 1, 0, 2, 1, 2, 1, 2, 1, 1, 0, 0, 1, 0, 1, 0, 2, 0, 0, 2, 2, 0,
#      2, 1, 0, 1, 2, 2, 2, 2, 1, 1, 0, 0, 2, 2, 0, 0, 1, 0, 1, 2, 0, 0, 1, 2, 2, 0, 2, 0, 1, 0, 0, 2, 0, 1, 1, 1, 0, 2,
#      0, 2, 0, 2, 0, 0, 1, 1, 2, 1, 1, 0, 2, 2, 0, 0, 1, 2, 2, 0, 0, 0, 0, 0, 1, 1, 0, 0, 2, 1, 1, 0, 1, 0, 1, 1, 1, 0,
#      0, 2, 2, 1, 2, 1, 0, 2, 1, 0, 0, 1, 0, 0, 2, 1, 2, 1, 0, 2, 1, 0, 1, 2, 2, 0, 1, 0, 2, 1, 1, 1, 2, 2, 0, 0, 1, 0,
#      0, 2, 2, 0, 1, 2, 2, 1, 1, 1, 2, 2, 2, 2, 0, 2, 2, 1, 2, 2, 1, 1, 1, 2, 1, 0, 1, 2, 1, 2, 1, 0, 1, 2, 0, 0, 1, 0,
#      1, 1, 0, 2, 2, 0, 0, 1, 2, 0, 1, 1, 1, 2, 2, 2, 1, 1, 1, 0, 1, 2, 2, 1, 0, 2, 0, 2, 0, 0, 1, 0, 0, 1, 2, 1, 0, 1,
#      0, 0, 0, 1, 2, 1, 1, 1, 2, 0, 1, 2, 0, 2, 1, 0, 1, 0, 2, 1, 2, 1, 2, 0, 0, 0, 1, 0, 1, 1, 1, 2, 1, 2, 1, 0, 0, 2,
#      1, 0, 0, 1, 2, 0, 2, 2, 2, 0, 2, 2, 1, 1, 1, 2, 1, 2, 2, 1, 0, 1, 0, 1, 0, 1, 2, 1, 2, 1, 0, 0, 2, 2, 1, 0, 1, 1,
#      0, 2, 1, 0, 1, 0, 1, 0, 2, 1, 2, 2, 2, 0, 0, 1, 1, 1, 2, 2, 1, 1, 1, 1, 1, 0, 2, 1, 2, 2, 1, 1, 0, 2, 1, 2, 0, 1,
#      1, 1, 1, 2, 0, 2, 2, 1, 2, 2, 2, 2, 1, 0, 2, 2, 2, 0, 1, 0, 2, 0, 1, 0, 0, 1, 0, 2, 0, 2, 0, 0, 2, 2, 1, 1, 2, 2,
#      2, 1, 2, 0, 0, 0, 1, 2, 1, 1, 2, 1, 1, 1, 2, 2, 2, 0, 2, 1, 1, 2, 1, 2, 0, 2, 0, 0, 1, 0, 2, 1, 1, 2, 1, 0, 0, 0,
#      1, 1, 2, 1, 2, 1, 2, 2, 0, 2, 2, 0, 1, 1, 2, 0, 1, 2, 2, 2, 0, 0, 0, 1, 1, 1, 1, 2, 0, 2, 0, 2, 0, 2, 2, 2, 1, 1,
#      2, 0, 2, 2, 2, 1, 1, 2, 0, 0, 1, 0, 0, 0, 2, 0, 1])
# msg = [40, -84, -70, 44, -60, 99, 127, -97, 78, 4, 124, -33, 9, 56, -67, -124, 101, 75, -2, 1, -62, 43, 126, 126, 28,
#        123, 18, -3, -105, -24, 109, 103, 84, -57, -119, -21, -61, -1, -13, 114, -12, -81, -60, -126, -39, 124, -124,
#        -62, 78, -25, -119, -73, 56, -17, -26, 21, -27, 110, 71, 48, -33, -96, 107, 26, -58, 29, -97, 77, 43, -106, -83,
#        -74, 8, -118, -103, -71, 120, 42, -100, -108, 104, 77, 113, 37, 23, -43, 125, 89, 71, -107, -95, 124, -105, 62,
#        -15, -114, -103, -89, -42, -71, -76, 52, 100, 82, -83, 26, 42, 110, 110, -118, 126, -77, 62, -55, -104, 71, 61,
#        -18, 106, 61, -69, -95, -30, -12, 87, 75, -79, -31, -108, 123, 19, -97, -112, -82, 111, 6, -93, -63, 18, 119,
#        -75, 105, 38, 67, 43, 39, 0, -33, 45, 123, 115, -20, -119, 79, 114, 53, -70, 112, 12, -3, 90, -8, -121, 36, -39,
#        -68, 36, -21, 96, -56, 42, -25, -124, -20, -112, 72, 95, 72, 54, -13, 3, 30, -64, 62, -91, -30, -41, 62, 105,
#        -111, -117, 124, 91, -97, 74, 73, 63, 104, 16, 61, 39, -19, 82, 103, 112, 119, -115, -53, -50, 36, 8, 48, -125,
#        97, 65, -54, -62, 71, -62, 83, 74, 9, -101, 13, -93, 17, 42, -62, 97, 67, 85, -3, -29, -5, 121, 56, -90, 11, -72,
#        -89, -51, 29, -18, 113, -62, 86, 50, -76, 40, -76, -13, -12, -48, -19, 36, -80, -24, -88, 40, -46, 122, -24,
#        -113, -16, -75, -66, 99, 0, -68, -93, 110, -85, 79, -76, -98, -120, 113, -67, -62, 119, 109, 54, -116, 120, -72,
#        -100, -6, 106, 45, 80, -33, -75, 70, -127, 51, 42, 108, -7, -59, 33, 84, -118, 103, 59, 14, 86, 85, -107, -60,
#        -63, 25, -47, 82, 57, 0, 6, 106, -116, -18, -89, -120, -68, -120, 127, -28, -79, -56, 8, 76, -61, 16, 90, 107,
#        -11, 5, -65, 62, 21, -26, -47, -77, 4, -46, 97, 107, -87, 97, 23, 71, 118, 91, 116, 127, -96, -55, -58, 28, 72,
#        -99, -10, -27, -87, 124, 51, -16, -120, 63, 97, 98, -51, -39, -109, 47, 61, -87, 1, -121, 26, -66, -25, 78, -33,
#        25, -35, 17, -109, -26, -38, 11, 94, 5, 106, 85, -96, 123, -115, 20, -39, -114, 15, 14, -60, -11, 99, 42, 33,
#        -16, -48, 76, 102, 8, -94, 109, 65, -54, -78, -29, 76, -27, 27, 30, 9, -20, 12, -115, 54, 121, 45, -127, 5, -126,
#        75, 104, 123, -1, 118, 125, -77, -99, 95, 34, 95, -37, 91, -107, -128, -103, -73, -13, 76, -21, -25, 8, -95, 41,
#        -17, -104, -86, -56, -49, 26, -60, 83, 4, -40, 110, 86, 87, 12, -23, -23, -71, -36, 82, 60, 39, 78, -108, -79,
#        -114, -58, -73, 25, 29, -65, 86, 50, -106, -8, 25, -70, -107, -54, -99, 112, -83, 39, -46, 20, -50, -27, -24, 10,
#        55, 64, -67, 25, -65, 20, 113, -104, 110, 10, 17, -35, -34, -9, -72, -57, -113, 30, -4, 63, -99, 122, -15, 32, 0,
#        23, -50, -72, 21, -98, -24, 100, 34, 126, -79, -60, -63, -122, -47, 17, -13, 92, -5, -123, -74, -7, -114, 84, 31,
#        -39, 28, 8, 106, -100, 42, 20, 125, -34, 80, 27, 56, -49, 92, 57, 3, -67, -70, 70, -116, 8, -50, -91, 68, -20,
#        39, -65, 71, -56, -102, 98, -76, -71, -110, 76, -50, 17, 23, -98, -101, 28, 119, 92, 57, -38, -57, -63, 21, 89,
#        24, -65, 127, -77, 20, -70, -43, 114, -84, 12, -54, 4, 45, -35, -46, 33, -84, -68, 96, 52, 106, 97, -17, 80, 91,
#        -18, 65, 39, -125, -120, 119, -103, -24, -93, -90, -24, 119, -75, 93, 1, -52, -18, -28, 52, -82, 29, 10, -82,
#        -88, 84, 25, 71, -25, 71, 1, -71, -82, -111, 9, -118, -24, 82, 20, 8, -98, -83, 16, 34, -79, 91, 70, 113, -12,
#        -36, -12, 68, 31, 40, 2, 39, -65, -93, -5, -4, 30, 13, -37, -63, 110, 60, 5, 123, -101, -7, -28, -56, 18, 99,
#        -128, -49, 78, 55, -123, -127, 121, 71, 81, -50, -94, 20, -101, 74, 50, -32, -86, 65, -8, 119, -30, 50, -31, -23,
#        40, -34, -22, 117, -61, 93, -62, -65, -80, 112, 6, -49, -6, 23, -83, 61, 110, -123, -117, -84, -26, -9, 29, -99,
#        -31, -40, 66, 100, -31, 0, 74, 77, 71, 1, -121, 24, -2, 81, -119, 123, 106, 76, 25, 63, -106, -110, 108, -68,
#        -19, 21, -106, -53, 29, -108, 57, -101, 79, 84, -39, -124, -100, -44, -25, -9, 78, 51, -42, 47, -94, 117, 61, 49,
#        -100, -120, 102, 33, -118, -110, -54, 112, -19, 106, -74, 113, 54, -91, 106, 113, -76, 105, 67, 12, -43, -5, -18,
#        -95, -70, -52, -103, 28, 34, -82, -32, 109, -79, -61, -54, -110, 119, 119, -99, 90, -108, 22, 62, 50, 88, -12,
#        18, 54, -49, 125, -122, -114, 61, 105, 125, 1, 17, 55, -8, -126, 84, -115, 45, 70, -7, -39, -80, -15, 4, -38,
#        -113, -38, 70, 73, 120, -39, -55, 73, 26, 112, -104, 120, 65, 17, 35, 35, 94, 61, -112, 1, 127, -91, 80, 59, 15,
#        -95, 51, 7, -48, -92, 100, 52, 115, -18, 54, -28, -82, 14, -47, -5, 28, 3, -42, -59, -77, 9, -48, -27, -103, -78,
#        63, 105, 27, -107, -40, -50, -116, 73, 80, 16, 88, -121, 110, 28, 7, 29, -91, 43, -60, -32, -7, 86, 50, -19, -83,
#        9, -43, -18, 36, 16, 127, 102, -103, -87, 31, -83, -121, -99, 2, 103, -91, 102, 48, -87, 86, 109, -73, -63, -50,
#        100, 0, 28, 12, -90, -8, -60, 1, 64, -115, 49, -1, 87, -119, -63, 102, 89, 117, -100, -16, 93, -62, 116, 1, 13,
#        3, 35, -95, 93, -16, 54, 68, 65, 38, 101, 33, 79, -122, -58, -117, -39, 19, -125, 59, 0, 5, -106, -111, 104, -27,
#        -6, 35, -44, -120, -125, 120, 48, 125, -118, 111, -40, 87, -11, -94, -70, 60, -24, 102, -8, -82, -43, 63, -6, 98,
#        15, -110, -86, 57, -97, 5, 124, 86, 41, -47, 103, 61, 70, -74, -59, 83, -31, 121, -61, 88, 102, -62, 61, 20, 111,
#        -7, -102, -115, -105, -80, -100, -124, -39, -100, -60, -87, 49, -61, 78, -22, 47, -52, 127, 19, -68, -78, -17,
#        -72, -120, -115, 90, 126, -97, -52, 76, 9, 12, 95, 91, 125, 25, 118, 64, -93, -44, -55, -11, -112, -113, -57,
#        -103, -125, -30, 26, 35, 73, -83, 60, 107, 58, 5, 0, -65, 16, -42, -54, -119, -95, -3, 122, 101, -89, -10, 20,
#        16, -23, 91, 65, -59, -115, 115, -71, 102, 43, -108, -28, 37, -14, 75, 91, -115, -120, -112, -3, 109, 100, 68,
#        -49, -105, -127, 51, -88, 30, 22, 85, -78, 12, 55, -95, -23, -10, -75, 35, -35, -72, -89, -11, 79, 5, 56, -4,
#        108, -79, -29, -83, -63, -76, -36, -95, 42, 66, -4, 64, 89, -45, 46, 34, -39, -94, 52, -60, -117, -119, 84, 95,
#        49, -114, 116, 107, -64, -30, -86, -8, -103, 13, 82, 51, 7, 47, -20, 94, 107, -91, -76, -25, -95, 88, -44, 110,
#        28, -78, -107, -44, -32, 103, -47, 79, -1, 41, 78, 100, -112, -26, 15, -108, -119, -53, 110, 57, -57, 64, 18,
#        -43, -73, 104, -52, -47, -106, -76, 87, -71, -36, 97, -108, 58, 97, 34, 23, -14, 64, 123, 84, 12, 121, 101, -75,
#        -69, 34, 59, 72, 44, 8, 36, 56, -122, -67, 104, -108, -17, -5, -107, -104, -112, 75, 118, -15, 7, -22, -87, 21,
#        92, -97, -20, 92, -21, -41, 76, 75, -19, 60, 4, -49, -58, -3, 83, -57, -99, -93, -128, -83, 12, 25, -72, 119,
#        -59, 8, -75, -100, -83, -125, 9, -94, 13, 68, 30, -13, 20, 43, -104, 104, 11, -26, -124, -78, -34, 6, -42, -39,
#        99, -17, -15, -9, -2, 62, 11, -73, -45, 16, -106, -62, 102, 70, 20, -88, -64, -117, 92, -1, -65, -117, -53, 14,
#        -10, -38, -117, 80, 34, 24, 29, 105, 32, -53, -66, 16, -115, -109, 23, 112, -80, -2, 12, 90, -113, -107, -53,
#        -35, 24, -69, 86, 28, 7, 23, -15, 120, -120, 63, -108, -81, 20, -96, 105, -46, -5, -36, 4, 74, 26, 124, -92, 103,
#        80, 9, 96, 0, 65, -96, -31, -18, 28, 19, -15, 29, -52, -55, 31, -45, 19, 57, -95, 77, -18, 69, 46, -15, -48, -47,
#        -119, 20, 8, 31, -19, -94, -92, 117, 100, -41, 98, 75, -68, 71, -52, -21, -100, 80, 29, -58, 95, 59, 116, -23,
#        26, -98, -18, -126, 39, -89, -28, 60, -70, -46, -24, -65, -59, -51, -89, -69, 84, 26, 100, 14, 51, -60, -49, 56,
#        58, 27, 75, -43, -40, -71, 100, -95, -45, 22, -19, -118, -33, -14, 2, -97, 3, 80, 7, 25, 1, 32, 2, -109, 49, -13,
#        -122, -71, -101, -72, -103, 36, -39, 38, 112, 16, -35, 27, -57, -29, -47, -121, -76, -1, -78, -71, 49, 17, 116,
#        12, 77, -74, 6, 40, -76, 103, 20, 95, -6, 18, 9, 83, 64, 14, 33, 60, -72, 107, 122, -32, -13, 43, -12, 80, 83,
#        -98, -36, -111, 66, 32, -90, -17, 74, -65, 117, 119, -115, 63, -24, 20, -79, 15, 39, -118, -7, -109, 35, 61, 4,
#        -110, 115, -38, 42, -31, -69, 44, 85, 97, 101, 97, 91, 119, -56, 12, 15, 89, 65, -13, 40, -6, 13, 64, 121, -31,
#        -28, -10, -34, -104, 106, 45, 114, -44, -94, 26, -61, -78, 40, 70, 37, -9, 5, 73, -107, -110, -86, 83, -114, 54,
#        -55, 125, 16, 54, -127, 66, 87, -117, 107, -47, -109, -41, -44, -57, 65, 2, -51, -65, 15, -82, 96, 85, -39, 54,
#        102, 38, 9, -44, 80, 61, -120, 39, 123, 78, 106, -4, -36, -90, 114, 1, -111, -33, -115, -8, -24, -126, -106, 6,
#        123, -93, -20, -126, -123, 10, -25, 126, -127, -41, 34, 21, 62, 15, 11, -35, 56, -115, -9, 119, -92, -105, -126,
#        9, 16, -55, 114, -7, -116, 25, -122, 109, 25, 40, -112, -91, 34, 81, -51, 11, -46, 7, 70, 51, -88, 79, 79, 99,
#        -16, -115, -89, 61, 118, -106, 78, 59, -115, -104, -90, -61, -115, -17, -29, -94, -64, 111, -61, -81, 37, -9, 23,
#        14, -71, -55, -3, -63, -53, 27, -71, 95, 70, -17, -33, 28, 105, 34, -44, 52, 70, -28, -121, -77, -63, -71, -85,
#        -123, -95, -117, 82, -50, -30, -23, 85, 10, -66, 100, -105, 20, -116, 82, -68, 31, 16, 10, -16, -64, 62, 81, 127,
#        -88, -108, 121, 45, 108, -56, 6, 16, -21, 58, 59, 14, -2, -47, 115, 114, 86, 33, -38, 97, -56, -10, 84, -57, 55,
#        -37, 81, 115, 101, -38, 25, -21, -34, 20, 110, 36, 13, -95, 4, -94, 121, -85, -11, -33, 80, 104, 53, 6, 20, -114,
#        -65, -104, -58, -82, -30, 54, -98, 110, 35, 19, 12, 51, -80, -55, 61, 83, 62, 109, 40, -30, -87, -78, 107, 53,
#        11, -36, -43, 51, -40, 94, -24, -32, 46, 46, 122, 47, 117, 47, -90, -41, 126, -51, -98, -48, -31, 11, -18, 66,
#        -100, -116, -21, 86, -49, 23, -11, 76, -118, 69, 98, 111, -108, -58, 86, 37, 29, -43, -7, 53, -66, -118, -65,
#        110, 117, 23, -83, -117, 25, 26, 91, -33, 110, 64, -1, -46, 89, -68, -78, -4, 95, 65, -74, 92, 56, -94, -52, 48,
#        1, 107, -99, -52, -21, -69, -8, -10, -40, 55, -61, -83, 102, -113, 105, -23, -75, -49, -15, -2, -63, 55, -41,
#        -118, -114, 105, -79, 45, 36, -18, -3, -62, 95, 99, -97, 110, -109, 51, 33, -46, -1, 25, 60, 76, -28, -67, 10,
#        13, 114, 61, 18, -25, -10, -30, 77, 98, -66, 84, -93, -11, -109, -47, -13, -120, -33, 37, -70, 27, -79, -16, 18,
#        100, 24, 89, 5, -51, -103, -103, 67, 40, 121, -95, -83, -33, -19, -121, 78, -31, 101, -100, -76, 27, -80, -109,
#        -77, 96, -112, 85, 38, 53, 14, 63, -65, 119, 36, -64, 124, -27, 0]
#
# hTruncBytes = [-101, 49, 61, -11, -12, -109, -49, 8, -52, -82, 75, -72, -4, -113, 4, 8, -65, -62, -86, -86, -94, 96, 71, 3,
#           -47, 7, -75, 125, -84, 112, 15, -114]
#
# crypt = NTRUCrypt()
#
# # msgBin = ""
# # for byte in msg:
# #     msgBin = "{0:08b}".format(byte & 0xff) + msgBin
# #
# # c = Polynomial.fromBSP(msgBin[:-7], Parameters.N, Parameters.q)
#
# print(crypt.decrypt(crypt.encrypt("The quick brown fox", pub), priv, pub, priv_inv))