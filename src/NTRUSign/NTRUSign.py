import secrets
import time
from copy import deepcopy
import pickle

import math
from typing import List

from src.NTRUCrypt.MaskGenerator import MGF
from src.NTRUSign.BasisGenerator import BasisGenerator
from src.Utils.Polynomial import Polynomial
from src.NTRUSign.SigningParameters import Parameters


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


class NTRUSignError(Exception):
    """
    This class will be used to represent errors that have to do with
    the NTRUSign object specified below
    """
    pass


class NTRUSign:

    def __init__(self):
        Parameters.initParameters("ees251sp2")
        pass

    def keygen(self) -> (Polynomial, Polynomial):
        """
        A key pair shall be generated using the following or a mathematically equivalent set of steps. Note that the
        algorithm below outputs only the values f and h. In some applications it may be desirable to store the values
        f^–1 and g as well. This standard does not specify the output format for the key as long as it is unambiguous.
        :return: a keypair consisting of private key f and public key h
        """

        N = Parameters.N
        q = Parameters.q
        i = Parameters.pertubationBases
        privateKeySet = []
        while i >= 0:
            f, g, F, G = BasisGenerator.myGenerateBasis()
            # pickle.dump([f,g,F,G], open("Basis.p", "wb"))
            # f,g,F,G = pickle.load(open("Basis.p", 'rb'))
            print("f: {}".format(f))
            print("g: {}".format(g))
            print("F: {}".format(F))
            print("G: {}".format(G))
            if Parameters.basisType == "standard":
                fp = F
            elif Parameters.basisType == "transpose":
                fp = g
            h = f.inverse_pow_2(2, int(math.floor(math.log2(q)))) * fp
            privateKeySet.append((f, fp, h))
            i -= 1

        return h, privateKeySet

    def sign(self, m: Polynomial, privkey: (Polynomial, Polynomial), perBases: "List[(Polynomial, Polynomial, Polynomial)]"):
        """
        This algorithm implements the SVSP signature primitive as specified in section 3.5.2.1 of [1]
        :param m: message to sign
        :param privkey: private key of the recipient
        :param perBases: pertubation bases (fi, f'i, hi)
        :return: signature s, which is a ring element
        """
        N = Parameters.N
        q = Parameters.q

        s = Polynomial([0], N)
        iLoop = Parameters.pertubationBases
        while iLoop >= 1:
            fiLoop = perBases[iLoop][0]
            B = (fiLoop * m * Polynomial([-1], N)) % q
            j = 0
            while j < N:
                B[j] = int(math.floor(B[j]/q + 0.5))
                j += 1
            j = 0
            b = (fiLoop * m) % q
            while j < N:
                b[j] = int(math.floor(b[j] / q + 0.5))
                j += 1
            siLoop = (b * fiLoop + B * fiLoop) % q
            s = (s + siLoop) % q
            m = (siLoop * (perBases[iLoop][2] - perBases[iLoop-1][2])) % q
            iLoop -= 1
        B = privkey[0] * m * Polynomial([-1], N)
        j = 0
        while j < N:
            B[j] = int(math.floor(B[j] / q + 0.5))
            j += 1
        j = 0
        b = (privkey[0] * m)
        while j < N:
            b[j] = int(math.floor(b[j] / q + 0.5))
            j += 1
        s0 = b * privkey[1] + B * privkey[0]
        return (s + s0) % q

    def verify(self, i: Polynomial, s: Polynomial, pub: Polynomial):
        """
        This algorithm implements the SVVP verification operation as specified in section 3.5.3.1 of [1]
        :param i: message representative, which is a polynomial of degree N - 1
        :param s: signature to be verified, a polynomial
        :param pub: public key, a polynomial
        :return: True or False indicating that the signature is valid or not
        """
        N = Parameters.N
        q = Parameters.q
        normBound = Parameters.normBound

        t = pub * s
        e2 = (i - t) % q
        e2 = NTRUSign._shift(e2)    # 3 - 9
        s = NTRUSign._shift(s)      # 10 - 16
        j = 0
        ssum, e2sum, squarsesum = 0, 0, 0
        while j < N:
            ssum += s[j]
            e2sum += e2[j]
            squarsesum += s[j]*s[j] + e2[j]*e2[j]
            j += 1
        centeredNorm = math.sqrt((N*squarsesum - ssum*ssum - e2sum*e2sum)/N)
        return not (centeredNorm > normBound)

    @staticmethod
    def _shift(p: Polynomial):
        N, q = Parameters.N, Parameters.q

        p = deepcopy(p)
        maxrange = 0
        maxrangeindex = 0
        psorted = sorted(p[:])
        for i in range(len(psorted) - 1):
            range = psorted[i + 1] - psorted[i]
            if range > maxrange:
                maxrange = range
        pl = psorted[:-1]
        pm = psorted[0]
        j = q - pl + pm
        if j > maxrange:
            shift = 0
            while p[shift] != pm:
                shift += 1
        else:
            shift = j
        j = 0
        while j < N:
            p[j] = (p[j] - shift) % q
            j += 1
        return p

    def _getRand_(self, max=-1):
        """
        Generate and return a random number below max
        :param max: upper bound for random number, if max = -1 => max = 2^32
        :return: random number bounded by max
        """
        if max == -1:
            max = 2**32
        return secrets.randbelow(max)


sign = NTRUSign()
pub, something = sign.keygen()