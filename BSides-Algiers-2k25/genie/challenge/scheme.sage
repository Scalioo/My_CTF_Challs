
import random, secrets
from hashlib import shake_256

load("CSIDH.sage")
load("HKZbasis.sage")


def mod_cn_2_vec(a, relation_basis, use_bkz=False, block_size=20, M=5):
    n = relation_basis.nrows()

    if use_bkz:
        A = relation_basis.BKZ(block_size=block_size)
    else:
        A = relation_basis.LLL()
    A = Matrix(ZZ, A)

    GS, mu = A.gram_schmidt()
    norms = [GS[i].norm()**2 for i in range(n)]

    target = vector([ZZ(0)]*n)
    target[0] = ZZ(a)

    for i in reversed(range(n)):
        coeff = target.dot_product(GS[i]) / norms[i]
        k = ZZ(coeff.round())
        target -= k * A[i]

    vec = vector(ZZ, target)

    short_vectors = []
    for _ in range(200):
        coeffs = [randrange(-2, 3) for _ in range(n)]
        short_vectors.append(sum(c*b for c, b in zip(coeffs, A.rows())))

    best_vec = vec
    best_norm = vec.norm(1)

    for _ in range(M):
        e_prime = vec + random.choice(short_vectors)
        improved = True
        while improved:
            improved = False
            for s in short_vectors:
                if (e_prime - s).norm(1) < e_prime.norm(1):
                    e_prime -= s
                    improved = True
                    break
        if e_prime.norm(1) < best_norm:
            best_norm = e_prime.norm(1)
            best_vec = e_prime

    return best_vec



class SCHEME:
    def __init__(self, primes , S , relation_basis, cn, use_bkz=True):
        self.csidh = CSIDH(primes)
        self.S = S
        self.E0 = self.csidh.E0
        self.SK = []
        self.PK = []
        self.relation_basis = relation_basis
        self.n = self.relation_basis.nrows()
        self.cn = cn  
        self.use_bkz = use_bkz

    def keygen(self):
        self._gen_secret_key()
        self._gen_public_key()
        return {
            "Points_list": [(P.xy() , PP.xy()) for _ , P , PP in self.PK],
            "params": {"n": self.n, "S": self.S}
        }

    def _gen_secret_key(self):
        self.SK = []
        self.SK.append([0] * self.n)  
        a  = ZZ(secrets.randbelow(int(self.cn)))
        vec = mod_cn_2_vec(a, self.relation_basis, use_bkz=self.use_bkz,block_size=20, M=10)
        vec = list(vec)
        self.SK.append(vec)
        quick = [-sign(a) for a in vec ]
        for _ in range(self.S - 2):
            vec = [vec[i] + quick[i] for i in range(len(vec))]
            self.SK.append(vec)
        return self.SK

    def _gen_public_key(self):
        self.PK = []
        Q1 = self.E0.gens()[0]
        Q2 = self.E0.gens()[1]
        for sk in self.SK:
            pk_curve , P , PP = self.csidh.group_action(self.E0, sk , Q1 , Q2)
            self.PK.append((pk_curve , P , PP))
        return self.PK

    def signing(self, msg, t):
        b_list, commit_curves = self.sample_ephemeral_randoms(t)
        c_list = self.derive_challenges(msg, commit_curves, t)
        responses = self.compute_responses(4 , b_list, c_list)
        return {
            "c": c_list,
            "r": responses
        }

    def sample_ephemeral_randoms(self, ROUNDS):
        b_list, curves = [], []
        for _ in range(ROUNDS):
            a = ZZ(secrets.randbelow(int(self.cn)))
            vec = mod_cn_2_vec(a, self.relation_basis,use_bkz=self.use_bkz, block_size=20, M=5)
            b_list.append(vec)
            pk_curve = self.csidh.group_action(self.E0, vec)   
            curves.append(pk_curve)
        return b_list, curves 

    def derive_challenges(self, msg, curves, t):
        enc = b"".join(int(E.j_invariant()).to_bytes(64, "big") for E in curves)
        enc = b"CSI-FISH|chal|" + enc + b"|MSG|" + (msg if isinstance(msg, bytes) else msg.encode())
        shake = shake_256(enc)
        rnd = shake.digest(t)
        return [(b % (self.S - 1)) + 1 for b in rnd]
    
    def compute_responses(self, e , b_list, c_list):
        responses = []
        for b, c in zip(b_list, c_list):
            aj = self.SK[c]  
            responses.append([bi - aji + random.randint(-e, e) for bi, aji in zip(b, aj)])
        return responses
        
    def verify(self, msg, sig , t) :
        if not isinstance(sig, dict) or "c" not in sig or "r" not in sig: return False
        c_list, r_list = sig["c"], sig["r"]
        if len(c_list) != t or len(c_list) != len(r_list):
            return False
        if any(not (1 <= c < self.S) for c in c_list):
            return False

        recomputed_curves = []
        for c, r in zip(c_list, r_list):
            base = self.PK[c][0]
            r_vec = [int(x) for x in r]
            E = self.csidh.group_action(base, r_vec)
            recomputed_curves.append(E)

        c_check = self.derive_challenges(msg, recomputed_curves, len(c_list))
        return list(c_list) == list(c_check)

