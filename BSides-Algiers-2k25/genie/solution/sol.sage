import os
os.environ["PWNLIB_NOTERM"] = "1"
os.environ["TERM"] = "dumb"
from pwn import  remote
import random, secrets

from hashlib import shake_256

def mod_cn_2_vec(a, relation_basis, use_bkz=False, block_size=20, M=5):
    """
    Convert integer 'a' mod class number into a short exponent vector
    using Babai + optional DLW, with Sage's LLL/BKZ.
    """
    n = relation_basis.nrows()

    # Step 1: reduce basis
    if use_bkz:
        A = relation_basis.BKZ(block_size=block_size)
    else:
        A = relation_basis.LLL()
    A = Matrix(ZZ, A)

    # Step 2: Gram–Schmidt for Babai
    GS, mu = A.gram_schmidt()
    norms = [GS[i].norm()**2 for i in range(n)]

    # Step 3: embed a into target
    target = vector([ZZ(0)]*n)
    target[0] = ZZ(a)

    # Step 4: Babai nearest plane
    for i in reversed(range(n)):
        coeff = target.dot_product(GS[i]) / norms[i]
        k = ZZ(coeff.round())
        target -= k * A[i]

    vec = vector(ZZ, target)

    # Step 5: DLW refinement
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

load("HKZbasis.sage")
load("CSIDH.sage")



primes  = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 331, 337, 347, 349, 353, 359, 367, 373, 587]
p = 4 * prod(primes) - 1
F.<i> = GF(p^2, modulus=x^2 + 1)   
i = F.gen(0)
Fp = GF(p)
S = 16
csidh = CSIDH(primes)  
def get_curve(P , PP):
    x1 = F(P[0])   
    y1 = F(P[1])   
    x2 = F(PP[0])
    y2 = F(PP[1])
    if x1 != x2:
        a = (y1^2 - y2^2 - (x1^3 - x2^3)) / (x1 - x2)
        b = y1^2 - x1^3 - a*x1
        E = EllipticCurve(F, [a, b])
        P = E(x1, y1)
        Q = E(x2, y2)
        return P , Q
    else:
        print("x1 == x2, need a third point or special handling.")

def same_subgroup(P, Q, ell):
    P = ((p+1)/ell) * P
    Q = ((p+1)/ell) * Q
    e = P.weil_pairing(Q, ell)
    return e == 1


def kernel_sign(R1 , R2, p ,ell):
    R = ((p+1)/ell) * R1 
    if R.is_zero() :
        R = ((p+1)/ell) * R2
    x, y = R.xy()
    FrobR = R.curve()(x^p, y^p)
    if FrobR == R:
        return -1   
    elif FrobR == -R:
        return +1   
    else:
        return None 

def get_secret_key(Points):
    tested = [ get_curve(Point[0] , Point[1]) for Point in Points ] 
    sk = [[0, False] for _ in range(74)]
    for i in range(74):
        for pair in tested[1:]:
            P , PP =  pair  
            if sk[i][1] : continue
            if same_subgroup(P , PP , primes[i]) :
                sk[i][0] += kernel_sign(P , PP ,p , primes[i])
            else : 
                sk[i][1] = True
    return sk 

def signing(SK, msg, t):
    b_list, commit_curves = sample_ephemeral_randoms(t)
    c_list = derive_challenges(msg, commit_curves, t)
    responses = compute_responses(SK , b_list, c_list)
    return {
        "c": c_list,
        "r": responses
    }

def sample_ephemeral_randoms(ROUNDS):
    b_list, curves = [], []
    for _ in range(ROUNDS):
        a = ZZ(secrets.randbelow(int(cn)))
        vec = mod_cn_2_vec(a, relation_basis,use_bkz=True, block_size=20, M=5)
        b_list.append(vec)
        pk_curve = csidh.group_action(csidh.E0, vec)   
        curves.append(pk_curve)
    return b_list, curves 

def derive_challenges(msg, curves, t):
    enc = b"".join(int(E.j_invariant()).to_bytes(64, "big") for E in curves)
    enc = b"CSI-FISH|chal|" + enc + b"|MSG|" + (msg if isinstance(msg, bytes) else msg.encode())
    shake = shake_256(enc)
    rnd = shake.digest(t)
    return [(b % (S - 1)) + 1 for b in rnd]

def compute_responses(SK , b_list, c_list):
    responses = []
    for b, c in zip(b_list, c_list):
        aj = SK[c]                
        responses.append([bi - aji  for bi, aji in zip(b, aj)])
    return responses

def get_SK(vec):
    SK = []
    SK.append([0] * 74) 
    SK.append(vec)
    quick = [-sign(a) for a in vec ]
    for _ in range(S - 2):
        vec = [vec[i] + quick[i] for i in range(len(vec))]
        SK.append(vec)
    return SK

to_sign = 'shellmates{Just_To_Make_Sure}'
# io = process(["sage" , "server.sage"])
io = remote('localhost' , 13005)

io.recvuntil(b'>')
io.sendline(b'2')
io.recvline()
Points = eval(io.recvline().strip())
print(Points)
io.recvline()

io.sendlineafter(b'Enter a message to verify: ' , to_sign.encode())

sk = get_secret_key(Points)

vec= [sk[i][0] for i in range(74) ]
print(vec)
SK = get_SK(vec)
sig = signing(SK ,to_sign  , 23)
io.sendlineafter(b'Enter the signature as a dictionary: ' , str(sig).encode())
io.interactive()











