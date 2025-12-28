
from Crypto.Util.number import getPrime

flag = open('flag.txt' , 'rb').read()
secret = flag.split(b'{')[1].split(b'}')[0]



p = 3271248728850841860903005442889317521647
a = 799742319595872184263632894731325153523
b = 27093

class Curve:
    def __init__(self, a, b, p):
        self.a = a
        self.b = b
        self.p = p

    def to_affine(self , P):
        return P[0] * pow(P[1] , -1, p) % p
    
    def double_and_add(self, P, Q, PQ):
        X1, Z1 = PQ
        X2, Z2 = P
        X3, Z3 = Q
        a = self.a
        b = self.b
        p = self.p

        A = X2**2
        B = Z2**2
        C = A - a * B
        X4 = C**2 - 8 * b * X2 * Z2**3
        Z4 = 4 * (X2 * Z2 * (A + a * B) + b * Z2**4)

        D = X2 * X3 - a * Z2 * Z3
        E = X2 * Z3 + X3 * Z2
        X5 = Z1 * (D**2 - 4 * b * Z2 * Z3 * E)
        Z5 = X1 * (X2 * Z3 - X3 * Z2)**2

        return (X4 % p, Z4 % p), (X5 % p, Z5 % p)

    def multiply(self, P, k):
        R0 = (1, 0)
        R1 = P
        for i in reversed(range(k.bit_length())):
            bit = (k >> i) & 1
            if bit == 0:
                R0, R1 = self.double_and_add(R0, R1, P)
            else:
                R1, R0 = self.double_and_add(R1, R0, P)
        return R0
    
    # Addition works only if P and Q are scalar multiples of the same base point
    def add(self , P , Q , d) :
        X =  self.multiply(G , d)
        Q =  self.double_and_add(P,Q , X)[1]
        return Q
    
E = Curve(a,b,p)
generator  = int(input("Enter Your Generator's x-coordinate :"))
G = (generator , 1)

S = [getPrime(128) for _ in range(len(secret))]

Points = [E.multiply(G,S[i]) for i in range(len(secret))]
print([E.to_affine(P) for P in Points])



V = E.multiply(Points[0] , secret[0])
for i in range(1 , len(secret)):
    D = E.multiply(Points[i] , secret[i])
    diff = sum([S[i]*secret[i] for i in range(i)])
    V = E.add(V,D,abs(S[i]*secret[i] - diff))


print(E.to_affine(V))










