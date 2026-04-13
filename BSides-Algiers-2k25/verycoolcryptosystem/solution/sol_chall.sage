from Crypto.Util.number import long_to_bytes
lines = open("../dist/out.txt" , 'r').readlines()


n =     int(lines[0].split('=')[1].strip())
b_s =   eval(lines[1].split('=')[1].strip())
M_0_1 = int(lines[2].split('=')[1].strip())
M_1_2 = int(lines[3].split('=')[1].strip())
M_2_3 = int(lines[4].split('=')[1].strip())
A   = eval(lines[5].split('=')[1].strip())
eps =   eval(lines[6].split('=')[1].strip())
U_ =    eval(lines[7].split('=')[1].strip())



Pn.<x,y> = PolynomialRing(Zmod(n) , order="lex")


known = int.from_bytes(b'shellmat' , "big") << (22*8)


dbl = (known + x) ** 6
k = 5
e1 = 5 


fp = ((dbl**e1 * y  + b_s[0]) * sum([(y + dbl)**(k-1-i) * ((y**2) + dbl)** i for i in range(k)]) )- M_0_1

fpp = (y * (dbl  + b_s[1])**e1 + b_s[2]) * sum([((y**2) + dbl)**(k-1-i) * ((y**3) + dbl)**i for i in range(k)])  -  M_1_2

fppp = (y* ( y * (dbl + b_s[3])**e1 + b_s[4] )+ b_s[5]) * sum([((y**3) + dbl)**(k-1-i) * ((y**4) + dbl)**i for i in range(k)])  - M_2_3


I = ideal(fp ,fpp  , fppp)
G = I.groebner_basis() 


P2n.<y> = PolynomialRing(Zmod(n))
fa = P2n(G[1])
a = fa.roots(multiplicities=False)[0]

print(a)

P2n.<x> = PolynomialRing(Zmod(n))
fm = P2n(G[0](x,a))
m_s = fm.roots(multiplicities=False)


m = b''
for i in m_s :
    try :
        if long_to_bytes(int(i)).decode().isascii() :
            print(long_to_bytes(int(i)))
            m = long_to_bytes(int(i))
    except :
        continue

Rn = Zmod(n)
SIZE = 4 
M = GL(SIZE, Rn)

def priv_key(flag1) :
    m = Rn(int.from_bytes(flag1,"big"))  
    coeffs = SIZE - 1 
    bound = coeffs * (coeffs + 1) // 2
    c = m ** bound
    c_s = []
    for i in range(coeffs):
        t = i * (i + 1) // 2
        o = ((c +  b_s[t]) if t else c ) ** 5 
        if not i:
            c_s.append((a * o + b_s[t]))
            continue
        for j in range(0, i):
            o *= a 
            o += b_s[t + j + 1]
        c_s.append(o)

    diag = [a**i + c for i in range(1,5)]
    Mat = Matrix(Rn, [ i * [0] + [diag[i]] +  ([c_s[i] ] if i < len(c_s) else []) + (2-i) * [((b_s[i] + b_s[i+1])*a)**20 ]  for i in range(4)] )
    return M(Mat) , b_s  


flag = b'shellmat'+ m
D , b_s  = priv_key(flag)
eps = M(eps)
U_ =  M(U_)
Dr = D^k
Dr = Dr.list() 
assert Dr[0][1] == M_0_1 
assert Dr[1][2] == M_1_2 
assert Dr[2][3] == M_2_3 





lam  = ~D * eps * D
U = lam * U_ * lam 

print(U)

for u in U.list() :
    for i in u :
        flag += long_to_bytes(int(i))

print(flag)






