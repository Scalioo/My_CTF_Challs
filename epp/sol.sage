import os
os.environ["PWNLIB_NOTERM"] = "1"
os.environ["TERM"] = "dumb"
from pwn import remote
import time
from tqdm import tqdm 

p = 3271248728850841860903005442889317521647
a = 799742319595872184263632894731325153523
b = 27093
start  = time.time()

# io = process(["python3", "final.py"])
io = remote('localhost' , 13002)
io.sendlineafter(b" x-coordinate :" , b"1")
Points =  eval(io.recvline().decode().strip())



v = Integer(io.recvline().decode().strip())
print(v)

def get_s(x) :
    P = E2.lift_x(x , all=True) 
    d = log(P[0] , G)
    if not is_prime(d):
        d = log(P[1] , G)
    return d


E2 =  EllipticCurve(GF(p^2), [a,b])
G = E2.lift_x(1)

print("=" * 80  , "Doing Dlog " , "="*80 , "\n")

S  = [get_s(Integer(Points[i])) for i in tqdm(range(len(Points))) ] 

print(S)
print('density:', RR(len(S) / log(max(map(abs, S)),2)))

print("============ Finding Sum ==================")
P = E2.lift_x(v, all=True) 
c = -1 * log(P[0] , G)
print("The Sum is : " , -c)

print(G.order())


print("============ Doing LLL ==================")
R = 2 ** 120
M = Matrix([
    [*S, G.order(), c],
    *[[0] * i + [1] + [0] * (len(S) - i + 1) for i in range(len(S))],
    [0] * len(S) + [0, R]
])

L = M.T.LLL()
res = L[-1][1:-1]
for l in L :
    print(l)
print(res)

flag = bytes([abs(r) for r in res])
print(flag)
end = time.time()
print((end - start) / 60 )