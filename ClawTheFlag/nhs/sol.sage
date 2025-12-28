import hashlib
from Crypto.Util.number import inverse as inv , long_to_bytes as lb
import os
os.environ['TERM'] = 'xterm'
import secrets

B = 2^224


# lines = open('out.txt', 'r').readlines()
# messages = eval(lines[0])
# n = int(lines[1])
# sigs = eval(lines[2])

from pwn import * 
import os
import ast
from Crypto.Util.number import inverse, bytes_to_long
import hashlib
import json

def sign(m , q , g , p ,x ):
        h = int(hashlib.sha256(m).hexdigest(), 16) % q
        while True:
            ks = [int(hashlib.sha3_224(lb(secrets.randbelow(q - 1) + 1)).hexdigest() ,16)  for i in range(3)]
            rs = [pow(g, k, p) % q for k in ks]

            if not all(rs):
                continue
            try:
                k_inv = inverse(ks[0], q)
            except ValueError:
                print("Cannot compute inverse of k, regenerating...")
                continue

            s = (k_inv * (h * rs[0]  + x * rs[1] * rs[2] )) % q

            if s == 0:
                continue
                
            return (rs, s)


messages = []
sigs = []

r = remote('nsh.ctf.clawtheflag.com', 1337, ssl=True)
# r = remote('localhost', 1025)

p = int(r.recvline().strip().split(b'=')[1])
q = int(r.recvline().strip().split(b'=')[1])
g = int(r.recvline().strip().split(b'=')[1])
n = q
for _ in range(20):
    r.recvlines(3)
    r.sendlineafter(b'> ', b'1')
    #    recv message from   : print(f"Message to sign (hex): {message.hex()}") 
    msg = r.recvline().strip().split(b': ')[1]
    m = bytes.fromhex( msg.decode() ) 
    messages.append(m) 
    # r.interactive()
    # r.sendlineafter(b'Enter the message to sign: ', m.hex().encode())
    sig = r.recvline().strip().split(b': ')[1]
    sigs.append(ast.literal_eval(sig.decode()) )


print(sigs)

rs = [sig[0] for sig in sigs] 
ss = [sig[1] for sig in sigs]

msgs = [ int(hashlib.sha256(m).hexdigest(), 16) % n for m in messages ]


depth = 14
ts , a_s = [] , []
for i in range(depth-1) :
    ts.append( rs[i][1] * rs[i][2] * inv(ss[i],n)  )
    a_s.append( inv(ss[i],n) * msgs[i] * rs[i][0])

matrix = [[0]*i + [n] + [0]*(depth-1-i+1) for i in range(depth-1)]
matrix.append(ts+ [ B/n, 0])
matrix.append(a_s+[0,B])

M = Matrix(QQ , matrix)
out = M.LLL()

print(int(B).bit_length())

#get d from Bd/n
for row in out:
    if row[-1] == B:
        print('wiw')
        potential_nonce_diff = row[0]
        d = ((QQ((row[-2])) * n) / B) % n
        print(int(d))

        r.recvlines(3)
        r.sendlineafter(b'> ', b'2')
        m = r.recvline().strip().split(b': ')[1]
        m = bytes.fromhex( m.decode() )
        print(f"Message to verify (hex): {m.hex()}")
        signature = sign(m , q , g , p , int(d) )
        signature_json = json.dumps({"rs": signature[0], "s": signature[1]})
        print(f"Signature (JSON): {signature_json}")
        r.sendlineafter(b'Enter the signature as a tuple ([r0, r1, r2], s): ', signature_json.encode())
        # r.recvuntil(b's): ')
        # r , s = sign()
        # r.sendline()
        r.interactive()

# 83779614715916756932175856084201217306485757365426413585027101166523921515973


