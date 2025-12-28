import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
import os

def gen_challenge():
    q = random_prime(2^160 - 1, False, 2^159)
    
    t = 2^864 // q
    if t % 2 != 0: t += 1
    
    while True:
        p = t * q + 1
        if p.is_prime():
            break
        t += 2
        
    e = (p - 1) // q
    while True:
        h = randint(2, p - 1)
        g = power_mod(h, e, p)
        if g != 1:
            break
            
    x = randint(1, q - 1)
    y = power_mod(g, x, p)
    
    a = randint(2, q - 1)
    b = randint(1, q - 1)
    
    signatures = []
    msgs = [b"Welcome to the challenge", b"This is a signed message", b"Hope U can Solve this"]
    
    state = randint(1, q - 1)
    
    hidden_bits = 32
    mask = (1 << hidden_bits) - 1
    
    for msg in msgs:
        state = (a * state + b) % q
        
        k = state >> hidden_bits
        
        if k == 0: k = 1 
        
        m_hash = int(hashlib.sha1(msg).hexdigest(), 16)
        
        r = power_mod(g, k, p) % q
        if r == 0: continue
        
        k_inv = inverse_mod(k, q)
        s = (k_inv * (m_hash + x * r)) % q
        if s == 0: continue
        
        signatures.append({
            'msg': msg.decode(),
            'h': m_hash,
            'r': r,
            's': s
        })
        
    FLAG = b"Cybears{REDACTED}"
    key = hashlib.sha256(str(x).encode()).digest()
    iv = os.urandom(16)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    ciphertext = cipher.encrypt(pad(FLAG, 16))
    
    output = []
    output.append("=== Public Parameters ===")
    output.append(f"p = {p}")
    output.append(f"q = {q}")
    output.append(f"g = {g}")
    output.append(f"y = {y}")
    output.append(f"a = {a}")
    output.append(f"b = {b}")
    output.append("")
    output.append("=== Signatures ===")
    for i, sig in enumerate(signatures):
        output.append(f"Msg {i}: {sig['msg']}")
        output.append(f"r: {sig['r']}")
        output.append(f"s: {sig['s']}")
        output.append("")
        
    output.append("=== Encrypted Flag ===")
    output.append(f"iv = {iv.hex()}")
    output.append(f"ciphertext = {ciphertext.hex()}")
    
    with open("out.txt", "w") as f:
        f.write("\n".join(output))
        

if __name__ == "__main__":
    gen_challenge()
