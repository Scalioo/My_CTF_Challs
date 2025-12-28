import hashlib 
import secrets
from Crypto.Util.number import getPrime, isPrime, inverse, long_to_bytes
import os
import json

try:
    FLAG = open("flag.txt", "r").read().strip()
except FileNotFoundError:
    FLAG = "Cybears{placeholder_flag_for_testing}"

class Signature:
    def __init__(self):
        while True:
            self.q = getPrime(256)
            self.p = secrets.randbits(1792) * self.q + 1
            if isPrime(self.p):
                self.g = pow(2, (self.p-1)//self.q, self.p)
                if self.g != 1:
                    print(f"p = {self.p}")
                    print(f"q = {self.q}") 
                    print(f"g = {self.g}")
                    break

        self.x = secrets.randbelow(self.q - 1) + 1
        self.y = pow(self.g, self.x, self.p)
    
    def sign(self, m):
        h = int(hashlib.sha256(m).hexdigest(), 16) % self.q
        while True:
            ks = [int(hashlib.sha3_224(long_to_bytes(secrets.randbelow(self.q - 1) + 1)).hexdigest() ,16)  for _ in range(3)]
            rs = [pow(self.g, k, self.p) % self.q for k in ks]

            if not all(rs):
                continue
                
            try:
                k0_inv = inverse(ks[0], self.q)
            except ValueError:
                continue
                
            s = (k0_inv * (h * rs[0] + self.x * rs[1] * rs[2])) % self.q
            
            if s == 0:
                continue
            
            return (rs, s)
    
    def verify(self, m, sig):
        try:
            rs, s = sig
            if len(rs) != 3:
                return False
                
            if not all(0 < r < self.q for r in rs):
                return False
            if not (0 < s < self.q):
                return False
                
            h = int(hashlib.sha256(m).hexdigest(), 16) % self.q
            w = inverse(s, self.q)
            
            u1 = (h * w * rs[0]) % self.q
            u2 = (rs[1] * rs[2] * w) % self.q
            
            term1 = pow(self.g, u1, self.p)
            term2 = pow(self.y, u2, self.p)
            v = (term1 * term2) % self.p % self.q
            return (v == rs[0])
        except Exception:
            return False

if __name__ == "__main__":
    elgamal = Signature()

    for i in range(21):
        print(f"\n--- Attempt {i+1}/21 ---")
        choice = input("Choose an option:\n1. Sign a message\n2. Verify a message\n> ")
        
        if choice == "1":
            message = os.urandom(32)
            print(f"Message to sign (hex): {message.hex()}")
            signature = elgamal.sign(message)
            print(f"Signature: {signature}")
            
        elif choice == "2":
            message = os.urandom(32)
            print(f"Message to verify (hex): {message.hex()}")
            signature_input = input("Enter the signature as a tuple ([r0, r1, r2], s): ")
            
            try:
                signature = json.loads(signature_input)
                # Accept both dict and list formats
                if isinstance(signature, dict) and "rs" in signature and "s" in signature:
                    signature = (tuple(signature["rs"]), signature["s"])
                elif isinstance(signature, list) and len(signature) == 2:
                    signature = (tuple(signature[0]), signature[1])
                else:
                    print("Error: Invalid signature format. Use {'rs': [r0, r1, r2], 's': s} or [[r0, r1, r2], s]")
                    continue
                print(f"Verifying signature: {signature}")
                if elgamal.verify(message, signature):
                    print("Signature is valid.")
                    print(f"Here is your flag: {FLAG}")
                    exit(0)
                else:
                    print("Signature is invalid.")
            except (ValueError, SyntaxError, TypeError):
                print("Error: Invalid signature format. Use {'rs': [r0, r1, r2], 's': s} or ([r0, r1, r2], s)")
            except Exception as e:
                print(f"An unexpected error occurred: {e}")
        else:
            print("Invalid choice.")