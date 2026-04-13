import ast
import sys
import os 
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad

flag = open("flag.txt", "rb").read()

load("HKZbasis.sage")
load("scheme.sage")

primes = [3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43, 47, 53, 59, 61, 67, 71, 
          73, 79, 83, 89, 97, 101, 103, 107, 109, 113, 127, 131, 137, 139, 149, 151, 
          157, 163, 167, 173, 179, 181, 191, 193, 197, 199, 211, 223, 227, 229, 233, 
          239, 241, 251, 257, 263, 269, 271, 277, 281, 283, 293, 307, 311, 313, 317, 
          331, 337, 347, 349, 353, 359, 367, 373, 587]

def initialize(primes):
    scheme = SCHEME(primes, S=16, relation_basis=relation_basis, cn=cn, use_bkz=True)
    return scheme

def sign_message(scheme, message):
    sig = scheme.signing(message, 23)
    return sig

def verify_message(scheme, message, sig):
    check = scheme.verify(message, sig , 23)
    if check:
        print("Correct Signature")
    else:
        print("That's a wrong signature")



# generate pubkey and sign a random message 

scheme = initialize(primes)
print("Generating the Key, this may take some time...")
keys = scheme.keygen()
print(keys['Points_list'])
print(keys['params'])
msg = os.urandom(32)
signature = sign_message(scheme, msg )
print("Signature:")
print(verify_message(scheme , msg , signature))



key = str(scheme.SK).encode()
key = hashlib.sha256(key).digest()

iv = os.urandom(16)

cipher = AES.new(key, AES.MODE_CBC, iv)

ciphertext = cipher.encrypt(pad(flag , AES.block_size))

result = iv + ciphertext
print(f"Hex result: {result.hex()}")



# in out file right all necessary outputs 



with open("out.txt", "w") as f:
    f.write("Points_list:\n")
    f.write(str(keys['Points_list']) + "\n")
    f.write("Params:\n")
    f.write(str(keys['params']) + "\n")
    f.write("Random message (hex):\n")
    f.write(msg.hex() + "\n")
    f.write("Signature:\n")
    f.write(str(signature) + "\n")
    f.write("Hex result:\n")
    f.write(result.hex() + "\n")


