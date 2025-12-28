import hashlib
import random

def solve_truncated_lcg_dss(p, q, g, y, a, b, hidden_bits, signatures):
    T = 2**hidden_bits
    
    R = Zmod(q)
    Xs = []
    Cs = []
    
    n = len(signatures) - 1 
    
    for i in range(n):
        r1, s1, h1 = signatures[i]
        r2, s2, h2 = signatures[i+1]
        
        term1_r = R(s2).inverse() * r2 * T
        term2_r = R(s1).inverse() * r1 * T
        
        term1_h = R(s2).inverse() * h2 * T
        term2_h = R(s1).inverse() * h1 * T
        
        X_val = term1_r - a * term2_r
        C_val = term1_h - a * term2_h - b
        
        Xs.append(int(X_val))
        Cs.append(int(C_val))
        
    lattice_eqs = []
    
    for i in range(len(Xs) - 1):
        coeffs = [0] * (len(signatures)) 
        
        coeffs[i] += int(a * R(Xs[i+1]))
        
        coeffs[i+1] += int(-R(Xs[i+1]) - a * R(Xs[i]))
        
        coeffs[i+2] += int(Xs[i])
        
        const_val = int(-R(Cs[i]) * R(Xs[i+1]) + R(Cs[i+1]) * R(Xs[i]))
        
        lattice_eqs.append((coeffs, const_val))
        
    print(f"Generated {len(lattice_eqs)} lattice equations.")
    
    num_deltas = len(signatures)
    num_eqs = len(lattice_eqs)
    
    dim = num_deltas + 1
    
    K = 2**(hidden_bits + 10) 
    

        
    svp_rows = []
    
    for j in range(num_deltas):
        row = [0] * (num_deltas + num_eqs + 1)
        row[j] = 1
        for eq_idx in range(num_eqs):
            c = lattice_eqs[eq_idx][0][j]
            row[num_deltas + eq_idx] = c * K
        svp_rows.append(row)
        
    for eq_idx in range(num_eqs):
        row = [0] * (num_deltas + num_eqs + 1)
        row[num_deltas + eq_idx] = q * K
        svp_rows.append(row)
        
    row_c = [0] * (num_deltas + num_eqs + 1)
    for eq_idx in range(num_eqs):
        c_val = lattice_eqs[eq_idx][1]
        row_c[num_deltas + eq_idx] = c_val * K
    row_c[-1] = 1 
    svp_rows.append(row_c)
    
    M = Matrix(ZZ, svp_rows)
    print("Running LLL...")
    M_red = M.LLL()
    
    print("Checking rows...")
    for row in M_red:
        if abs(row[-1]) == 1:
            valid_eqs = True
            for k in range(num_eqs):
                if row[num_deltas + k] != 0:
                    valid_eqs = False
                    break
            
            if valid_eqs:
                deltas = []
                sign = row[-1]
                for j in range(num_deltas):
                    val = row[j] * sign
                    deltas.append(val)
                
                if all(0 <= d < 2**(hidden_bits+10) for d in deltas): 
                     print("Found small deltas!", deltas[:3])
                     
                     d0 = deltas[0]
                     d1 = deltas[1]
                     
                     val = R(d1) - R(a) * R(d0) + R(Cs[0])
                     num = -val
                     den = R(Xs[0])
                     
                     curr_x = num / den
                     curr_x_int = Integer(curr_x)
                     if pow(g, curr_x_int, p) == y:
                         return curr_x_int, a, b

    return None

def solve_challenge():
    print("Reading challenge from out.txt...")
    with open("out.txt", "r") as f:
        lines = f.readlines()
        
    p = int(lines[1].split('=')[1].strip())
    q = int(lines[2].split('=')[1].strip())
    g = int(lines[3].split('=')[1].strip())
    y = int(lines[4].split('=')[1].strip())
    a = int(lines[5].split('=')[1].strip())
    b = int(lines[6].split('=')[1].strip())
    hidden_bits = 32
    
    signatures = []
    i = 0
    while i < len(lines):
        line = lines[i].strip()
        if line.startswith("Msg"):
            msg_str = line.split(":", 1)[1].strip()
            msg_bytes = msg_str.encode('utf-8')
            msg_h = int(hashlib.sha1(msg_bytes).hexdigest(), 16)
            
            r_line = lines[i+1].strip()
            s_line = lines[i+2].strip()
            r = int(r_line.split(':')[1].strip())
            s = int(s_line.split(':')[1].strip())
            signatures.append((r, s, msg_h))
            i += 3
        elif line.startswith("iv ="):
             iv_hex = line.split('=')[1].strip()
        elif line.startswith("ciphertext ="):
             ct_hex = line.split('=')[1].strip()
        i += 1
        
    print(f"Parsed {len(signatures)} signatures.")
    
    for count in range(3, len(signatures) + 1):
        print(f"\n--- Testing with first {count} signatures ---")
        try:
            sol = solve_truncated_lcg_dss(p, q, g, y, a, b, hidden_bits, signatures[:count])
            if sol:
                x, a, b = sol
                print(f"Solved with {count} signatures!")
                
                from Crypto.Cipher import AES
                from Crypto.Util.Padding import unpad
                
                key = hashlib.sha256(str(x).encode()).digest()
                iv = bytes.fromhex(iv_hex)
                ct = bytes.fromhex(ct_hex)
                
                cipher = AES.new(key, AES.MODE_CBC, iv)
                try:
                    flag = unpad(cipher.decrypt(ct), 16)
                    print("Decrypted Flag:", flag.decode())
                    return # Exit after finding min signatures
                except Exception as e:
                    print("Decryption failed:", e)
            else:
                print(f"Failed with {count} signatures.")
    
        except Exception as e:
            print(f"Attack failed with {count} signatures: {e}")


if __name__ == "__main__":
    solve_challenge()
