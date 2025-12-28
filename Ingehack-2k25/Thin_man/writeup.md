# Thin Man

## Code Analysis

- The server multiplies the flag by a point given by the user.  
- Looking at the add function, we notice that the curve is written in [Long Weierstrass form](https://crypto.stanford.edu/pbc/notes/elliptic/explicit.html).  
- The server does not check whether the provided point is on the intended curve, making it vulnerable to an **Invalid Curve Attack**.  
- The `a6` parameter does not affect the addition function, meaning that scalar multiplication remains correct for any `a6` as long as the other parameters are valid.  

## Exploit

### Recovering `n`:

1. **Using a Single Point is Insufficient**  
   - Since the flag is long, using a single point to recover `n` via discrete logarithm does not work.  
   - Instead, we need to generate multiple points with different `a6` values to obtain multiple modular reductions of `n`
   
2. **Generate Multiple Points on Different Curves**  
   - By setting different values of `a6`, we obtain different elliptic curves.  
   - Each curve has its own **group order**, which we can factor into small prime factors.  

3. **Retrieve the Encrypted Flag (Scalar Multiplication Output)**  
   - The server performs scalar multiplication:   `P = n * G`
   - We retrieve the resulting point `P` for different curves.  

4. **Compute Discrete Logarithm for Each Factor**  
   - Using the **Pohlig-Hellman algorithm**, we compute `n mod p^e` for different small prime factors `p^e` of the group order.  
   - Since the order of each elliptic curve is different, we ensure that `n` is reduced modulo multiple coprime values.  

5. **Combine Partial Results Using the Chinese Remainder Theorem (CRT)**  
   - After computing `n` modulo each prime factor, we use **CRT** to reconstruct the full value of `n`.  

6. **Recover the Flag**  
   - Once `n` is recovered, we convert it to bytes to reveal the flag.  
## Code
[Check the script](sol/sol.sage)
