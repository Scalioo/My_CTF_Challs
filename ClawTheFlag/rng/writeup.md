# Rng - Writeup

## Metadata
| Property | Value |
|----------|-------|
| **Name** | Rng |
| **Difficulty** | Hard |
| **Description** | I love rng , who doesn't ? (im lying) |
| **Flag** | `Cybears{lil_bit_truncated_lil_bit_signature_and_thats_the_flag}` |

## Challenge Description
The challenge provides a static output file `out.txt` containing public parameters ($p, q, g, y$), LCG parameters ($a, b$), and three DSA signatures for specific messages. The flag is encrypted using AES-CBC, with the key derived from the private key $x$.

The DSA nonces $k$ are generated using a Linear Congruential Generator (LCG):
1. An initial random `state` $S_0$ is chosen.
2. For each signature:
   - `state = (a * state + b) % q`
   - `k = state >> 32`
   - The signature $(r, s)$ is computed using this truncated nonce $k$.

## Vulnerability
The vulnerability is a **lattice-based attack on truncated LCG nonces** used in a signature scheme.

1. **Truncation Leakage**: The shift operation `k = state >> 32` means that $k$ represents the most significant bits of the LCG state. Specifically, $S_i = 2^{32} k_i + \delta_i$ where $0 \leq \delta_i < 2^{32}$. Thus, each nonce $k_i$ provides a very close approximation of the LCG state $S_i$.
2. **LCG State Correlation**: The LCG recurrence $S_{i+1} \equiv a S_i + b \pmod{q}$ creates a linear dependency between successive nonces and their (small) truncation errors:
   $$(2^{32} k_{i+1} + \delta_{i+1}) \equiv a (2^{32} k_i + \delta_i) + b \pmod{q}$$
3. **Combining DSA and LCG**: From the DSA equation, we know $k_i \equiv s_i^{-1}(H(m_i) + x r_i) \pmod{q}$. By substituting this into the LCG recurrence, we link the secret key $x$ to the small unknown errors $\delta_i$.
   $$2^{32} s_{i+1}^{-1}(H(m_{i+1}) + x r_{i+1}) + \delta_{i+1} \equiv a(2^{32} s_i^{-1}(H(m_i) + x r_i) + \delta_i) + b \pmod{q}$$

## Attack
1. **Equation Linearization**: Rearrange the combined DSA-LCG equation into the form $\sum \delta_j \cdot C_{i,j} + x D_i \equiv E_i \pmod{q}$, where $C, D, E$ are constants derived from known values.
2. **Lattice Construction**: The solution uses a Shortest Vector Problem (SVP) formulation. Let $K$ be a large scaling factor. The lattice basis $M$ is constructed from rows:
```python
# For each unknown error delta_j:
[0, ..., 1, ..., 0, c_{0,j}*K, c_{1,j}*K, ..., 0]

# For each modular constraint q:
[0, ..., 0, q*K, 0, ..., 0]

# For the targets/constants:
[0, ..., 0, e_0*K, e_1*K, ..., 1]
```
3. **LLL Solver**: The target vector in the lattice is $(\delta_0, \delta_1, \delta_2, 0, 0, 1)$. Since $\delta_j$ are only 32 bits, this vector is extremely short relative to the lattice volume. LLL finds this short vector, revealing the truncation errors.

4. **Key and Flag Recovery**: Solving for $\delta_i$ allows direct computation of $x$. Derive the AES key: `hashlib.sha256(str(x).encode()).digest()` and decrypt the ciphertext provided in `out.txt`.
