# Not so Harsh - Writeup

## Metadata
| Property | Value |
|----------|-------|
| **Name** | Not so Harsh |
| **Difficulty** | medium |
| **Description** | My new signature scheme extension is so secure that I even hid the flag inside the signature verification process! Can you retrieve it? |
| **Flag** | `Cybears{was_meant_to_be_extended_hnp_but_iwas_too_lazy}` |

## Challenge Description
The challenge presents a server implementing a custom signature scheme derived from DSA. The user has 21 interacting attempts to either:
1. **Sign a message**: The server generates a random 32-byte message and signs it using the private key $x$.
2. **Verify a message**: The server provides a random message, and the user must provide a valid signature $[[r_0, r_1, r_2], s]$ to get the flag.

The signature is computed as:
$$s \equiv k_0^{-1}(H(m)r_0 + x r_1 r_2) \pmod{q}$$
where $k_0, k_1, k_2$ are nonces and $r_i$ are their respective points mapped to the scalar field.

## Vulnerability
The security of this scheme is fundamentally broken by the **nonce generation method** and the resulting **[Hidden Number Problem (HNP)](https://eprint.iacr.org/2019/023.pdf)**.

1. **Short Nonce Leakage**: The nonces $k_i$ are generated as `int(hashlib.sha3_224(...).hexdigest(), 16)`. Since SHA3-224 output is exactly 224 bits, and the group order $q$ is a 256-bit prime, every nonce $k_i$ is significantly smaller than $q$ ($k_i < 2^{224}$ while $q \approx 2^{256}$). This means the top 32 bits of every nonce are always zero.
2. **Linearization of the Signature Equation**: Multiplying the signature equation by $k_0$ and rearranging gives:
   $$s \cdot k_0 \equiv H(m)r_0 + x r_1 r_2 \pmod{q}$$
   Dividing by $s$:
   $$k_0 \equiv s^{-1} H(m) r_0 + x (s^{-1} r_1 r_2) \pmod{q}$$
3. **[Hidden Number Problem (HNP)](https://eprint.iacr.org/2019/023.pdf)**: Let $a_i \equiv s^{-1} r_1 r_2 \pmod{q}$ and $b_i \equiv s^{-1} H(m) r_0 \pmod{q}$. The equation becomes:
   $$k_i \equiv x a_i + b_i \pmod{q}$$
   Since we know $k_i$ is "short" (bounded by $2^{224}$), this is a textbook HNP.

## Attack
1. **Signature Harvesting**: Collect $\approx 14$ signatures. For each, extract $r_0, r_1, r_2, s$ and calculate the message hash $H(m)$.
2. **Lattice Construction**: We aim to find the secret $x$ and the small nonces $k_i$. The solution script uses the following lattice construction (where $n=q$, $B=2^{224}$, $ts_i = a_i$, $as_i = b_i$):
```python
matrix = [
    [n,  0, ..., 0,   0,   0],
    [0,  n, ..., 0,   0,   0],
    ...
    [ts1, ts2, ..., tsn, B/n, 0],
    [as1, as2, ..., asn, 0,   B]
]
```
3. **LLL Recovery**: Applying LLL on this basis over $QQ$ recovers a short vector. Specifically, the private key $x$ is retrieved from the second to last column of the reduced basis row that satisfies the bound conditions.

4. **Forgery**: With $x$ recovered, generate a valid signature for the server's verification challenge to obtain the flag.

## References
- [Revisiting the Hidden Number Problem: Optimal Lattice-Based Attacks](https://eprint.iacr.org/2019/023.pdf) (Albrecht et al., 2019)

