# Genie — BSides CTF Crypto Challenge Writeup

> **Challenge**: Genie  
> **Author**: scalio  
> **Category**: Cryptography  
> **Difficulty**: Hard  
> **Flag**: `shellmates{Weil_Pairing_and_Frobenius_u_get_torsion_group_Kernel_Sign}`

---

## Table of Contents

1. [Challenge Overview](#1-challenge-overview)
2. [Cryptographic Background](#2-cryptographic-background)
   - 2.1 [CSIDH — The Isogeny Group Action](#21-csidh--the-isogeny-group-action)
   - 2.2 [CSI-FiSh — Signature Scheme](#22-csi-fish--signature-scheme)
   - 2.3 [Frobenius Endomorphism & Eigenspaces](#23-frobenius-endomorphism--eigenspaces)
   - 2.4 [The Weil Pairing](#24-the-weil-pairing)
3. [Challenge Analysis](#3-challenge-analysis)
   - 3.1 [What We're Given](#31-what-were-given)
   - 3.2 [Server Logic Breakdown](#32-server-logic-breakdown)
   - 3.3 [The Fatal Vulnerability](#33-the-fatal-vulnerability)
4. [The Attack — Step by Step](#4-the-attack--step-by-step)
   - 4.1 [Step 1: Reconstruct Curves from Points](#41-step-1-reconstruct-curves-from-points)
   - 4.2 [Step 2: Determine Kernel Signs via Frobenius](#42-step-2-determine-kernel-signs-via-frobenius)
   - 4.3 [Step 3: Detect Subgroup Collapse via Weil Pairing](#43-step-3-detect-subgroup-collapse-via-weil-pairing)
   - 4.4 [Step 4: Reconstruct Full Secret Key](#44-step-4-reconstruct-full-secret-key)
   - 4.5 [Step 5: Decrypt the Flag](#45-step-5-decrypt-the-flag)
5. [Deep Dive — Why Each Technique Works](#5-deep-dive--why-each-technique-works)
6. [Solution Code (Annotated)](#6-solution-code-annotated)
7. [Key Takeaways](#7-key-takeaways)

---

## 1. Challenge Overview

The challenge implements a **CSI-FiSh-like signature scheme** built on top of **CSIDH** (Commutative Supersingular Isogeny Diffie-Hellman). The server:

1. Generates a secret key — a list of 16 exponent vectors over 74 small primes
2. Computes the corresponding public key — 16 curves plus **two tracked torsion points on each curve**
3. Signs a random message using the CSI-FiSh protocol
4. Encrypts the flag with `AES-CBC` using the SHA-256 hash of the secret key
5. Outputs everything to `out.txt`

Our goal: **recover the secret key from the public data and decrypt the flag**.

The critical insight (hinted by the flag itself) is that the public key **leaks torsion point images**, which enables us to recover the **Frobenius eigenvalue** at each prime — revealing the **kernel direction (sign)** of every isogeny step. Combined with the structured secret key format, this fully recovers `SK`.

---

## 2. Cryptographic Background

### 2.1 CSIDH — The Isogeny Group Action

CSIDH works over a **supersingular elliptic curve** defined over **𝔽ₚ** where:

```
p = 4 · ℓ₁ · ℓ₂ · … · ℓₙ − 1
```

is prime, and each `ℓᵢ` is a small prime. In this challenge:

```python
primes = [3, 5, 7, ..., 373, 587]  # 74 small primes
p = 4 * prod(primes) - 1
```

The starting curve is **E₀: y² = x³ + x** over **𝔽ₚ²** (with `𝔽ₚ² = 𝔽ₚ[i]/(i²+1)`). This curve has order **(p+1)²**.

A **secret key** is a vector **e = (e₁, …, eₙ) ∈ ℤⁿ**. The **group action** applies a chain of `ℓᵢ`-isogenies to compute:

```
E' = [𝔩₁]^e₁ · [𝔩₂]^e₂ · … · [𝔩ₙ]^eₙ ⋆ E₀
```

Each positive/negative exponent `eᵢ` selects which of the two possible `ℓᵢ`-isogeny kernels to use — and that choice is determined by the **sign** of `eᵢ`.

### 2.2 CSI-FiSh — Signature Scheme

CSI-FiSh is an isogeny-based signature scheme that works as follows:

**Key Generation:**
- Sample a random integer `a mod h` (class number)
- Use lattice reduction (Babai nearest plane + DLW refinement on the relation lattice) to convert `a` into a short exponent vector **e**
- Compute `S = 16` public key curves: `SK[0] = 0`, `SK[1] = e`, and `SK[k] = SK[k-1] + direction`
- Each public key entry is computed via the CSIDH group action

**Signing (Fiat-Shamir):**
1. Sample ephemeral random vectors **bⱼ**, compute commitment curves
2. Hash commitments + message → challenge indices `cⱼ ∈ {1, …, S-1}`
3. Compute responses: `rⱼ = bⱼ − SK[cⱼ]`

**The challenge's `compute_responses` has a critical twist**: it adds random noise `random.randint(-e, e)` with `e=4` to the responses. This means the signature itself cannot directly leak exponents — the attack must target the **public key structure** instead.

### 2.3 Frobenius Endomorphism & Eigenspaces

The **Frobenius endomorphism** on `E/𝔽ₚ²` is:

```
π: (x, y) ↦ (xᵖ, yᵖ)
```

For our supersingular curve over `𝔽ₚ²`, the Frobenius satisfies `π² = [-1]` (or `π² = [1]` depending on the model). This means `π` has eigenvalues **+1** and **−1** on the `ℓ`-torsion:

```
E[ℓ] = E[ℓ]⁺ ⊕ E[ℓ]⁻
```

where:
- **E[ℓ]⁺ = { R : π(R) = R }** — points fixed by Frobenius (defined over `𝔽ₚ`)
- **E[ℓ]⁻ = { R : π(R) = −R }** — points negated by Frobenius

Each eigenspace is a cyclic group of order `ℓ`, and they correspond to the **two possible `ℓ`-isogeny directions** in CSIDH.

### 2.4 The Weil Pairing

The **Weil pairing** is a bilinear map:

```
eℓ : E[ℓ] × E[ℓ] → μℓ
```

Key property: `eℓ(P, Q) = 1` if and only if `P` and `Q` generate the **same cyclic subgroup** of `E[ℓ]` (i.e., one is a scalar multiple of the other).

In the attack, we use this to determine when two points `P, Q` projected to the `ℓ`-torsion land in the **same eigenspace** — meaning the isogeny did not change the structure at prime `ℓ` — versus when they separate, indicating the isogeny kernel passed through that prime and the exponent is no longer incrementing.

---

## 3. Challenge Analysis

### 3.1 What We're Given

From `out.txt`:
- **Points_list**: 16 pairs of points `(Pₖ, Qₖ)`, one pair per public key curve
- **Params**: `n = 74`, `S = 16`
- **Random message** (hex)
- **Signature**: challenge indices `c` and response vectors `r`
- **Hex result**: `IV ‖ AES-CBC(flag)` encrypted under `SHA256(str(SK))`

### 3.2 Server Logic Breakdown

#### Secret Key Structure (`_gen_secret_key`)

```python
SK[0] = [0, 0, ..., 0]              # zero vector (74 components)
SK[1] = vec                          # random short vector from lattice reduction
quick  = [-sign(e) for e in vec]     # direction: -1, 0, or +1 per component
SK[k]  = SK[k-1] + quick            # each step adds the direction vector
```

This means:
- If `vec[i] > 0`: `quick[i] = -1`, so `SK[k][i]` **decreases** by 1 each step
- If `vec[i] < 0`: `quick[i] = +1`, so `SK[k][i]` **increases** by 1 each step (toward 0)
- If `vec[i] == 0`: `quick[i] = 0`, the component stays at 0

The exponents walk from `SK[1]` toward zero over `S-2 = 14` additional steps. This means:
- The **sign** of each component is constant across all `SK[k]` (for `k >= 1`)
- The **magnitude** decreases by 1 per step until it hits zero, then stays at zero

#### Public Key Construction (`_gen_public_key`)

```python
for sk in SK:
    pk_curve, P, PP = csidh.group_action(E0, sk, Q1, Q2)
    PK.append((pk_curve, P, PP))
```

The group action is modified to also **push forward two generator-like points** `Q₁, Q₂` through the entire isogeny chain. The pushed-forward points `(Pₖ, Qₖ)` are published as the public key.

**This is the vulnerability.** Standard CSIDH/CSI-FiSh public keys only reveal the j-invariant (or the curve). Here, the scheme leaks **specific points on each curve** — points that carry torsion structure inherited from `E₀`.

#### Encryption

```python
key = SHA256(str(SK))
AES-CBC(flag, key, random_iv)
```

We need to recover `SK` exactly (as a Python string) to derive the AES key.

### 3.3 The Fatal Vulnerability

The public key leaks **pushed-forward torsion points** `(Pₖ, Qₖ)` on each curve `Eₖ`. These points retain their torsion orders from `E₀`, so for each small prime `ℓᵢ`:

1. We can project to the `ℓᵢ`-torsion: `R = ((p+1) / ℓᵢ) · Pₖ`
2. We can compute the **Frobenius eigenvalue** of `R` — telling us which eigenspace it sits in
3. We can use the **Weil pairing** to test if `Pₖ` and `Qₖ` land in the same `ℓᵢ`-torsion subgroup — telling us whether the isogeny at `ℓᵢ` has been "used up" (exponent hit zero)

By comparing across the 16 public key entries, we can recover every component of the secret key.

---

## 4. The Attack — Step by Step

### 4.1 Step 1: Reconstruct Curves from Points

We receive pairs of points `(Pₖ, Qₖ)` but not the curve equations. Since both points lie on the same curve `y² = x³ + ax + b`, we can recover `(a, b)` by solving:

```
y₁² = x₁³ + a·x₁ + b
y₂² = x₂³ + a·x₂ + b
```

Subtracting:

```
a = (y₁² − y₂² − (x₁³ − x₂³)) / (x₁ − x₂)
b = y₁² − x₁³ − a·x₁
```

```python
def get_curve(P, PP):
    x1, y1 = F(P[0]), F(P[1])
    x2, y2 = F(PP[0]), F(PP[1])
    a = (y1^2 - y2^2 - (x1^3 - x2^3)) / (x1 - x2)
    b = y1^2 - x1^3 - a*x1
    E = EllipticCurve(F, [a, b])
    return E(x1, y1), E(x2, y2)
```

### 4.2 Step 2: Determine Kernel Signs via Frobenius

For each curve's points and each small prime `ℓᵢ`, compute:

```
R = ((p+1) / ℓᵢ) · Pₖ
```

If `R ≠ 𝒪` (the point at infinity), then `R` has order `ℓᵢ` and lives in one of the two Frobenius eigenspaces. Check:

```
π(R) = (xᵣᵖ, yᵣᵖ)  =?  ±R
```

```python
def kernel_sign(R1, R2, p, ell):
    R = ((p+1) // ell) * R1
    if R.is_zero():
        R = ((p+1) // ell) * R2   # fallback to second point
    x, y = R.xy()
    FrobR = R.curve()(x^p, y^p)
    if FrobR == R:
        return -1    # lies in the +1 eigenspace -> sign convention: -1
    elif FrobR == -R:
        return +1    # lies in the -1 eigenspace -> sign convention: +1
    else:
        return None  # shouldn't happen for ℓ-torsion points
```

The sign convention (`+1` / `-1`) matches the CSIDH group action implementation:
- When a point has `y ∈ 𝔽ₚ` (Frobenius fixes it), the CSIDH code sets `s = +1` and processes primes with the same sign
- This maps to the eigenspace direction for the isogeny kernel

### 4.3 Step 3: Detect Subgroup Collapse via Weil Pairing

We need to know not just the **direction** but also the **magnitude** of each exponent. The key observation is:

> When `SK[k][i] = 0`, the `ℓᵢ`-isogeny is not applied, and the two pushed-forward points remain in **the same `ℓᵢ`-torsion subgroup**.

We test this with the Weil pairing:

```python
def same_subgroup(P, Q, ell):
    P_ell = ((p+1) // ell) * P
    Q_ell = ((p+1) // ell) * Q
    e = P_ell.weil_pairing(Q_ell, ell)
    return e == 1  # trivial pairing <-> same cyclic subgroup
```

**Interpretation:**
- If `eℓ(Pₖ, Qₖ) = 1`: Both points are in the same `ℓ`-torsion eigenspace. The isogeny at `ℓ` has been applied (exponent is nonzero) — **accumulate the sign**.
- If `eℓ(Pₖ, Qₖ) ≠ 1`: The points span different eigenspaces. The exponent at `ℓ` is zero for this SK entry — **stop counting**.

### 4.4 Step 4: Reconstruct Full Secret Key

```python
def get_secret_key(Points):
    tested = [get_curve(P, PP) for P, PP in Points]
    sk = [[0, False] for _ in range(74)]
    
    for i in range(74):
        for pair in tested[1:]:     # skip SK[0] = zero vector
            P, PP = pair
            if sk[i][1]:            # already hit zero, stop
                continue
            if same_subgroup(P, PP, primes[i]):
                # Isogeny active at this prime -> accumulate sign
                sk[i][0] += kernel_sign(P, PP, p, primes[i])
            else:
                # Exponent has hit zero -> mark as done
                sk[i][1] = True
    
    return sk
```

This walks through `SK[1]` through `SK[15]` and accumulates the Frobenius sign for each prime. Since each step changes the exponent by `±1`, the total accumulated sign gives us `SK[1][i]`. Once the exponent hits zero (detected by Weil pairing), we stop counting.

From `SK[1]`, we reconstruct all other `SK[k]` using the known structure:

```python
def get_SK(vec):
    SK = [[0] * 74]       # SK[0]
    SK.append(vec)         # SK[1]
    quick = [-sign(a) for a in vec]
    for _ in range(S - 2):
        vec = [vec[i] + quick[i] for i in range(74)]
        SK.append(vec)
    return SK
```

### 4.5 Step 5: Decrypt the Flag

```python
key = hashlib.sha256(str(SK).encode()).digest()
iv, ct = hex_result[:16], hex_result[16:]
cipher = AES.new(key, AES.MODE_CBC, iv)
flag = cipher.decrypt(ct)
```

---

## 5. Deep Dive — Why Each Technique Works

### Why Frobenius Reveals the Isogeny Direction

In CSIDH, the group action code distinguishes the two possible `ℓ`-isogeny directions by checking whether a random point's y-coordinate lies in `𝔽ₚ` or not:

```python
s = 1 if P[1] in Fp else -1
S = [i for i, e in enumerate(es) if sign(e) == s and e != 0]
```

A point with `y ∈ 𝔽ₚ` satisfies `Frob(P) = P` (since `yᵖ = y` in `𝔽ₚ`). So:
- Points in the **+1 eigenspace** (Frobenius-fixed) get paired with positive exponents
- Points in the **−1 eigenspace** (Frobenius-negated) get paired with negative exponents

When we compute `kernel_sign`, we're directly reading this eigenspace alignment from the pushed-forward torsion point.

### Why the Weil Pairing Detects Zero Exponents

Before any isogeny, `Q₁` and `Q₂` are generators of `E₀` — they span both eigenspaces. When an `ℓ`-isogeny is applied through one eigenspace:
- Points in the **kernel eigenspace** collapse (mapped to the identity)
- Points in the **other eigenspace** survive

After the isogeny, both pushed-forward points will lie in the **same eigenspace** at that prime — so their Weil pairing is trivial (= 1).

But if `eᵢ = 0` at some point, no `ℓᵢ`-isogeny is applied. The two points continue to span both eigenspaces at `ℓᵢ`, giving a **non-trivial** Weil pairing.

So: trivial pairing → isogeny was applied → exponent is nonzero.  
Non-trivial pairing → no isogeny → exponent has reached zero.

### Why the Structured SK Makes This a Full Break

The secret key isn't a single random vector — it's a **linear walk**:

```
SK[k] = SK[1] − (k−1) · sign(SK[1])
```

This means each component decreases in magnitude by 1 per step. By scanning through the 15 non-zero SK entries, we observe exactly when each component hits zero, giving us the **absolute value**. Combined with the Frobenius sign, we recover `SK[1]` completely — and from it, all of `SK`.

---

## 6. Solution Code (Annotated)

```python
from hashlib import shake_256
import hashlib
from Crypto.Cipher import AES

load("HKZbasis.sage")  # relation_basis, cn
load("CSIDH.sage")     # CSIDH class

primes = [3, 5, 7, ..., 587]  # 74 primes
p = 4 * prod(primes) - 1
F.<i> = GF(p^2, modulus=x^2 + 1)
S = 16
csidh = CSIDH(primes)

# -- Step 1: Parse output and reconstruct curves --
Points = [...]  # parsed from out.txt

def get_curve(P, PP):
    """Recover curve E and lift points onto it from raw coordinates."""
    x1, y1 = F(P[0]), F(P[1])
    x2, y2 = F(PP[0]), F(PP[1])
    a = (y1^2 - y2^2 - (x1^3 - x2^3)) / (x1 - x2)
    b = y1^2 - x1^3 - a*x1
    E = EllipticCurve(F, [a, b])
    return E(x1, y1), E(x2, y2)

# -- Step 2: Frobenius eigenvalue detection --
def kernel_sign(R1, R2, p, ell):
    """Determine the isogeny direction at prime ell via Frobenius."""
    R = ((p+1)//ell) * R1
    if R.is_zero():
        R = ((p+1)//ell) * R2
    x, y = R.xy()
    FrobR = R.curve()(x^p, y^p)
    if FrobR == R:    return -1
    elif FrobR == -R: return +1
    else:             return None

# -- Step 3: Weil pairing subgroup test --
def same_subgroup(P, Q, ell):
    """Check if P and Q lie in the same ell-torsion subgroup."""
    return ((p+1)//ell * P).weil_pairing((p+1)//ell * Q, ell) == 1

# -- Step 4: Full secret key recovery --
def get_secret_key(Points):
    tested = [get_curve(Pt[0], Pt[1]) for Pt in Points]
    sk = [[0, False] for _ in range(74)]
    for i in range(74):
        for pair in tested[1:]:
            P, PP = pair
            if sk[i][1]: continue
            if same_subgroup(P, PP, primes[i]):
                sk[i][0] += kernel_sign(P, PP, p, primes[i])
            else:
                sk[i][1] = True
    return sk

sk = get_secret_key(Points)
vec = [sk[i][0] for i in range(74)]

# -- Expand SK[1] into full SK --
SK = [[0]*74]
SK.append(vec)
quick = [-sign(a) for a in vec]
for _ in range(S - 2):
    vec = [vec[i] + quick[i] for i in range(74)]
    SK.append(vec)

# -- Step 5: Decrypt flag --
enc = bytes.fromhex('b646481492a21bd7...')  # from out.txt
iv, ct = enc[:16], enc[16:]
key = hashlib.sha256(str(SK).encode()).digest()
flag = AES.new(key, AES.MODE_CBC, iv).decrypt(ct)
print(flag)
# -> shellmates{Weil_Pairing_and_Frobenius_u_get_torsion_group_Kernel_Sign}
```

---

## 7. Key Takeaways

| Aspect | Detail |
|--------|--------|
| **Vulnerability** | Public key leaks torsion point images, not just j-invariants |
| **Attack primitive 1** | Frobenius eigenvalue → isogeny kernel direction (sign) |
| **Attack primitive 2** | Weil pairing → subgroup membership → exponent magnitude |
| **Root cause** | The `group_action` function pushes forward two generators and publishes them |
| **Crypto lesson** | In isogeny-based schemes, revealing **any** torsion structure beyond the curve itself can be catastrophic |
| **Fix** | Only publish the curve (or its j-invariant) — never auxiliary points |

### Why "Genie"?

Once the torsion points are out of the bottle, you can't put them back. The challenge name is a nod to the fact that this information leak — like a genie — grants wishes (full key recovery) that the scheme designer never intended.

---

*Challenge by scalio — BSides CTF*
