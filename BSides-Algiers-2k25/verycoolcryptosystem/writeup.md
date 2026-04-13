# Very Cool Cryptosystem — BSides CTF Crypto Challenge Writeup

> **Challenge**: Very Cool Cryptosystem  
> **Author**: scalio  
> **Category**: Cryptography  
> **Difficulty**: Medium  
> **Flag**: `shellmates{CayleyPurser_without_pub_key?_grobner?_anyway_hope_u_used_the_right_monomial_ordering_isthisenough}`

---

## Table of Contents

1. [Challenge Overview](#1-challenge-overview)
2. [Cryptographic Background](#2-cryptographic-background)
   - 2.1 [Cayley-Purser — Matrix-Based Public Key Cryptography](#21-cayley-purser--matrix-based-public-key-cryptography)
   - 2.2 [Upper-Triangular Matrix Powers](#22-upper-triangular-matrix-powers)
   - 2.3 [Gröbner Bases & Polynomial System Solving](#23-gröbner-bases--polynomial-system-solving)
   - 2.4 [Monomial Orderings — Why Lex Matters](#24-monomial-orderings--why-lex-matters)
3. [Challenge Analysis](#3-challenge-analysis)
   - 3.1 [What We're Given](#31-what-were-given)
   - 3.2 [Server Logic Breakdown](#32-server-logic-breakdown)
   - 3.3 [The Fatal Vulnerability](#33-the-fatal-vulnerability)
4. [The Attack — Step by Step](#4-the-attack--step-by-step)
   - 4.1 [Step 1: Formulate the Super-Diagonal Equations](#41-step-1-formulate-the-super-diagonal-equations)
   - 4.2 [Step 2: Compute the Gröbner Basis](#42-step-2-compute-the-gröbner-basis)
   - 4.3 [Step 3: Solve for the Secret Scalar a](#43-step-3-solve-for-the-secret-scalar-a)
   - 4.4 [Step 4: Recover the Flag Bytes from m](#44-step-4-recover-the-flag-bytes-from-m)
   - 4.5 [Step 5: Reconstruct D and Decrypt](#45-step-5-reconstruct-d-and-decrypt)
5. [Deep Dive — Why Each Technique Works](#5-deep-dive--why-each-technique-works)
6. [Solution Code (Annotated)](#6-solution-code-annotated)
7. [Key Takeaways](#7-key-takeaways)

---

## 1. Challenge Overview

The challenge implements a **modified Cayley-Purser cryptosystem** — a matrix-based public-key encryption scheme. Instead of the original 2×2 design proposed by Sarah Flannery in 1999, this variant uses **4×4 upper-triangular matrices** over the ring ℤ/nℤ, where n = p·q is an RSA modulus.

The encryption script:

1. Splits the 110-character flag into two parts: `flag[:30]` and `flag[30:]`
2. Derives a **private key matrix D** from the first 30 bytes using a convoluted polynomial construction with random blinding values `b_s`
3. Generates a **Cayley-Purser public key** triplet (A, B, Dʳ) with r = 5
4. Encrypts the remaining 80 bytes of the flag into a 4×4 matrix U, then computes U' = κ · U · κ
5. Outputs the public parameters, partial private key data, and ciphertext to `out.txt`

Our goal: **recover both halves of the flag** — first the private key material (Part 1), then the encrypted message (Part 2).

The critical insight (hinted by the flag itself) is that the challenge **leaks the blinding values b_s and three super-diagonal entries of D⁵**, which reduces private key recovery to a **multivariate polynomial system** solvable by Gröbner basis computation with the correct monomial ordering.

---

## 2. Cryptographic Background

### 2.1 Cayley-Purser — Matrix-Based Public Key Cryptography

The Cayley-Purser algorithm is a public-key cryptosystem that uses **matrix multiplication over a commutative ring** instead of modular exponentiation (RSA) or discrete logarithms (DH/ElGamal).

**Setup:** Work in the General Linear Group GL(n, ℤ/Nℤ) — the set of n×n invertible matrices modulo N.

**Key Generation:**
- Choose a secret invertible matrix **D** ∈ GL(n, ℤ/Nℤ)
- Choose a random invertible matrix **A** ∈ GL(n, ℤ/Nℤ) such that D·A ≠ A·D (they don't commute)
- Compute **B = D⁻¹ · A⁻¹ · D** (conjugation of A⁻¹ by D)
- Compute **Dʳ** for some public exponent r
- **Public key**: (A, B, Dʳ)
- **Private key**: D

**Encryption (session):**
- Choose random s
- Compute γ = (Dʳ)ˢ = Dʳˢ
- Compute ε = γ⁻¹ · A · γ
- Compute κ = γ⁻¹ · B · γ
- Encipher: U' = κ · U · κ (where U encodes the plaintext)
- Send (U', ε)

**Why it's insecure (in general):** The fundamental flaw is that D commutes with all its powers. Since γ = Dʳˢ, we have D · γ = γ · D. This lets an attacker who knows D express κ purely in terms of D and the public ε, bypassing the need to know the session secret s.

In this challenge, we face an additional hurdle: the private key D itself must be recovered first — but the leaked data makes this possible via algebraic methods.

### 2.2 Upper-Triangular Matrix Powers

A crucial property exploited in this challenge: if T is an **upper-triangular matrix**, then Tʳ is also upper-triangular, and the entries follow predictable formulas.

**Diagonal entries** of Tʳ:

```
(Tʳ)ᵢᵢ = (Tᵢᵢ)ʳ
```

Each diagonal entry is simply the r-th power of the corresponding diagonal entry of T.

**Super-diagonal entries** of Tʳ (one above the diagonal):

```
                          r-1
(Tʳ)ᵢ,ᵢ₊₁ = Tᵢ,ᵢ₊₁  ·   Σ   (Tᵢᵢ)^(r-1-k) · (Tᵢ₊₁,ᵢ₊₁)^k
                          k=0
```

This is a **geometric-series-like sum** involving the two adjacent diagonal entries. When the diagonal entries are equal, this simplifies to `r · Tᵢᵢ^(r-1) · Tᵢ,ᵢ₊₁`, but in general they differ, giving the full sum shown above.

This formula is what lets us set up polynomial equations from the leaked super-diagonal values of D⁵.

### 2.3 Gröbner Bases & Polynomial System Solving

A **Gröbner basis** is a special generating set for a polynomial ideal that has favorable computational properties — analogous to row echelon form for linear systems, but for polynomial systems.

Given a system of polynomial equations:

```
f₁(x₁, …, xₘ) = 0
f₂(x₁, …, xₘ) = 0
    ⋮
fₖ(x₁, …, xₘ) = 0
```

The Gröbner basis G of the ideal I = ⟨f₁, …, fₖ⟩ is a set of polynomials that:
- Generates the same ideal (same solution set)
- Has a "reduced" structure that makes root-finding tractable
- Under lexicographic ordering, produces a **triangular system** (elimination)

**Triangular property (lex ordering):** If the system has finitely many solutions and we use lexicographic ordering with x₁ > x₂ > … > xₘ, the Gröbner basis has the shape:

```
G = { g₁(x₁, x₂, …, xₘ),  g₂(x₂, …, xₘ),  …,  gₘ(xₘ) }
```

The last polynomial `gₘ` involves only xₘ — solve it first, then back-substitute. This is exactly how Gaussian elimination works, but for nonlinear systems.

### 2.4 Monomial Orderings — Why Lex Matters

The choice of monomial ordering fundamentally affects the shape of the Gröbner basis:

| Ordering | Abbreviation | Speed | Shape | Use Case |
|----------|-------------|-------|-------|----------|
| Degree reverse lexicographic | `degrevlex` | Fast | Dense, no elimination | Fastest to compute |
| Lexicographic | `lex` | Slow | Triangular, eliminates variables | Required for solving |
| Degree lexicographic | `deglex` | Medium | Partial elimination | Rarely useful |

In this challenge, we **must** use `lex` ordering because we need the elimination structure to isolate the unknowns. The flag literally spells this out: *"hope_u_used_the_right_monomial_ordering"*.

A common strategy in practice is to compute in `degrevlex` first (faster), then convert to `lex` via the FGLM algorithm. However, for systems over ℤ/nℤ (not a field) and of moderate degree, direct `lex` computation in SageMath/Singular works acceptably.

---

## 3. Challenge Analysis

### 3.1 What We're Given

From `out.txt`:

| Value | Type | Description |
|-------|------|-------------|
| n | Integer (~200 bits) | RSA modulus p·q |
| b_s | List of 6 integers | All random blinding values used in private key construction |
| Dr[0][1], Dr[1][2], Dr[2][3] | 3 integers | Super-diagonal entries of D⁵ |
| A | 4×4 matrix | Full random public matrix A |
| eps | 4×4 matrix | ε = γ⁻¹ · A · γ (conjugated A with session key) |
| U_ | 4×4 matrix | Encrypted flag matrix U' = κ · U · κ |

**Not given:** The full public key triplet. Specifically, B and Dʳ are **not directly provided** (only three entries of Dʳ). The challenge title's irony: "Very Cool Cryptosystem" — it's cool because it doesn't even give you the full public key, yet it's still breakable.

### 3.2 Server Logic Breakdown

#### Ring & Group Setup

```python
p = random_prime(2¹⁰⁰)
q = random_prime(2¹⁰⁰)
n = p · q                    # ~200-bit RSA modulus
Rn = Zmod(n)                 # The ring ℤ/nℤ
M = GL(4, Rn)                # 4×4 invertible matrices over ℤ/nℤ
```

#### Private Key Construction (`priv_key`)

The private key matrix D is built from `flag[:30]` via several derived values:

```python
m = Rn(int.from_bytes(flag[:30], "big"))   # flag → ring element
a = Rn(randint(0, n-1))                    # random secret scalar
c = m⁶                                     # bound = 3·(3+1)/2 = 6
```

**The c_s construction** — three super-diagonal entries, each a polynomial in (m, a, b_s):

For i=0 (simplest):
```
t = 0, and since t is falsy:  o = c⁵ = m³⁰
c_s[0] = a · m³⁰ + b₀
```

For i=1 (one inner loop iteration):
```
t = 1:  o = (c + b₁)⁵ = (m⁶ + b₁)⁵
j=0:    o = o · a + b₂
c_s[1] = a · (m⁶ + b₁)⁵ + b₂
```

For i=2 (two inner loop iterations):
```
t = 3:  o = (c + b₃)⁵ = (m⁶ + b₃)⁵
j=0:    o = o · a + b₄ = a · (m⁶ + b₃)⁵ + b₄
j=1:    o = o · a + b₅ = a² · (m⁶ + b₃)⁵ + a · b₄ + b₅
c_s[2] = a² · (m⁶ + b₃)⁵ + a · b₄ + b₅
```

**The diagonal entries:**

```
diag[0] = a   + m⁶
diag[1] = a²  + m⁶
diag[2] = a³  + m⁶
diag[3] = a⁴  + m⁶
```

**Full matrix D** (upper-triangular):

```
        ┌                                                                  ┐
        │  a + m⁶      a·m³⁰ + b₀       ((b₀+b₁)·a)²⁰   ((b₀+b₁)·a)²⁰  │
   D =  │  0           a² + m⁶           c_s[1]            ((b₁+b₂)·a)²⁰  │
        │  0           0                  a³ + m⁶           c_s[2]          │
        │  0           0                  0                  a⁴ + m⁶        │
        └                                                                  ┘
```

#### Public Key Generation (`gen_pub`)

```python
r = 5
A = matrix_random()                      # random invertible 4×4
D, b_s = priv_key(flag[:30])
# Ensure D and A don't commute:
assert D · A ≠ A · D
Dr = D⁵
B = D⁻¹ · A⁻¹ · D                       # conjugation
pubkey = (A, B, Dr)
```

#### Encryption (`encrypt`)

```python
s = randint(1, 2¹⁰)                      # random session exponent
γ = Dr^s = D^(5s)                         # session key matrix
ε = γ⁻¹ · A · γ                          # conjugated A
κ = γ⁻¹ · B · γ                          # conjugated B (decryption key)
```

The remaining 80 flag bytes are packed into a 4×4 matrix U (5 bytes per entry, 16 entries), then encrypted:

```python
U' = κ · U · κ
```

#### What's Actually Written to `out.txt`

The output deliberately omits the full public key. Only **three super-diagonal entries** of Dr are revealed:

```python
for i in range(3):
    f.write(f"Dr[{i}][{i+1}] = {Dr[i][i+1]}")
```

Along with n, b_s (all 6 values), A (full), ε (full), and U' (full).

### 3.3 The Fatal Vulnerability

The challenge leaks **two things it shouldn't**:

**Leak 1: The blinding values b_s.** With all six bᵢ known, the super-diagonal entries c_s[0], c_s[1], c_s[2] become **explicit polynomial functions** of only two unknowns: the message m and the secret scalar a.

**Leak 2: Three super-diagonal entries of D⁵.** Using the closed-form formula for upper-triangular matrix powers, each leaked value gives a **polynomial equation** in m and a.

Together: **3 polynomial equations in 2 unknowns** over ℤ/nℤ. The system is overdetermined (more equations than unknowns), which makes Gröbner basis computation more tractable and guarantees a unique solution (modulo n).

Once D is recovered, the standard Cayley-Purser commutativity attack decrypts the ciphertext — regardless of the session secret s.

---

## 4. The Attack — Step by Step

### 4.1 Step 1: Formulate the Super-Diagonal Equations

Using the upper-triangular power formula with r = 5, each leaked super-diagonal value satisfies:

```
                            4
D⁵ᵢ,ᵢ₊₁ = c_s[i]  ·      Σ   (aⁱ⁺¹ + m⁶)^(4-k) · (aⁱ⁺² + m⁶)^k
                           k=0
```

We introduce two polynomial variables:
- **x** = the unknown 22 bytes of the flag (since "shellmat" = 8 bytes are known)
- **y** = the secret scalar a

And set up the ring with lex ordering:

```python
Pn.<x,y> = PolynomialRing(Zmod(n), order="lex")

known = int.from_bytes(b'shellmat', "big") << (22*8)
dbl = (known + x)⁶        # this is c = m⁶
k = 5                      # exponent r
e1 = 5                     # power used in c_s construction
```

**Equation 1** — from Dr[0][1] = M₀₁:

The super-diagonal factor is c_s[0] = y · c⁵ + b₀, and the geometric sum runs over diagonal entries (y + c) and (y² + c):

```python
f₁ = (dbl^e1 · y + b_s[0]) · Σᵢ₌₀⁴ (y + dbl)^(4-i) · (y² + dbl)^i  −  M₀₁
```

**Equation 2** — from Dr[1][2] = M₁₂:

Factor c_s[1] = y · (c + b₁)⁵ + b₂, sum over (y² + c) and (y³ + c):

```python
f₂ = (y · (dbl + b_s[1])^e1 + b_s[2]) · Σᵢ₌₀⁴ (y² + dbl)^(4-i) · (y³ + dbl)^i  −  M₁₂
```

**Equation 3** — from Dr[2][3] = M₂₃:

Factor c_s[2] = y² · (c + b₃)⁵ + y · b₄ + b₅, sum over (y³ + c) and (y⁴ + c):

```python
f₃ = (y · (y · (dbl + b_s[3])^e1 + b_s[4]) + b_s[5]) · Σᵢ₌₀⁴ (y³ + dbl)^(4-i) · (y⁴ + dbl)^i  −  M₂₃
```

### 4.2 Step 2: Compute the Gröbner Basis

```python
I = ideal(f₁, f₂, f₃)
G = I.groebner_basis()
```

Because we used **lex ordering** with x > y, the Gröbner basis produces a triangular system:

```
G[0] = g₁(x, y)     # polynomial in both variables
G[1] = g₂(y)         # univariate polynomial in y only
```

The elimination property of lex Gröbner bases automatically removes x from one of the generators, giving us a univariate polynomial that we can solve directly.

This is the step where ordering is critical — with `degrevlex`, both generators would involve both variables and we'd have no triangular structure to exploit.

### 4.3 Step 3: Solve for the Secret Scalar a

Extract G[1] as a univariate polynomial in y over ℤ/nℤ and find its roots:

```python
P2n.<y> = PolynomialRing(Zmod(n))
fa = P2n(G[1])
a = fa.roots(multiplicities=False)[0]
```

Since n is composite, root-finding over ℤ/nℤ uses the Chinese Remainder Theorem internally — SageMath factors n (or solves modulo p and q separately if n is an RSA modulus). The roots exist and are unique because the system is overdetermined.

### 4.4 Step 4: Recover the Flag Bytes from m

Substitute the recovered value of a into G[0] to get a univariate polynomial in x:

```python
P2n.<x> = PolynomialRing(Zmod(n))
fm = P2n(G[0](x, a))
m_candidates = fm.roots(multiplicities=False)
```

Filter for the root that decodes to valid ASCII:

```python
m = b''
for candidate in m_candidates:
    raw = long_to_bytes(int(candidate))
    if raw.decode('ascii', errors='strict'):
        m = raw
        break
```

This gives us the unknown 22 bytes: `es{CayleyPurser_withou`

Prepending the known prefix:

```
flag[:30] = b"shellmat" + m = "shellmates{CayleyPurser_withou"
```

### 4.5 Step 5: Reconstruct D and Decrypt

Now that we have both `a` and the full 30-byte flag prefix, we can exactly reconstruct the private key matrix D by re-running `priv_key`:

```python
D, b_s = priv_key(flag[:30])
```

**The commutativity exploit:**

Since D commutes with γ = D⁵ˢ (they are both powers of D), we can express the decryption key purely in terms of D and the public ε:

```
κ = γ⁻¹ · B · γ
  = γ⁻¹ · D⁻¹ · A⁻¹ · D · γ          (definition of B)
  = D⁻¹ · γ⁻¹ · A⁻¹ · γ · D          (D and γ commute)
  = D⁻¹ · (γ⁻¹ · A · γ)⁻¹ · D        (matrix inverse of conjugation)
  = D⁻¹ · ε⁻¹ · D                     (definition of ε)
```

Therefore:

```
κ⁻¹ = D⁻¹ · ε · D
```

And since U' = κ · U · κ:

```
U = κ⁻¹ · U' · κ⁻¹
```

In code:

```python
lam = D⁻¹ · ε · D          # this is κ⁻¹
U = lam · U' · lam          # decrypt
```

Each of the 16 entries of U encodes 5 bytes of `flag[30:]`. Concatenating them:

```
flag[30:] = "t_pub_key?_grobner?_anyway_hope_u_used_the_right_monomial_ordering_isthisenough}"
```

Full flag:

```
shellmates{CayleyPurser_without_pub_key?_grobner?_anyway_hope_u_used_the_right_monomial_ordering_isthisenough}
```

---

## 5. Deep Dive — Why Each Technique Works

### Why the b_s Leak Is Fatal

In a properly designed system, the blinding values bᵢ would be **secret**. They serve to make the c_s[i] entries appear random — even to someone who knows factors of n.

But with b_s public, each c_s[i] becomes a **known polynomial** in just two unknowns (m, a). This collapses the algebraic complexity from "16 unknown matrix entries" to "2 scalar unknowns" — a dramatic reduction that makes the system tractable for Gröbner basis methods.

Without the b_s leak, an attacker would face 2 unknowns + 6 unknown blinding values = 8 unknowns with only 3 equations — an underdetermined system with no unique solution.

### Why Upper-Triangular Structure Matters

If D were a dense random 4×4 matrix, D⁵ would also be dense, and the three super-diagonal entries would be complicated functions of all 16 entries of D. The resulting polynomial system would have 16 unknowns — completely intractable for Gröbner basis methods.

The upper-triangular structure guarantees:
- D⁵ is also upper-triangular
- The super-diagonal of D⁵ depends only on the **diagonal and super-diagonal** of D
- The diagonal entries are simple functions of a and c = m⁶
- The super-diagonal entries are simple functions of a, m, and b_s

This reduces 16 matrix unknowns to exactly 2 scalar unknowns.

### Why Lex Ordering Gives a Triangular System

The **Elimination Theorem** in computational algebra states:

> If G is a Gröbner basis for an ideal I ⊂ k[x₁, …, xₘ] with respect to lexicographic ordering (x₁ > x₂ > … > xₘ), then G ∩ k[xₖ, …, xₘ] is a Gröbner basis for I ∩ k[xₖ, …, xₘ].

In plain terms: lex Gröbner bases **automatically eliminate variables**. If the system has finitely many solutions (zero-dimensional ideal), the basis will contain a univariate polynomial in the "last" variable — exactly what we need for the back-substitution strategy.

Other orderings (like `degrevlex`) produce generators that are shorter to compute but mix all variables together, offering no elimination structure.

### Why D Commuting with γ Breaks Everything

This is the **fundamental flaw** of all Cayley-Purser variants. The security of the scheme relies on the difficulty of recovering D from the public key (A, B, Dʳ). But once D is known, the session key γ = Dʳˢ becomes irrelevant because:

```
D · γ = D · D^(rs) = D^(rs+1) = D^(rs) · D = γ · D
```

This commutativity lets us "slide" D past γ in any expression, eliminating the unknown exponent s entirely. The decryption key κ = γ⁻¹ · B · γ simplifies to D⁻¹ · ε⁻¹ · D — a function of only known quantities.

In the original 2×2 Cayley-Purser, this flaw was worse: D could be recovered from the public key alone using simple linear algebra (Flannery's attack). Here, recovering D requires the additional leaked data (b_s and Dr super-diagonal), but once obtained, the same commutativity collapse applies.

### Why Root-Finding Works over ℤ/nℤ

Finding roots of a polynomial over ℤ/nℤ (where n = p·q is composite) is generally as hard as factoring n. However, SageMath's `roots()` function over `Zmod(n)` attempts to factor n first (for small moduli) or uses Hensel lifting.

In this challenge, n is ~200 bits (two 100-bit primes), which is small enough that SageMath can factor it and solve modulo p and q separately, then combine with CRT. If n were larger (e.g., 2048 bits), this step would fail — the challenge's choice of small primes is intentional.

---

## 6. Solution Code (Annotated)

```python
from Crypto.Util.number import long_to_bytes

# ──────────────────────────────────────────────
# Step 0: Parse output
# ──────────────────────────────────────────────

lines = open("../dist/out.txt", 'r').readlines()

n     = int(lines[0].split('=')[1].strip())
b_s   = eval(lines[1].split('=')[1].strip())
M_0_1 = int(lines[2].split('=')[1].strip())     # Dr[0][1]
M_1_2 = int(lines[3].split('=')[1].strip())     # Dr[1][2]
M_2_3 = int(lines[4].split('=')[1].strip())     # Dr[2][3]
A     = eval(lines[5].split('=')[1].strip())     # Full 4x4 matrix A
eps   = eval(lines[6].split('=')[1].strip())     # Full 4x4 matrix ε
U_    = eval(lines[7].split('=')[1].strip())     # Full 4x4 matrix U'


# ──────────────────────────────────────────────
# Step 1: Set up the polynomial system
# ──────────────────────────────────────────────

# Multivariate ring over ℤ/nℤ with LEX ordering (critical!)
Pn.<x,y> = PolynomialRing(Zmod(n), order="lex")

# Known flag prefix: "shellmat" (8 bytes), unknown: 22 bytes
known = int.from_bytes(b'shellmat', "big") << (22*8)

# c = m⁶ where m = known_prefix + unknown_suffix
dbl = (known + x) ^ 6
k = 5       # r = 5 (the matrix power exponent)
e1 = 5      # power used in c_s construction

# Equation 1: from Dr[0][1]
#   c_s[0] = y · c⁵ + b₀
#   sum = Σ (y + c)^(4-i) · (y² + c)^i for i in 0..4
fp = ((dbl**e1 * y + b_s[0])
      * sum([(y + dbl)**(k-1-i) * ((y**2) + dbl)**i
             for i in range(k)])
     ) - M_0_1

# Equation 2: from Dr[1][2]
#   c_s[1] = y · (c + b₁)⁵ + b₂
#   sum = Σ (y² + c)^(4-i) · (y³ + c)^i for i in 0..4
fpp = ((y * (dbl + b_s[1])**e1 + b_s[2])
       * sum([((y**2) + dbl)**(k-1-i) * ((y**3) + dbl)**i
              for i in range(k)])
      ) - M_1_2

# Equation 3: from Dr[2][3]
#   c_s[2] = y² · (c + b₃)⁵ + y · b₄ + b₅
#   sum = Σ (y³ + c)^(4-i) · (y⁴ + c)^i for i in 0..4
fppp = ((y * (y * (dbl + b_s[3])**e1 + b_s[4]) + b_s[5])
        * sum([((y**3) + dbl)**(k-1-i) * ((y**4) + dbl)**i
               for i in range(k)])
       ) - M_2_3


# ──────────────────────────────────────────────
# Step 2: Compute Gröbner basis
# ──────────────────────────────────────────────

# 3 equations, 2 unknowns → overdetermined
# Lex ordering → triangular system: G[0](x,y), G[1](y)
I = ideal(fp, fpp, fppp)
G = I.groebner_basis()


# ──────────────────────────────────────────────
# Step 3: Solve for 'a' (secret scalar)
# ──────────────────────────────────────────────

P2n.<y> = PolynomialRing(Zmod(n))
fa = P2n(G[1])                            # univariate in y
a = fa.roots(multiplicities=False)[0]      # the secret scalar

print(f"Recovered a = {a}")


# ──────────────────────────────────────────────
# Step 4: Solve for unknown flag bytes
# ──────────────────────────────────────────────

P2n.<x> = PolynomialRing(Zmod(n))
fm = P2n(G[0](x, a))                      # substitute a, get univariate in x
m_s = fm.roots(multiplicities=False)

m = b''
for i in m_s:
    try:
        candidate = long_to_bytes(int(i))
        if candidate.decode().isascii():
            print(f"Recovered suffix: {candidate}")
            m = candidate
    except:
        continue

flag = b'shellmat' + m
print(f"flag[:30] = {flag}")


# ──────────────────────────────────────────────
# Step 5: Reconstruct D and decrypt
# ──────────────────────────────────────────────

Rn = Zmod(n)
SIZE = 4
M = GL(SIZE, Rn)

# Re-run priv_key with recovered flag[:30] to get D
def priv_key(flag1):
    m = Rn(int.from_bytes(flag1, "big"))
    coeffs = SIZE - 1
    bound = coeffs * (coeffs + 1) // 2
    c = m ** bound
    c_s = []
    for i in range(coeffs):
        t = i * (i + 1) // 2
        o = ((c + b_s[t]) if t else c) ** 5
        if not i:
            c_s.append((a * o + b_s[t]))
            continue
        for j in range(0, i):
            o *= a
            o += b_s[t + j + 1]
        c_s.append(o)
    diag = [a**i + c for i in range(1, 5)]
    Mat = Matrix(Rn, [
        i * [0] + [diag[i]]
        + ([c_s[i]] if i < len(c_s) else [])
        + (2-i) * [((b_s[i] + b_s[i+1]) * a)**20]
        for i in range(4)
    ])
    return M(Mat), b_s

D, b_s = priv_key(flag)
eps = M(eps)
U_ = M(U_)

# Verify: check that our D⁵ matches the leaked super-diagonal
Dr = D^k                          # D⁵
Dr = Dr.list()
assert Dr[0][1] == M_0_1, "Dr[0][1] mismatch!"
assert Dr[1][2] == M_1_2, "Dr[1][2] mismatch!"
assert Dr[2][3] == M_2_3, "Dr[2][3] mismatch!"
print("✓ All super-diagonal entries verified")

# Decrypt using the commutativity exploit:
#   κ⁻¹ = D⁻¹ · ε · D
#   U  = κ⁻¹ · U' · κ⁻¹
lam = ~D * eps * D                 # κ⁻¹
U = lam * U_ * lam                 # decrypted plaintext matrix

# Extract flag bytes from all 16 matrix entries
for u in U.list():
    for entry in u:
        flag += long_to_bytes(int(entry))

print(f"\n🏁 Flag: {flag.decode()}")
# → shellmates{CayleyPurser_without_pub_key?_grobner?_anyway_hope_u_used_the_right_monomial_ordering_isthisenough}
```

---

## 7. Key Takeaways

| Aspect | Detail |
|--------|--------|
| **Vulnerability** | Leaking b_s values + super-diagonal of D⁵ reduces key recovery to a polynomial system |
| **Attack primitive 1** | Upper-triangular matrix power formula → polynomial equations in (m, a) |
| **Attack primitive 2** | Gröbner basis with lex ordering → triangular system → back-substitution |
| **Attack primitive 3** | Cayley-Purser commutativity → κ⁻¹ = D⁻¹ · ε · D (no session secret needed) |
| **Root cause** | Exposing internal randomness (b_s) that was meant to obscure the key derivation |
| **Crypto lesson** | Never leak auxiliary randomness used during key construction — it turns algebraic hardness into a solvable system |
| **Fix** | Keep b_s secret, don't reveal partial entries of D⁵, or abandon Cayley-Purser entirely (known to be broken) |

### Why "Very Cool Cryptosystem"?

The irony is multi-layered. The Cayley-Purser scheme was "very cool" when proposed — a teenager's invention that briefly seemed competitive with RSA. But it was broken almost immediately due to the commutativity flaw. This challenge recreates that history: a system that looks impressive on the surface (4×4 matrices! polynomial key derivation! blinding values!) but crumbles the moment you apply the right algebraic tools. The flag itself is the ultimate hint: *"CayleyPurser_without_pub_key? gröbner? anyway_hope_u_used_the_right_monomial_ordering"* — telling you exactly what you need to know, if you know where to look.

---

*Challenge by scalio — BSides CTF*
