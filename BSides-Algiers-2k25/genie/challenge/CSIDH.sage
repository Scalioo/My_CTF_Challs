





class CSIDH :
    def __init__(self ,primes):
        self.primes = primes
        self.p = 4 * prod(self.primes) - 1
        self.Fp = GF(self.p)
        self.F = GF(self.p**2, modulus=x**2 + 1, names='i')
        self.i = self.F.gen(0)
        self.E0 = EllipticCurve(self.F, [1, 0])
        self.E0.set_order((self.p + 1)**2)

    def group_action(self , E , priv, G=None , QQ=None):
        ells = self.primes
        es = priv[:]
        while any(es):
            x = self.Fp.random_element()
            P = E.lift_x(x)
            s = 1 if P[1] in self.Fp else -1
            S = [i for i, e in enumerate(es) if sign(e) == s and e != 0]
            k = prod([ells[i] for i in S])
            Q = ((self.p + 1) // k) * P

            for i in S:
                R = (k // ells[i]) * Q
                if R.is_zero():
                    continue
                phi = E.isogeny(R)
                E = phi.codomain()
                if G and Q :
                    G , QQ = phi(G), phi(QQ)
                Q = phi(Q)
                es[i] -= s
                k //= ells[i]
        if G and QQ :
            return E, G , QQ
        return E
