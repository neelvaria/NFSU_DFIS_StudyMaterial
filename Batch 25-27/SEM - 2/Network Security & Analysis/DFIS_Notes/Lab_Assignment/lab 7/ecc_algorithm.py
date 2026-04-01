# ── ECC (Elliptic Curve Cryptography) ──────────────────────
import random

# Curve: y² ≡ x³ - 3x + 3  (mod 61),  order = 73 (prime)
p, a, b, order = 61, 58, 3, 73   # a = -3 mod 61 = 58

def add(P, Q):
    if P is None: return Q
    if Q is None: return P
    if P[0] == Q[0] and (P[1] + Q[1]) % p == 0: return None
    if P == Q:
        lam = (3 * P[0]**2 + a) * pow(2 * P[1], p - 2, p) % p
    else:
        lam = (Q[1] - P[1]) * pow(Q[0] - P[0], p - 2, p) % p
    x = (lam**2 - P[0] - Q[0]) % p
    y = (lam * (P[0] - x) - P[1]) % p
    return (x, y)

def mul(k, P):
    R, Q = None, P
    while k:
        if k & 1: R = add(R, Q)
        Q = add(Q, Q)
        k >>= 1
    return R

# Generator point
G = (0, 8)

# ── ECDH Key Exchange ───────────────────────────────────────
alice_priv = random.randint(2, order - 2)
bob_priv   = random.randint(2, order - 2)

A = mul(alice_priv, G)   # Alice's public key
B = mul(bob_priv,   G)   # Bob's public key

shared_A = mul(alice_priv, B)
shared_B = mul(bob_priv,   A)

print("── ECDH ──────────────────────────────")
print(f"Alice public : {A}")
print(f"Bob   public : {B}")
print(f"Shared (Alice): {shared_A}")
print(f"Shared (Bob)  : {shared_B}")
print(f"Match?        : {shared_A == shared_B}")

# ── ECDSA Sign & Verify ─────────────────────────────────────
def mod_inv(k, n):
    g, x, a_ = n, 0, 1
    k = k % n
    while k:
        q = g // k
        g, k = k, g - q * k
        x, a_ = a_, x - q * a_
    return x % n

def sign(priv, h):
    while True:
        k = random.randint(1, order - 1)
        R = mul(k, G)
        if R is None: continue
        r = R[0] % order
        if r == 0: continue
        ki = mod_inv(k, order)
        s = ki * (h + priv * r) % order
        if s: return r, s

def verify(pub, h, sig):
    r, s = sig
    si = mod_inv(s, order)
    u1, u2 = h * si % order, r * si % order
    X = add(mul(u1, G), mul(u2, pub))
    return X is not None and X[0] % order == r

h = 42   # message hash
sig = sign(alice_priv, h)

print("\n── ECDSA ─────────────────────────────")
print(f"Message hash   : {h}")
print(f"Signature (r,s): {sig}")
print(f"Valid?         : {verify(A, h, sig)}")
print(f"Tampered valid?: {verify(A, 99, sig)}")