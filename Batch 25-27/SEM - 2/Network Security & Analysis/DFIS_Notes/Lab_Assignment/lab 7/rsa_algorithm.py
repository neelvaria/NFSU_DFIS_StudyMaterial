# ── RSA Algorithm ──────────────────────────────────────────
from math import gcd

def mod_inv(e, phi):
    g, x = phi, 0
    a, b = e % phi, 1
    while a:
        q = g // a
        g, a = a, g - q * a
        x, b = b, x - q * b
    return x % phi

# Key Generation
p, q = 61, 53
n = p * q
phi = (p - 1) * (q - 1)
e = next(i for i in range(2, phi) if gcd(i, phi) == 1)
d = mod_inv(e, phi)

print(f"Public Key  (e, n) : ({e}, {n})")
print(f"Private Key (d, n) : ({d}, {n})")

# Encrypt & Decrypt
msg = 42
C = pow(msg, e, n)
M = pow(C, d, n)

print(f"\nOriginal  : {msg}")
print(f"Encrypted : {C}")
print(f"Decrypted : {M}")
print(f"Match?    : {msg == M}")