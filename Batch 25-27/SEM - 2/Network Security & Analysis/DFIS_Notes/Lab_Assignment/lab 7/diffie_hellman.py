# ── Diffie-Hellman Key Exchange ────────────────────────────

# Public parameters
p, g = 23, 5

# Private keys (secret)
a, b = 6, 15

# Public keys (exchanged openly)
A = pow(g, a, p)   # Alice's public key
B = pow(g, b, p)   # Bob's public key

# Shared secret (computed independently)
alice_secret = pow(B, a, p)
bob_secret   = pow(A, b, p)

print(f"Public  : p={p}, g={g}")
print(f"Alice   : private={a}, public A={A}")
print(f"Bob     : private={b}, public B={B}")
print(f"\nAlice's shared secret : {alice_secret}")
print(f"Bob's   shared secret : {bob_secret}")
print(f"Match?                : {alice_secret == bob_secret}")