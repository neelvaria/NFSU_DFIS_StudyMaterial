# PROGRAM 3: ECC Cryptosystem Demonstration
# Uses Elliptic Curve: y^2 = x^3 + ax + b mod p

def inv_mod(k, p):
    return pow(k, p-2, p)

def point_add(P, Q, a, p):
    if P == (0, 0):
        return Q
    if Q == (0, 0):
        return P
    if P == Q:
        s = ((3 * P[0] * P[0] + a) * inv_mod(2 * P[1], p)) % p
    else:
        s = ((Q[1] - P[1]) * inv_mod(Q[0] - P[0], p)) % p

    xr = (s * s - P[0] - Q[0]) % p
    yr = (s * (P[0] - xr) - P[1]) % p
    return (xr, yr)

def scalar_mult(k, P, a, p):
    R = (0, 0)  # Identity
    while k > 0:
        if k & 1:
            R = point_add(R, P, a, p)
        P = point_add(P, P, a, p)
        k >>= 1
    return R


# ---------------------------------
# Main Program Inputs
# ---------------------------------

p = int(input("Enter prime p: "))
a = int(input("Enter curve parameter a: "))
b = int(input("Enter curve parameter b: "))

print("\nEnter base point G (x, y):")
Gx = int(input("Gx: "))
Gy = int(input("Gy: "))
G = (Gx, Gy)

private_key = int(input("Enter private key: "))

# Public key
public_key = scalar_mult(private_key, G, a, p)
print("\nPublic Key:", public_key)

# Message as a point
print("\nEnter message point M (x, y):")
Mx = int(input("Mx: "))
My = int(input("My: "))
M = (Mx, My)

k = int(input("Enter random value k: "))

# Encryption
C1 = scalar_mult(k, G, a, p)
C2 = point_add(M, scalar_mult(k, public_key, a, p), a, p)

print("\nEncrypted Points:")
print("C1:", C1)
print("C2:", C2)
