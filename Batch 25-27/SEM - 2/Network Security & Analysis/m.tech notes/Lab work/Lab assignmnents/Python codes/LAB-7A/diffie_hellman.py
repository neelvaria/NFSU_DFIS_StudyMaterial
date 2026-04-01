# PROGRAM 2: Diffie-Hellman Key Exchange Demonstration

def power_mod(base, exp, mod):
    return pow(base, exp, mod)

# Public values
p = int(input("Enter a prime number p: "))
g = int(input("Enter a primitive root g: "))

# Private keys
a = int(input("Enter private key for User A: "))
b = int(input("Enter private key for User B: "))

# Public keys
A = power_mod(g, a, p)
B = power_mod(g, b, p)

print("\nPublic key of A:", A)
print("Public key of B:", B)

# Shared secret
shared_A = power_mod(B, a, p)
shared_B = power_mod(A, b, p)

print("\nShared secret computed by A:", shared_A)
print("Shared secret computed by B:", shared_B)

if shared_A == shared_B:
    print("\nKey Exchange Successful! Shared Secret =", shared_A)
else:
    print("\nError: Shared secrets do not match!")
