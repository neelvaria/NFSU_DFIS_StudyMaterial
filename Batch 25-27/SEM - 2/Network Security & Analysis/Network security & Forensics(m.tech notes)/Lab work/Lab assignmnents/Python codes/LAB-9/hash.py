import hashlib

# ---------- Helper Functions ----------

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    # Extended Euclid's Algorithm to find d such that (d * e) % phi == 1
    old_r, r = e, phi
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_s < 0:
        old_s += phi
    return old_s

def sha256_hash(message: str) -> int:
    """
    Hash the message with SHA-256 and return as an integer.
    """
    digest = hashlib.sha256(message.encode('utf-8')).hexdigest()
    return int(digest, 16)  # convert hex string to integer


# ---------- Key Generation (RSA) ----------

print("=== RSA Key Generation ===")
p = int(input("Enter prime number p: "))
q = int(input("Enter prime number q: "))

n = p * q
phi = (p - 1) * (q - 1)

print(f"\nComputed n = p * q = {n}")
print(f"Computed phi(n) = (p-1)*(q-1) = {phi}")

# Choose e
while True:
    e = int(input("\nEnter public exponent e (1 < e < phi and gcd(e,phi)=1): "))
    if 1 < e < phi and gcd(e, phi) == 1:
        break
    else:
        print("Invalid e. It must be 1 < e < phi and gcd(e, phi) == 1. Try again.")

d = mod_inverse(e, phi)

print("\nPublic Key  (e, n) =", (e, n))
print("Private Key (d, n) =", (d, n))

# ---------- Signing ----------

print("\n=== Digital Signature Generation ===")
message = input("Enter the message to sign: ")

# Step 1: Hash the message
h = sha256_hash(message)
print("\nSHA-256 hash of message (as integer):")
print(h)

# Step 2: Create signature: s = h^d mod n
signature = pow(h, d, n)
print("\nDigital Signature (integer value):")
print(signature)

# ---------- Verification ----------

print("\n=== Signature Verification ===")
message_to_verify = input("Enter the message to verify: ")

# Recompute hash of the message
h_verify = sha256_hash(message_to_verify)
print("\nRecomputed SHA-256 hash of message (as integer):")
print(h_verify)

# Decrypt signature using public key: h' = s^e mod n
h_from_signature = pow(signature, e, n)
print("\nHash recovered from signature using public key:")
print(h_from_signature)

# Compare hashes
if h_verify == h_from_signature:
    print("\n✅ Signature is VALID: message is authentic and not modified.")
else:
    print("\n❌ Signature is INVALID: message has been changed or signature is wrong.")
