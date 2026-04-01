from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# -----------------------------
# 1. Generate RSA Key Pair
# -----------------------------
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# -----------------------------
# 2. Message to Sign
# -----------------------------
message = b"Confidential message for digital signature"

# -----------------------------
# 3. SIGN (using private key)
# -----------------------------
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()
)

print("🔐 Signature Generated:\n", signature)

# -----------------------------
# 4. VERIFY (using public key)
# -----------------------------
try:
    public_key.verify(
        signature,
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA512()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA512()
    )
    print("\n✅ Signature Verified: Message is authentic")

except Exception as e:
    print("\n❌ Verification Failed:", e)