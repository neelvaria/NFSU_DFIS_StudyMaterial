from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

# 1. Generate RSA Key Pair
private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048
)

public_key = private_key.public_key()

# 2. Message
message = b"Hello, this is a secure message using SHA-512!"

# 3. Sign the Message (Digital Signature)
signature = private_key.sign(
    message,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA512()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA512()
)

print("Signature:", signature)

# 4. Verify the Signature
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
    print("✅ Signature Verified Successfully")
except Exception as e:
    print("Verification Failed:", e)