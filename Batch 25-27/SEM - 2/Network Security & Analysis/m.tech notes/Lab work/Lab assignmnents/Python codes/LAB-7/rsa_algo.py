# PROGRAM 2: RSA Algorithm using File Input and File Output

def gcd(a, b):
    while b != 0:
        a, b = b, a % b
    return a

def mod_inverse(e, phi):
    # Extended Euclid Algorithm
    old_r, r = e, phi
    old_s, s = 1, 0

    while r != 0:
        q = old_r // r
        old_r, r = r, old_r - q * r
        old_s, s = s, old_s - q * s

    if old_s < 0:
        old_s += phi
    return old_s

def rsa_encrypt_char(ch, e, n):
    return pow(ord(ch), e, n)

def rsa_decrypt_char(c, d, n):
    return chr(pow(c, d, n))


# -----------------------
# Main Program
# -----------------------

p = int(input("Enter prime p: "))
q = int(input("Enter prime q: "))

n = p * q
phi = (p - 1) * (q - 1)

print("\nChoose encryption exponent e such that gcd(e, phi)=1")
e = int(input("Enter e: "))

if gcd(e, phi) != 1:
    print("Invalid e! Must be coprime with φ(n).")
    exit()

d = mod_inverse(e, phi)

print("\nPublic Key  =", (e, n))
print("Private Key =", d)

# File input/output
infile = "input.txt"
outfile = "rsa_output.txt"

with open(infile, "r") as f:
    plaintext = f.read()

cipher_nums = []
for ch in plaintext:
    cipher_nums.append(str(rsa_encrypt_char(ch, e, n)))

with open(outfile, "w") as f:
    f.write(" ".join(cipher_nums))

print("\nRSA Encryption Completed!")
print("Ciphertext saved in:", outfile)
