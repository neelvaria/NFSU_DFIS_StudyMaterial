# Autokey Cipher Encryption with File Input and Output

def autokey_encrypt(plaintext, key):
    plaintext = plaintext.upper().replace(" ", "")
    key = key.upper()

    # Extend key using plaintext
    extended_key = key + plaintext
    ciphertext = ""

    for i in range(len(plaintext)):
        p = ord(plaintext[i]) - ord('A')
        k = ord(extended_key[i]) - ord('A')

        c = (p + k) % 26
        ciphertext += chr(c + ord('A'))

    return ciphertext


# Initial key
key = "KEY"

# Read plaintext from file
with open("plaintext.txt", "r") as file:
    plaintext = file.read().strip()

# Encrypt
ciphertext = autokey_encrypt(plaintext, key)

# Write ciphertext to file
with open("ciphertext.txt", "w") as file:
    file.write(ciphertext)

print("Encryption completed successfully.")
print("Ciphertext:", ciphertext)