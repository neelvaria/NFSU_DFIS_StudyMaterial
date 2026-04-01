# Vigenere Cipher Encryption using File Handling

def vigenere_encrypt(plaintext, key):
    ciphertext = ""
    key = key.upper()
    key_index = 0

    for char in plaintext:
        if char.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')

            if char.isupper():
                encrypted_char = chr((ord(char) - ord('A') + shift) % 26 + ord('A'))
            else:
                encrypted_char = chr((ord(char) - ord('a') + shift) % 26 + ord('a'))

            ciphertext += encrypted_char
            key_index += 1
        else:
            ciphertext += char

    return ciphertext


# Key for encryption
key = "KEY"

# Read plaintext from file
with open("plaintext.txt", "r") as file:
    plaintext = file.read()

# Encrypt
ciphertext = vigenere_encrypt(plaintext, key)

# Write ciphertext to file
with open("ciphertext.txt", "w") as file:
    file.write(ciphertext)

print("Encryption completed.")
print("Ciphertext:", ciphertext)