# Caesar Cipher Encryption using File Handling

def caesar_encrypt(text, key):
    ciphertext = ""

    for char in text:
        if char.isalpha():
            if char.isupper():
                ciphertext += chr((ord(char) - ord('A') + key) % 26 + ord('A'))
            else:
                ciphertext += chr((ord(char) - ord('a') + key) % 26 + ord('a'))
        else:
            ciphertext += char

    return ciphertext


# Shift key
key = 3

# Read plaintext from file
with open("plaintext.txt", "r") as file:
    plaintext = file.read()

# Encrypt the plaintext
ciphertext = caesar_encrypt(plaintext, key)

# Write ciphertext to another file
with open("ciphertext.txt", "w") as file:
    file.write(ciphertext)

print("Encryption completed successfully.")
print("Ciphertext:", ciphertext)