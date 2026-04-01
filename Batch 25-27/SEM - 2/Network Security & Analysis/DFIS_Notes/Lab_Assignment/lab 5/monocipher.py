# Monoalphabetic Cipher Encryption using File Handling

# substitution key
plain_alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
cipher_alphabet = "QWERTYUIOPASDFGHJKLZXCVBNM"

def monoalphabetic_encrypt(text):
    ciphertext = ""

    for char in text:
        if char.isalpha():
            if char.isupper():
                index = plain_alphabet.index(char)
                ciphertext += cipher_alphabet[index]
            else:
                index = plain_alphabet.index(char.upper())
                ciphertext += cipher_alphabet[index].lower()
        else:
            ciphertext += char

    return ciphertext


# Read plaintext from file
with open("plaintext.txt", "r") as file:
    plaintext = file.read()

# Encrypt
ciphertext = monoalphabetic_encrypt(plaintext)

# Write ciphertext to output file
with open("ciphertext.txt", "w") as file:
    file.write(ciphertext)

print("Encryption completed successfully.")
print("Ciphertext:", ciphertext)