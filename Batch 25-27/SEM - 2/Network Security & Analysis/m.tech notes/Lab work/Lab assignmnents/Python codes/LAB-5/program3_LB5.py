# Program 3: Caesar Cipher Cryptosystem Demonstration
# Reads plaintext from a file and writes ciphertext to another file

def caesar_encrypt(text, shift):
    result = ""
    for ch in text:
        if ch.isalpha():
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
        else:
            result += ch
    return result

# File paths
input_file = "input_plaintext.txt"
output_file = "caesar_output.txt"

shift = int(input("Enter shift value for Caesar Cipher: "))

# Read plaintext
with open(input_file, "r") as f:
    plaintext = f.read()

# Encrypt
ciphertext = caesar_encrypt(plaintext, shift)

# Write ciphertext
with open(output_file, "w") as f:
    f.write(ciphertext)

print("Caesar Cipher Encryption Completed!")
