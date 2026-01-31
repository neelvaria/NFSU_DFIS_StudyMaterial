# Program 3: Caesar Cipher – Write Ciphertext to Another File

def encrypt_caesar(text, shift):
    encrypted = ""
    for ch in text:
        if ch.isalpha():
            base = ord('A') if ch.isupper() else ord('a')
            encrypted += chr((ord(ch) - base + shift) % 26 + base)
        else:
            encrypted += ch
    return encrypted


# Read from input file
with open("input.txt", "r") as infile:
    plaintext = infile.read()

# Encrypt plaintext
shift = 3  # you can change shift for different encryption
ciphertext = encrypt_caesar(plaintext, shift)

# Write ciphertext to output file
with open("output.txt", "w") as outfile:
    outfile.write(ciphertext)

print("Ciphertext written successfully to output.txt")
