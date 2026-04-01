# Program 4: Monoalphabetic Cipher Cryptosystem Demonstration
# Reads plaintext from a file and writes ciphertext to another file

# Example key mapping (A-Z)
key = "QWERTYUIOPASDFGHJKLZXCVBNM"

def mono_encrypt(text):
    result = ""
    for ch in text:
        if ch.isalpha():
            if ch.isupper():
                result += key[ord(ch) - ord('A')]
            else:
                result += key[ord(ch) - ord('a')].lower()
        else:
            result += ch
    return result

input_file = "input_plaintext.txt"
output_file = "mono_output.txt"

# Read plaintext
with open(input_file, "r") as f:
    plaintext = f.read()

# Encrypt
ciphertext = mono_encrypt(plaintext)

# Write ciphertext
with open(output_file, "w") as f:
    f.write(ciphertext)

print("Monoalphabetic Cipher Encryption Completed!")
