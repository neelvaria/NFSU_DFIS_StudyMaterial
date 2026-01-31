# PROGRAM 1: Poly-Alphabetic Cipher (Vigenère Cipher)
# Input from file → Output to file

def vigenere_encrypt(plaintext, key):
    key = key.upper()
    result = ""
    key_index = 0

    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = 'A' if ch.isupper() else 'a'
            encrypted = chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
            result += encrypted
            key_index += 1
        else:
            result += ch
    return result


input_file = "input.txt"
output_file = "polyalph_output.txt"

key = input("Enter key for Poly-Alphabetic Cipher: ")

with open(input_file, "r") as f:
    plaintext = f.read()

ciphertext = vigenere_encrypt(plaintext, key)

with open(output_file, "w") as f:
    f.write(ciphertext)

print("Poly-Alphabetic Cipher Encryption Completed!")
print(f"Ciphertext written to {output_file}")