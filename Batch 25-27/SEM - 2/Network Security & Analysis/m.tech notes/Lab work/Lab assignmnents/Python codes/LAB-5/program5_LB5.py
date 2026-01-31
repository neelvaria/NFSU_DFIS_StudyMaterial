# Program 5: Vigenère Cipher Demonstration
# Input from file and output to file

def vigenere_encrypt(plaintext, key):
    result = ""
    key = key.upper()
    key_index = 0

    for ch in plaintext:
        if ch.isalpha():
            shift = ord(key[key_index % len(key)]) - ord('A')
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
            key_index += 1
        else:
            result += ch
    return result

input_file = "input_plaintext.txt"
output_file = "vigenere_output.txt"

key = input("Enter Vigenere key: ")

with open(input_file, "r") as f:
    plaintext = f.read()

ciphertext = vigenere_encrypt(plaintext, key)

with open(output_file, "w") as f:
    f.write(ciphertext)

print("Vigenere Cipher Encryption Completed!")
