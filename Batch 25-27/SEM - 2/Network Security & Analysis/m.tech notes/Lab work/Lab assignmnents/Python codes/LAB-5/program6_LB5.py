# Program 6: AutoKey Cipher Demonstration
# Input from file and output to file

def autokey_encrypt(plaintext, key):
    result = ""
    full_key = key + plaintext  # AutoKey = key + plaintext characters
    key_index = 0

    for ch in plaintext:
        if ch.isalpha():
            shift = (ord(full_key[key_index].upper()) - ord('A'))
            base = 'A' if ch.isupper() else 'a'
            result += chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
            key_index += 1
        else:
            result += ch
    return result

input_file = "input_plaintext.txt"
output_file = "autokey_output.txt"

key = input("Enter AutoKey initial key: ")

with open(input_file, "r") as f:
    plaintext = f.read()

ciphertext = autokey_encrypt(plaintext, key)

with open(output_file, "w") as f:
    f.write(ciphertext)

print("AutoKey Cipher Encryption Completed!")
