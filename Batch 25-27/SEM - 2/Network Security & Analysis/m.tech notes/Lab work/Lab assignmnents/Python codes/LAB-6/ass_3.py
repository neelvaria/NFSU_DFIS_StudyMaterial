# Assignment 3: Rotor Cipher Demonstration
# Simple Rotor Implementation (Classroom Model)

def rotate_char(ch, shift):
    if ch.isalpha():
        base = 'A' if ch.isupper() else 'a'
        return chr((ord(ch) - ord(base) + shift) % 26 + ord(base))
    return ch

def rotor_cipher_encrypt(plaintext, num_rotors, angles):
    ciphertext = plaintext

    for i in range(num_rotors):
        shift = angles[i] % 26
        new_text = ""
        for ch in ciphertext:
            new_text += rotate_char(ch, shift)
        ciphertext = new_text  # output of one rotor becomes input to next

    return ciphertext


# I/O
input_file = "input.txt"
output_file = "rotor_output.txt"

with open(input_file, "r") as f:
    plaintext = f.read()

num_rotors = int(input("Enter number of rotors: "))

angles = []
for i in range(num_rotors):
    ang = int(input(f"Enter angle for rotor {i+1}: "))
    angles.append(ang)

ciphertext = rotor_cipher_encrypt(plaintext, num_rotors, angles)

with open(output_file, "w") as f:
    f.write(ciphertext)

print("Rotor Cipher Encryption Completed!")
