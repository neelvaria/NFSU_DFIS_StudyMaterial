# Rotor Cipher Demonstration

def rotor_cipher_encrypt(plaintext, rotor_angles):
    alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    plaintext = plaintext.upper()
    
    ciphertext = ""

    for char in plaintext:
        if char in alphabet:
            index = alphabet.index(char)
            
            # pass through each rotor
            for angle in rotor_angles:
                index = (index + angle) % 26
            
            ciphertext += alphabet[index]
        else:
            ciphertext += char

    return ciphertext


def main():
    
    plaintext = input("Enter Plaintext: ")
    
    num_rotors = int(input("Enter number of rotors: "))
    
    rotor_angles = []
    
    print("Enter angle for each rotor:")
    for i in range(num_rotors):
        angle = int(input(f"Rotor {i+1} angle: "))
        rotor_angles.append(angle)
    
    cipher = rotor_cipher_encrypt(plaintext, rotor_angles)
    
    print("\nCiphertext:", cipher)


if __name__ == "__main__":
    main()