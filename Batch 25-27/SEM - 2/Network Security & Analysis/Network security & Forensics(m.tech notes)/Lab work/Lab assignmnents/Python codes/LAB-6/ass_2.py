# Assignment 2: Polybius Cipher (File input/output)

polybius_square = {
    'A': "11", 'B': "12", 'C': "13", 'D': "14", 'E': "15",
    'F': "21", 'G': "22", 'H': "23", 'I': "24", 'J': "24", 'K': "25",
    'L': "31", 'M': "32", 'N': "33", 'O': "34", 'P': "35",
    'Q': "41", 'R': "42", 'S': "43", 'T': "44", 'U': "45",
    'V': "51", 'W': "52", 'X': "53", 'Y': "54", 'Z': "55"
}

def polybius_encrypt(plaintext):
    plaintext = plaintext.upper().replace(" ", "")
    ciphertext = ""

    for ch in plaintext:
        if ch in polybius_square:
            ciphertext += polybius_square[ch] + " "
        else:
            ciphertext += ch

    return ciphertext.strip()


input_file = "input.txt"
output_file = "poly_output.txt"

with open(input_file, "r") as f:
    plaintext = f.read()

ciphertext = polybius_encrypt(plaintext)

with open(output_file, "w") as f:
    f.write(ciphertext)

print("Polybius Cipher Encryption Completed!")
