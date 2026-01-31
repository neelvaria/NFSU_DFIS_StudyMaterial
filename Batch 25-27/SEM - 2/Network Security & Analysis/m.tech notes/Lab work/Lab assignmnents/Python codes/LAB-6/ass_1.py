# Assignment 1: Row Transposition Cipher
# Read plaintext from file and write ciphertext to another file

def row_transposition_encrypt(plaintext, key):
    key_digits = list(key)
    key_order = sorted(range(len(key_digits)), key=lambda x: key_digits[x])
    
    # Remove spaces/newlines for matrix placement
    plaintext = plaintext.replace(" ", "").replace("\n", "")

    # Calculate rows needed
    cols = len(key)
    rows = (len(plaintext) + cols - 1) // cols

    # Fill matrix row-wise
    matrix = []
    index = 0
    for r in range(rows):
        row = []
        for c in range(cols):
            if index < len(plaintext):
                row.append(plaintext[index])
            else:
                row.append('X')  # padding
            index += 1
        matrix.append(row)

    # Read matrix column-wise based on key order
    ciphertext = ""
    for col in key_order:
        for row in matrix:
            ciphertext += row[col]

    return ciphertext


# File IO
input_file = "input.txt"
output_file = "row_trans_output.txt"

key = input("Enter Row Transposition key (e.g. 431256): ")

with open(input_file, "r") as f:
    plaintext = f.read()

ciphertext = row_transposition_encrypt(plaintext, key)

with open(output_file, "w") as f:
    f.write(ciphertext)

print("Row Transposition Cipher Encryption Completed!")
