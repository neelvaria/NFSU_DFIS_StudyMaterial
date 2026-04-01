import math

def encrypt_row_transposition(plaintext, key):
    plaintext = plaintext.replace(" ", "").upper()
    
    col = len(key)
    row = math.ceil(len(plaintext) / col)
    
    # Padding plaintext
    padding = row * col - len(plaintext)
    plaintext += 'X' * padding
    
    # Create matrix
    matrix = []
    k = 0
    for r in range(row):
        matrix.append(list(plaintext[k:k+col]))
        k += col
    
    # Generate ciphertext
    ciphertext = ""
    key_order = sorted(list(key))
    
    for num in key_order:
        col_index = key.index(num)
        for r in range(row):
            ciphertext += matrix[r][col_index]
    
    return ciphertext


def main():
    key = "4312567"
    
    # Read plaintext from file
    with open("plaintext.txt", "r") as f:
        plaintext = f.read()
    
    # Encrypt
    cipher = encrypt_row_transposition(plaintext, key)
    
    # Write ciphertext to file
    with open("cipher.txt", "w") as f:
        f.write(cipher)
    
    print("Encryption Complete!")
    print("Ciphertext:", cipher)


if __name__ == "__main__":
    main()