# Write a program to calculate the mod exponent of a big number.

def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        # If exponent is odd
        if exponent % 2 == 1:
            result = (result * base) % modulus

        # Square the base
        base = (base * base) % modulus

        # Divide exponent by 2
        exponent = exponent // 2

    return result


# Input
base = int(input("Enter base: "))
exponent = int(input("Enter exponent: "))
modulus = int(input("Enter modulus: "))

# Calculate
result = mod_exp(base, exponent, modulus)

print("Modular Exponentiation Result:", result)