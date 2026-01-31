# PROGRAM 1: Modular Exponentiation of a Big Number

def mod_exp(base, exponent, modulus):
    result = 1
    base = base % modulus

    while exponent > 0:
        if exponent % 2 == 1:       # If exponent is odd
            result = (result * base) % modulus
        base = (base * base) % modulus
        exponent //= 2

    return result


# ---- Main Driver ----
base = int(input("Enter base: "))
exponent = int(input("Enter exponent: "))
modulus = int(input("Enter modulus: "))

print("\nResult =", mod_exp(base, exponent, modulus))
