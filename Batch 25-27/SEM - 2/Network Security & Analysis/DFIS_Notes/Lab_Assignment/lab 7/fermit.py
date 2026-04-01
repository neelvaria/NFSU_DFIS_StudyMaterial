# Program to demonstrate Fermat's Little Theorem

# Function to check if number is prime
def is_prime(n):
    if n <= 1:
        return False
    for i in range(2, int(n**0.5) + 1):
        if n % i == 0:
            return False
    return True


# Input values
a = int(input("Enter value of a: "))
p = int(input("Enter prime number p: "))

# Check if p is prime
if not is_prime(p):
    print("p must be a prime number.")
else:
    result = pow(a, p-1, p)

    print("Value of (a^(p-1)) mod p =", result)

    if result == 1:
        print("Fermat's Little Theorem is verified.")
    else:
        print("Fermat's Little Theorem is NOT satisfied.")