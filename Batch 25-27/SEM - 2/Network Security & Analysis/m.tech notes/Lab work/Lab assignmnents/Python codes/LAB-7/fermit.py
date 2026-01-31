# PROGRAM 3: Fermat's Little Theorem Demonstration

def mod_exp(base, exp, mod):
    result = 1
    base = base % mod

    while exp > 0:
        if exp % 2 == 1:
            result = (result * base) % mod
        base = (base * base) % mod
        exp //= 2
    return result


print("Fermat’s Little Theorem Checker")
a = int(input("Enter value of a: "))
p = int(input("Enter prime number p: "))

if a % p == 0:
    print("gcd(a,p) ≠ 1 → Fermat's theorem does not apply.")
else:
    value = mod_exp(a, p - 1, p)
    print(f"\nAccording to Fermat’s Little Theorem:")
    print(f"{a}^(p-1) mod {p} = {value}")

    if value == 1:
        print("The theorem is VERIFIED ✓")
    else:
        print("The theorem FAILED ✗")
