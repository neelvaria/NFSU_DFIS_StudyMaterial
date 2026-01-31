# Program 1: Basic Calculator

def calculator():
    print("----- Basic Calculator -----")
    print("1. Addition")
    print("2. Subtraction")
    print("3. Multiplication")
    print("4. Division")

    choice = int(input("Enter your choice (1-4): "))

    if choice in [1, 2, 3, 4]:
        num1 = float(input("Enter first number: "))
        num2 = float(input("Enter second number: "))

        if choice == 1:
            print("Result =", num1 + num2)

        elif choice == 2:
            print("Result =", num1 - num2)

        elif choice == 3:
            print("Result =", num1 * num2)

        elif choice == 4:
            if num2 != 0:
                print("Result =", num1 / num2)
            else:
                print("Error: Cannot divide by zero!")
    else:
        print("Invalid choice! Please select 1-4.")

if __name__ == "__main__":
    calculator()