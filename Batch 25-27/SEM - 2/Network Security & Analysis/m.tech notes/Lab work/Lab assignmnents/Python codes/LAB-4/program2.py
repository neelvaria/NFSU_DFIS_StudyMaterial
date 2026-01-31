# Program 2: Random Number Guessing Game

import random

def guessing_game():
    print("----- Random Number Guessing Game -----")
    secret_number = random.randint(1, 100)
    attempts = 0

    while True:
        guess = int(input("Guess a number between 1 and 100: "))
        attempts += 1

        if guess < secret_number:
            print("Too Low! Try again.")
        elif guess > secret_number:
            print("Too High! Try again.")
        else:
            print("Congratulations! You guessed it correctly.")
            print("Total attempts:", attempts)
            break

if __name__ == "__main__":
    guessing_game() 