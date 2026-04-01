# This program collects user records, stores them in a list and dictionary,
# and provides functions for displaying, filtering, and searching the data.

def add_record(records, record_dict):
    # Prompt the user for required fields
    name = input("Enter name: ")
    age = int(input("Enter age: "))
    city = input("Enter city: ")

    # Add the new record to the list (for iteration/ordering)
    records.append({'name': name, 'age': age, 'city': city})

    # Add the record to the dictionary (for fast lookup by name)
    record_dict[name] = {'age': age, 'city': city}
    print("Record added.\n")

def display_records(records):
    # Display all records in a readable format
    print("\nAll Records:")
    for rec in records:  # Iterate through the list using a for loop
        print(f"Name: {rec['name']}, Age: {rec['age']}, City: {rec['city']}")
    print()

def filter_by_age(records, min_age):
    # Show only those records where age meets the minimum threshold
    print(f"\nRecords with age >= {min_age}:")
    for rec in records:  # Iterate through all records
        if rec['age'] >= min_age:  # Use 'if' for conditional filtering
            print(f"Name: {rec['name']}, Age: {rec['age']}, City: {rec['city']}")
    print()

def search_by_name(record_dict):
    # Allow user to search for a record by name (dictionary lookup)
    name = input("Enter name to search: ")
    if name in record_dict:  # Use 'if-else' for checking existence
        print(f"Found: Name: {name}, Age: {record_dict[name]['age']}, City: {record_dict[name]['city']}\n")
    else:
        print("Name not found.\n")

def main():
    records = []         # List to store all record dicts (ordered)
    record_dict = {}     # Dictionary for fast name-based lookups

    while True:          # Menu loop runs until 'Exit' is selected
        print("Menu:")
        print("1. Add Record")
        print("2. Display All Records")
        print("3. Filter Records by Age")
        print("4. Search by Name")
        print("5. Exit")

        choice = input("Enter your choice (1-5): ")

        # Use 'if-elif-else' to select menu option
        if choice == "1":
            add_record(records, record_dict)
        elif choice == "2":
            display_records(records)
        elif choice == "3":
            min_age = int(input("Enter minimum age: "))
            filter_by_age(records, min_age)
        elif choice == "4":
            search_by_name(record_dict)
        elif choice == "5":
            print("Exiting program.")
            break  # Exit the while loop and program
        else:
            print("Invalid choice, try again.\n")

# Python standard entry point check to allow this script to run directly
if __name__ == "__main__":
    main()
