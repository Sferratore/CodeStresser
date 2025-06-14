import os
import sqlite3

def handle_user_input():
    user_code = input("Enter code to evaluate: ")
    result = eval(user_code)  # Vulnerability: arbitrary exec
    print("Result:", result)

def search_user(db_path):
    conn = sqlite3.connect(db_path)
    cursor = conn.cursor()
    name = input("Enter username to search: ")
    query = "SELECT * FROM users WHERE name = '" + name + "'"  # Vulnerability: SQL Injection
    cursor.execute(query)
    for row in cursor.fetchall():
        print(row)
    conn.close()

def read_file():
    filename = input("Enter filename: ")
    with open(filename, "r") as f:  # Vulnerability: Path exploit
        content = f.read()
        print(content)

def main():
    print("1. Eval")
    print("2. Search user")
    print("3. Read file")
    choice = input("Choose an option: ")
    if choice == "1":
        handle_user_input()
    elif choice == "2":
        search_user("users.db")
    elif choice == "3":
        read_file()

if __name__ == "__main__":
    main()
