import random
import string
import sqlite3
from cryptography.fernet import Fernet
import os

# Generate and save the Fernet key if it doesn't exist
def generate_fernet_key():
    if not os.path.exists("secret.key"):
        key = Fernet.generate_key()
        with open("secret.key", "wb") as key_file:
            key_file.write(key)

def load_fernet_key():
    return open("secret.key", "rb").read()

# Encrypt password using Fernet
def encrypt_password_fernet(password, key):
    cipher_suite = Fernet(key)
    encrypted_password = cipher_suite.encrypt(password.encode())
    return encrypted_password

# Decrypt password using Fernet
def decrypt_password_fernet(encrypted_password, key):
    cipher_suite = Fernet(key)
    decrypted_password = cipher_suite.decrypt(encrypted_password).decode()
    return decrypted_password

# Password generator
def generate_password(length=12, include_uppercase=True, include_numbers=True, include_special=True):
    characters = string.ascii_lowercase
    if include_uppercase:
        characters += string.ascii_uppercase
    if include_numbers:
        characters += string.digits
    if include_special:
        characters += string.punctuation
   
    password = ''.join(random.choice(characters) for _ in range(length))
    return password

# Database setup
def setup_database():
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    try:
        # Try to create the table
        c.execute('''CREATE TABLE passwords
                     (id INTEGER PRIMARY KEY, service TEXT, username TEXT, password BLOB, encryption_type TEXT)''')
    except sqlite3.OperationalError:
        # Table already exists, proceed to add the new column
        print("Table 'passwords' already exists. Adding 'encryption_type' column if not present.")
        try:
            c.execute("ALTER TABLE passwords ADD COLUMN encryption_type TEXT")
        except sqlite3.OperationalError:
            print("Column 'encryption_type' already exists or another error occurred.")
    conn.commit()
    conn.close()

# Store the encrypted password in the database
def store_password(service, usernHelooame, encrypted_password, encryption_type):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('''INSERT INTO passwords (service, username, password, encryption_type)
                 VALUES (?, ?, ?, ?)''', (service, username, encrypted_password, encryption_type))
    conn.commit()
    conn.close()

# Retrieve and decrypt the password from the database
def retrieve_password(service, key):
    conn = sqlite3.connect('password_manager.db')
    c = conn.cursor()
    c.execute('''SELECT username, password FROM passwords WHERE service=? AND encryption_type=?''', (service, 'Fernet'))
    result = c.fetchone()
    conn.close()
    if result:
        username, encrypted_password = result
        decrypted_password = decrypt_password_fernet(encrypted_password, key)
        return username, decrypted_password
    else:
        return None, None

# User authentication with a master password
def authenticate_user(master_password):
    # This should be stored and hashed securely in a real application
    stored_master_password = "MasterPassword123!"  # Replace with your master passwordMasterPassword123!
    return master_password == stored_master_password

# Main CLI interface
def main():
    generate_fernet_key()
    fernet_key = load_fernet_key()
    setup_database()
   
    master_password = input("Enter Master Password: ")
    if not authenticate_user(master_password):
        print("Access Denied!")
        return
   
    while True:
        print("\n--- Password Manager ---")
        print("1. Generate Password")
        print("2. Store Passwords & Check its strength")
        print("3. Retrieve Password") 
        print("Any key for exit")
        choice = input("Choose an option: ")
       
        if choice == '1':
            length = int(input("Enter password length: "))
            password = generate_password(length)
            print("Generated Password:", password)
       
        elif choice == '2':
            service = input("Enter service name: ")
            username = input("Enter username/email: ")
            password = input("Enter password: ")
            strength = check_password_strength(password)
            print(f"Password Strength: {strength}")
           
            encrypted_password = encrypt_password_fernet(password, fernet_key)
            store_password(service, username, encrypted_password, 'Fernet')
            print("Password stored successfully!")
       
        elif choice == '3':
            service = input("Enter service name: ")
            username, password = retrieve_password(service, fernet_key)
           
            if username:
                print(f"Username: {username}, Password: {password}")
            else:
                print("No password found for this service.")
       
        else:
            break

def check_password_strength(password):
    # Initialize strength score
    strength = 0
   
    # Criteria for password strength
    length_criteria = len(password) >= 8
    uppercase_criteria = any(char.isupper() for char in password)
    lowercase_criteria = any(char.islower() for char in password)
    digit_criteria = any(char.isdigit() for char in password)
    special_char_criteria = any(char in string.punctuation for char in password)
   
    # Scoring
    if length_criteria:
        strength += 1
    if uppercase_criteria:
        strength += 1
    if lowercase_criteria:
        strength += 1
    if digit_criteria:
        strength += 1
    if special_char_criteria:
        strength += 1
   
    # Assess strength based on score
    if strength == 5:
        return "Strong"
    elif 3 <= strength < 5:
        return "Medium"
    else:
        return "Weak"

if __name__ == "__main__":
    main()