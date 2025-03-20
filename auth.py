# auth.py
import sqlite3
from tkinter import simpledialog, messagebox
from database import conn, cursor  # Import the database connection and cursor

# Predefined positions for the dropdown selection
POSITIONS = [
    "CEO", "HR Manager", "Office Admin", "Finance Manager", "Accountant",
    "IT Manager", "IT Support Technician", "Sales Manager",
    "Operations Manager", "Secretary", "Compliance Officer"
]

def register_user(username, password, position):
    """Registers a new user with a role and position."""
    if position not in POSITIONS:
        return False  # Invalid position selection

    try:
        cursor.execute("INSERT INTO users (username, password, role, position) VALUES (?, ?, 'user', ?)",
                       (username, password, position))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return False  # Other database errors

def login_user(username, password):
    """Verifies user credentials, logs failed attempts, and returns role ('admin' or 'user')."""
    try:
        cursor.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
        result = cursor.fetchone()

        if result:
            log_event(username, "LOGIN SUCCESSFUL")  # Log successful login
            return result[0]  # Return 'admin' or 'user'

        log_event(username, "FAILED LOGIN ATTEMPT")  # Log failed login attempt
        return None  # Login failed
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None  # Database error

def log_event(username, event):
    """Logs system events such as login attempts, encryption, and decryption."""
    try:
        with open("system_logs.txt", "a") as log_file:
            log_file.write(f"User: {username} - {event}\n")
    except Exception as e:
        print(f"Error writing to log file: {e}")

def admin_login_prompt(root):
    """Prompts for admin login before opening the admin panel."""
    username = simpledialog.askstring("Admin Login", "Enter admin username:", parent=root)
    password = simpledialog.askstring("Admin Login", "Enter admin password:", show="*", parent=root)

    if username == "admin" and password == "admin123":
        return True  # Correct admin credentials
    else:
        messagebox.showerror("Access Denied", "Invalid admin credentials!")
        log_event(username, "FAILED ADMIN LOGIN ATTEMPT")  # Log failed admin login attempt
        return False  # Incorrect credentials

# Function to manually add an admin (Run once to create an admin)
def create_admin():
    try:
        cursor.execute("INSERT INTO users (username, password, role, position) VALUES ('admin', 'admin123', 'admin', 'CEO')")
        conn.commit()
        print("Admin user created successfully!")
    except sqlite3.IntegrityError:
        print("Admin already exists.")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

# Uncomment to create an admin user (run once)
# create_admin()