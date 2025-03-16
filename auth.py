import sqlite3
from tkinter import simpledialog, messagebox

# Connect to the database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Recreate the users table with 'role' column if it does not exist
cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'user'
    )
""")
conn.commit()

def register_user(username, password):
    """Registers a new user with a default role 'user'."""
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", (username, password))
        conn.commit()
        return True
    except sqlite3.IntegrityError:
        return False  # Username already exists

def login_user(username, password):
    """Verifies user credentials and returns role ('admin' or 'user')."""
    cursor.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
    result = cursor.fetchone()
    if result:
        return result[0]  # Return 'admin' or 'user'
    return None  # Login failed

def admin_login_prompt(root):
    """Prompts for admin login before opening the admin panel."""
    username = simpledialog.askstring("Admin Login", "Enter admin username:", parent=root)
    password = simpledialog.askstring("Admin Login", "Enter admin password:", show="*", parent=root)

    if username == "admin" and password == "admin123":
        return True  # Correct admin credentials
    else:
        messagebox.showerror("Access Denied", "Invalid admin credentials!")
        return False  # Incorrect credentials

# Function to manually add an admin (Run once to create an admin)
def create_admin():
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
        conn.commit()
        print("Admin user created successfully!")
    except sqlite3.IntegrityError:
        print("Admin already exists.")

# Uncomment to create an admin user (run once)
# create_admin()
