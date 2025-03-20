import sqlite3
from tkinter import simpledialog, messagebox

# Connect to the SQLite database
conn = sqlite3.connect("users.db")
cursor = conn.cursor()

# Initialize the database by creating necessary tables
def initialize_database():
    """Create the 'users', 'files', and 'logs' tables if they do not exist."""
    # Drop existing tables (if they exist)
    cursor.execute("DROP TABLE IF EXISTS users")
    cursor.execute("DROP TABLE IF EXISTS files")
    cursor.execute("DROP TABLE IF EXISTS logs")

    # Create the 'users' table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user',
            position TEXT NOT NULL
        )
    """)

    # Create the 'files' table for file encryption tracking
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            sender TEXT NOT NULL,
            recipient TEXT NOT NULL,
            file_path TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    # Create the 'logs' table for tracking system events
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            event TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    print("Database initialized successfully!")

# Predefined positions for dropdown selection
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
        cursor.execute("INSERT INTO logs (username, event) VALUES (?, ?)", (username, event))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def save_encrypted_file(sender, recipient, file_path, encryption_key):
    """Stores encrypted file details in the database with the encryption key."""
    try:
        cursor.execute("INSERT INTO files (sender, recipient, file_path, encryption_key) VALUES (?, ?, ?, ?)", 
                       (sender, recipient, file_path, encryption_key))
        conn.commit()
        log_event(sender, f"ENCRYPTED FILE '{file_path}' SENT TO {recipient}")
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def get_user_files(username):
    """Retrieves files that were sent to the given user."""
    try:
        cursor.execute("SELECT id, file_path, encryption_key FROM files WHERE recipient=?", (username,))
        return cursor.fetchall()  # Returns full file details
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def retrieve_encrypted_file(user, file_id):
    """Fetches an encrypted file for a specific user from the database."""
    try:
        cursor.execute("SELECT file_path, encryption_key FROM files WHERE id=? AND recipient=?", (file_id, user))
        result = cursor.fetchone()
        if result:
            return result  # Returns file path and encryption key
        return None  # No file found or unauthorized access
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return None

def get_all_files():
    """Retrieves all encrypted files (Admin Access)."""
    try:
        cursor.execute("SELECT id, sender, recipient, file_path, timestamp FROM files ORDER BY timestamp DESC")
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def delete_encrypted_file(file_id):
    """Deletes an encrypted file record from the database."""
    try:
        cursor.execute("DELETE FROM files WHERE id=?", (file_id,))
        conn.commit()
    except sqlite3.Error as e:
        print(f"Database error: {e}")

def get_all_users():
    """Retrieves all registered users and their positions."""
    try:
        cursor.execute("SELECT username, position FROM users ORDER BY username ASC")
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def decrypt_file(user, file_id):
    """Logs and manages file decryption events."""
    file_info = retrieve_encrypted_file(user, file_id)
    if file_info:
        log_event(user, f"DECRYPTED FILE: {file_info[0]}")
    else:
        log_event(user, "FAILED DECRYPTION ATTEMPT")

def list_stored_files():
    """Retrieves all stored encrypted files from the database (for Admin)."""
    try:
        cursor.execute("SELECT id, file_path, sender, recipient, timestamp FROM files ORDER BY timestamp DESC")
        return cursor.fetchall()
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

def get_system_logs():
    """Retrieves all system logs from the database."""
    try:
        cursor.execute("SELECT username, event, timestamp FROM logs ORDER BY timestamp DESC")
        logs = cursor.fetchall()
        return logs
    except sqlite3.Error as e:
        print(f"Database error: {e}")
        return []

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

# Initialize the database when this module is imported
initialize_database()