import sqlite3

def create_connection():
    """Creates and returns a database connection."""
    return sqlite3.connect("users.db")

def create_users_table():
    """Creates the users table with a role column."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL DEFAULT 'user'
        )
    """)

    conn.commit()
    conn.close()

def create_files_table():
    """Creates the encrypted_files table to store encrypted files."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("""
        CREATE TABLE IF NOT EXISTS encrypted_files (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filepath TEXT NOT NULL,
            encryption_key TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    """)

    conn.commit()
    conn.close()

def register_user(username, password):
    """Registers a new user with default role 'user'."""
    conn = create_connection()
    cursor = conn.cursor()
    
    try:
        cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, 'user')", (username, password))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False  # Username already exists

def login_user(username, password):
    """Checks user credentials and returns role ('admin' or 'user')."""
    conn = create_connection()
    cursor = conn.cursor()
    
    cursor.execute("SELECT role FROM users WHERE username=? AND password=?", (username, password))
    result = cursor.fetchone()
    
    conn.close()
    return result[0] if result else None  # Returns 'admin' or 'user' if found, else None

def create_admin():
    """Creates an admin user if not already in the system."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT * FROM users WHERE username = 'admin'")
    if not cursor.fetchone():
        cursor.execute("INSERT INTO users (username, password, role) VALUES ('admin', 'admin123', 'admin')")
        conn.commit()
        print("✅ Admin user created successfully!")
    else:
        print("⚠️ Admin already exists.")

    conn.close()

def store_encrypted_file(filename, filepath, encryption_key):
    """Stores encrypted file details in the database."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("INSERT INTO encrypted_files (filename, filepath, encryption_key) VALUES (?, ?, ?)", 
                   (filename, filepath, encryption_key))

    conn.commit()
    conn.close()

def retrieve_encrypted_file(filename):
    """Retrieves the file path and encryption key from the database."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT filepath, encryption_key FROM encrypted_files WHERE filename=?", (filename,))
    result = cursor.fetchone()

    conn.close()
    return result  # Returns (filepath, encryption_key) if found, else None

def list_stored_files():
    """Lists all encrypted files stored in the database."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("SELECT id, filename, timestamp FROM encrypted_files")
    files = cursor.fetchall()

    conn.close()
    return files  # Returns a list of (id, filename, timestamp)

def delete_encrypted_file(file_id):
    """Deletes an encrypted file from the database using its ID."""
    conn = create_connection()
    cursor = conn.cursor()

    cursor.execute("DELETE FROM encrypted_files WHERE id=?", (file_id,))
    conn.commit()
    conn.close()

# Run these functions once to set up the database
if __name__ == "__main__":
    create_users_table()   # Ensure the users table exists
    create_files_table()   # Ensure the encrypted_files table exists
    create_admin()         # Ensure the admin user exists
    print("✅ Database setup complete!")
