import os
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, simpledialog
from PIL import Image, ImageTk
import pyperclip  # For copying encryption key
from backend import encrypt_file, decrypt_file
from auth import login_user, register_user
from admin import open_admin_window
from database import list_stored_files  # Importing function to list stored files

# Initialize main window
root = tk.Tk()
root.title("JASCO Secure File System")
root.geometry("500x550")

# Load background image
try:
    bg_image = Image.open("background.jpg")  # Ensure this file exists
    bg_image = bg_image.resize((500, 550))
    bg_photo = ImageTk.PhotoImage(bg_image)

    bg_label = tk.Label(root, image=bg_photo)
    bg_label.place(relwidth=1, relheight=1)
except Exception as e:
    messagebox.showwarning("Warning", f"Background image error: {str(e)}")

# Username & Password Fields
tk.Label(root, text="Username:", font=("Arial", 12, "bold"), bg="#f0f0f0").place(x=50, y=50)
username_entry = tk.Entry(root, font=("Arial", 12))
username_entry.place(x=150, y=50, width=250)

tk.Label(root, text="Password:", font=("Arial", 12, "bold"), bg="#f0f0f0").place(x=50, y=100)
password_entry = tk.Entry(root, font=("Arial", 12), show="*")
password_entry.place(x=150, y=100, width=250)

# **Login Function**
def login():
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "Please enter username and password")
        return

    user_type = login_user(username, password)
    if user_type == "user":
        messagebox.showinfo("Success", "Login Successful! Welcome User.")
        open_user_dashboard()
    elif user_type == "admin":
        messagebox.showinfo("Success", "Admin Login Successful!")
        open_admin_dashboard()
    else:
        messagebox.showerror("Error", "Invalid username or password")

# **Register Function**
def register():
    username = username_entry.get()
    password = password_entry.get()

    if not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    success = register_user(username, password)
    if success:
        messagebox.showinfo("Success", "Registration Successful!")
    else:
        messagebox.showerror("Error", "User already exists!")

# **Encrypt File Function with Copy Key Feature**
def open_file_and_encrypt():
    """Opens file dialog for selecting a file to encrypt and stores it in the database."""
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if not file_path:
        messagebox.showerror("Error", "No file selected!")
        return

    try:
        encryption_key = encrypt_file(file_path)  # Now stores in the database and returns key

        # Debugging: Print the encryption key to ensure it's correct
        print(f"Encryption Key: {encryption_key}")

        # Create a pop-up window to display the encryption key
        key_window = Toplevel(root)
        key_window.title("Encryption Key")
        key_window.geometry("400x200")

        tk.Label(key_window, text="Encryption Key:", font=("Arial", 12, "bold")).pack(pady=10)
        
        key_entry = tk.Entry(key_window, font=("Arial", 12), width=40)
        key_entry.insert(0, encryption_key)  # Insert the encryption key
        key_entry.pack(pady=5)
        key_entry.config(state="readonly")  # Make it read-only
        
        # Copy Key Function
        def copy_key():
            pyperclip.copy(encryption_key)
            messagebox.showinfo("Copied", "Encryption key copied to clipboard!")

        # Copy Button
        copy_button = tk.Button(key_window, text="Copy Key", font=("Arial", 12), command=copy_key)
        copy_button.pack(pady=10)

        # Close Button
        close_button = tk.Button(key_window, text="Close", font=("Arial", 12), command=key_window.destroy)
        close_button.pack(pady=5)

        messagebox.showinfo("Success", "File encrypted and stored in the database.")

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# **Decrypt File Function**
def open_database_and_decrypt():
    """Opens a selection window to choose a file from the database and decrypt it."""
    files = list_stored_files()
    if not files:
        messagebox.showerror("Error", "No encrypted files found in the database.")
        return

    # Create file selection window
    selection_window = Toplevel(root)
    selection_window.title("Select a File to Decrypt")
    selection_window.geometry("400x300")

    tk.Label(selection_window, text="Select a file to decrypt:", font=("Arial", 12, "bold")).pack(pady=5)

    # Listbox for files
    file_listbox = tk.Listbox(selection_window, font=("Arial", 12))
    for file in files:
        file_listbox.insert(tk.END, f"{file[0]} - {file[1]} ({file[2]})")  # ID - Filename (Timestamp)
    file_listbox.pack(pady=5, fill=tk.BOTH, expand=True)

    def decrypt_selected_file():
        """Decrypts the selected file from the database."""
        selected_index = file_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No file selected!")
            return

        file_id = files[selected_index[0]][0]  # Get file ID
        key = simpledialog.askstring("Decryption Key", "Enter your encryption key:")
        if not key:
            messagebox.showerror("Error", "No key provided!")
            return

        try:
            decrypted_file = decrypt_file(file_id, os.getcwd())  # Save to current directory
            if decrypted_file:
                messagebox.showinfo("Success", f"File decrypted and saved as: {decrypted_file}")
                selection_window.destroy()
            else:
                messagebox.showerror("Error", "Decryption failed.")
        except Exception as e:
            messagebox.showerror("Decryption Error", str(e))

    # Decrypt Button
    decrypt_button = tk.Button(selection_window, text="Decrypt", font=("Arial", 12), command=decrypt_selected_file)
    decrypt_button.pack(pady=10)

# **User Dashboard**
def open_user_dashboard():
    user_window = Toplevel(root)
    user_window.title("User Dashboard")
    user_window.geometry("400x300")

    tk.Button(user_window, text="Encrypt File", font=("Arial", 12), command=open_file_and_encrypt).pack(pady=20)
    tk.Button(user_window, text="Decrypt File", font=("Arial", 12), command=open_database_and_decrypt).pack(pady=20)
    tk.Button(user_window, text="Logout", font=("Arial", 12), command=user_window.destroy).pack(pady=20)

# **Admin Dashboard**
def open_admin_dashboard():
    open_admin_window()  # Open admin panel directly from admin.py

# Buttons
login_btn = tk.Button(root, text="Login", font=("Arial", 12, "bold"), command=login)
login_btn.place(x=100, y=150, width=100)

register_btn = tk.Button(root, text="Register", font=("Arial", 12, "bold"), command=register)
register_btn.place(x=250, y=150, width=100)

# Separate Admin Login Button
admin_login_btn = tk.Button(root, text="Login as Admin", font=("Arial", 12, "bold"), bg="red", fg="white", command=open_admin_dashboard)
admin_login_btn.place(x=150, y=200, width=200)

root.mainloop()