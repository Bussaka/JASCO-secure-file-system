import os
import tkinter as tk
from tkinter import filedialog, messagebox, Toplevel, simpledialog, ttk
from PIL import Image, ImageTk
import pyperclip  # For copying encryption key
from backend import encrypt_file, decrypt_file
from auth import login_user, register_user
from admin import open_admin_window
from database import get_user_files, get_all_users  # Import database functions

# Initialize main window
root = tk.Tk()
root.title("JASCO Secure File System")
root.geometry("500x600")

# Load background image
try:
    bg_image = Image.open("background.jpg")  # Ensure this file exists
    bg_image = bg_image.resize((500, 600))
    bg_photo = ImageTk.PhotoImage(bg_image)

    bg_label = tk.Label(root, image=bg_photo)
    bg_label.place(relwidth=1, relheight=1)
except Exception as e:
    messagebox.showwarning("Warning", f"Background image error: {str(e)}")

# Username & Password Fields
tk.Label(root, text="Username:", font=("Arial", 12, "bold")).place(x=50, y=50)
username_entry = tk.Entry(root, font=("Arial", 12))
username_entry.place(x=150, y=50, width=250)

tk.Label(root, text="Password:", font=("Arial", 12, "bold")).place(x=50, y=100)
password_entry = tk.Entry(root, font=("Arial", 12), show="*")
password_entry.place(x=150, y=100, width=250)

tk.Label(root, text="Position:", font=("Arial", 12, "bold")).place(x=50, y=150)

# Dropdown for position selection
POSITIONS = [
    "CEO", "HR Manager", "Office Admin", "Finance Manager", "Accountant",
    "IT Manager", "IT Support Technician", "Sales Manager",
    "Operations Manager", "Secretary", "Compliance Officer"
]

position_var = tk.StringVar()
position_dropdown = ttk.Combobox(root, textvariable=position_var, values=POSITIONS)
position_dropdown.place(x=150, y=150, width=250)
position_dropdown.current(0)  # Default selection

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
        open_user_dashboard(username)
    elif user_type == "admin":
        messagebox.showinfo("Success", "Admin Login Successful!")
        open_admin_dashboard()
    else:
        messagebox.showerror("Error", "Invalid username or password")

# **Register Function**
def register():
    username = username_entry.get()
    password = password_entry.get()
    position = position_var.get()

    if not username or not password:
        messagebox.showerror("Error", "All fields are required!")
        return

    success = register_user(username, password, position)
    if success:
        messagebox.showinfo("Success", "Registration Successful!")
    else:
        messagebox.showerror("Error", "User already exists!")

# **Encrypt File Function**
def open_file_and_encrypt(user):
    """Opens file dialog for selecting a file to encrypt and stores it in the database."""
    file_path = filedialog.askopenfilename(title="Select a file to encrypt")
    if not file_path:
        messagebox.showerror("Error", "No file selected!")
        return

    recipient = select_recipient()
    if not recipient:
        return

    try:
        encryption_key = encrypt_file(file_path, user, recipient)

        # Show encryption key in a pop-up window
        key_window = Toplevel(root)
        key_window.title("Encryption Key")
        key_window.geometry("400x200")

        tk.Label(key_window, text="Encryption Key:", font=("Arial", 12, "bold")).pack(pady=10)

        key_entry = tk.Entry(key_window, font=("Arial", 12), width=40)
        key_entry.insert(0, encryption_key)
        key_entry.pack(pady=5)
        key_entry.config(state="readonly")

        def copy_key():
            pyperclip.copy(encryption_key)
            messagebox.showinfo("Copied", "Encryption key copied to clipboard!")

        copy_button = tk.Button(key_window, text="Copy Key", font=("Arial", 12), command=copy_key)
        copy_button.pack(pady=10)

        close_button = tk.Button(key_window, text="Close", font=("Arial", 12), command=key_window.destroy)
        close_button.pack(pady=5)

        messagebox.showinfo("Success", "File encrypted and stored in the database.")

    except Exception as e:
        messagebox.showerror("Encryption Error", str(e))

# **Select Recipient Function**
def select_recipient():
    """Opens a window to select a recipient from the database."""
    users = get_all_users()
    if not users:
        messagebox.showerror("Error", "No users found!")
        return None

    recipient_window = Toplevel(root)
    recipient_window.title("Select Recipient")
    recipient_window.geometry("400x300")

    tk.Label(recipient_window, text="Select Recipient:", font=("Arial", 12, "bold")).pack(pady=5)

    recipient_var = tk.StringVar()
    recipient_dropdown = ttk.Combobox(recipient_window, textvariable=recipient_var, values=[user[0] for user in users])
    recipient_dropdown.pack(pady=5)
    recipient_dropdown.current(0)

    def confirm_recipient():
        recipient_window.destroy()

    confirm_button = tk.Button(recipient_window, text="Confirm", font=("Arial", 12), command=confirm_recipient)
    confirm_button.pack(pady=10)

    recipient_window.wait_window()
    return recipient_var.get()

# **Decrypt File Function**
def open_database_and_decrypt(user):
    """Allows a user to decrypt only files sent to them."""
    files = get_user_files(user)
    if not files:
        messagebox.showerror("Error", "No encrypted files available for you.")
        return

    selection_window = Toplevel(root)
    selection_window.title("Select a File to Decrypt")
    selection_window.geometry("400x300")

    tk.Label(selection_window, text="Select a file to decrypt:", font=("Arial", 12, "bold")).pack(pady=5)

    file_listbox = tk.Listbox(selection_window, font=("Arial", 12))
    for file in files:
        file_listbox.insert(tk.END, f"{file[0]} - {file[1]}")
    file_listbox.pack(pady=5, fill=tk.BOTH, expand=True)

    def decrypt_selected_file():
        selected_index = file_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No file selected!")
            return

        file_id = files[selected_index[0]][0]
        key = simpledialog.askstring("Decryption Key", "Enter your encryption key:")
        if not key:
            messagebox.showerror("Error", "No key provided!")
            return

        decrypted_file = decrypt_file(user, file_id, os.getcwd())
        if decrypted_file:
            messagebox.showinfo("Success", f"File decrypted and saved as: {decrypted_file}")
            selection_window.destroy()
        else:
            messagebox.showerror("Error", "Decryption failed.")

    decrypt_button = tk.Button(selection_window, text="Decrypt", font=("Arial", 12), command=decrypt_selected_file)
    decrypt_button.pack(pady=10)

# **Admin & User Dashboards**
def open_user_dashboard(user):
    user_window = Toplevel(root)
    user_window.title("User Dashboard")
    tk.Button(user_window, text="Encrypt File", font=("Arial", 12), command=lambda: open_file_and_encrypt(user)).pack(pady=20)
    tk.Button(user_window, text="Decrypt File", font=("Arial", 12), command=lambda: open_database_and_decrypt(user)).pack(pady=20)

def open_admin_dashboard():
    open_admin_window()

# **Add Buttons to Main Window**
login_button = tk.Button(root, text="Login", font=("Arial", 12), command=login)
login_button.place(x=150, y=200, width=100)

register_button = tk.Button(root, text="Register", font=("Arial", 12), command=register)
register_button.place(x=270, y=200, width=100)

admin_login_button = tk.Button(root, text="Login as Admin", font=("Arial", 12), command=open_admin_dashboard)
admin_login_button.place(x=150, y=250, width=220)

# Run the application
root.mainloop()