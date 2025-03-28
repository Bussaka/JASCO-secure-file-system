import tkinter as tk
from tkinter import scrolledtext, messagebox, ttk
from database import list_stored_files, delete_encrypted_file, get_all_users, get_system_logs  # Import database functions

def view_logs():
    """Reads and displays system logs in a scrollable text box."""
    logs = get_system_logs()  # Fetch logs from the database

    # Create a new window for logs
    log_window = tk.Toplevel()
    log_window.title("System Logs")
    log_window.geometry("600x400")

    tk.Label(log_window, text="System Logs", font=("Arial", 14, "bold")).pack(pady=10)

    log_area = scrolledtext.ScrolledText(log_window, wrap=tk.WORD, width=70, height=20)
    log_area.pack(padx=10, pady=5)
    log_area.insert(tk.END, "\n".join([f"{row[2]} - {row[0]}: {row[1]}" for row in logs]))  # Format logs
    log_area.config(state="disabled")  # Prevent editing

def manage_encrypted_files():
    """Opens a window to allow the admin to view and delete encrypted files from the database."""
    files = list_stored_files()
    if not files:
        messagebox.showinfo("Info", "No encrypted files found in the database.")
        return

    # Create a file management window
    file_window = tk.Toplevel()
    file_window.title("Manage Encrypted Files")
    file_window.geometry("500x400")

    tk.Label(file_window, text="Stored Encrypted Files", font=("Arial", 12, "bold")).pack(pady=5)

    # Listbox to display encrypted files
    file_listbox = tk.Listbox(file_window, font=("Arial", 12), width=50, height=15)
    for file in files:
        file_listbox.insert(tk.END, f"{file[0]} - {file[1]} ({file[2]})")  # ID - Filename (Timestamp)
    file_listbox.pack(pady=5, fill=tk.BOTH, expand=True)

    def delete_selected_file():
        """Deletes the selected file from the database."""
        selected_index = file_listbox.curselection()
        if not selected_index:
            messagebox.showerror("Error", "No file selected!")
            return

        file_id = files[selected_index[0]][0]  # Get file ID
        confirm = messagebox.askyesno("Confirm", "Are you sure you want to delete this file?")
        if confirm:
            delete_encrypted_file(file_id)
            messagebox.showinfo("Success", "File deleted successfully.")
            file_window.destroy()  # Close and refresh window

    # Delete Button
    delete_button = tk.Button(file_window, text="Delete Selected File", font=("Arial", 12), command=delete_selected_file)
    delete_button.pack(pady=10)

def show_users():
    """Opens a window to display all users and their positions."""
    users = get_all_users()
    if not users:
        messagebox.showinfo("Info", "No users found in the database.")
        return

    user_window = tk.Toplevel()
    user_window.title("User Database")
    user_window.geometry("500x400")

    tk.Label(user_window, text="User List", font=("Arial", 12, "bold")).pack(pady=5)

    # Table to display users
    user_table = ttk.Treeview(user_window, columns=("Username", "Position"), show="headings")
    user_table.heading("Username", text="Username")
    user_table.heading("Position", text="Position")
    user_table.pack(padx=10, pady=5, fill=tk.BOTH, expand=True)

    for user in users:
        user_table.insert("", "end", values=user)

def open_admin_window():
    """Opens the admin panel window."""
    admin_window = tk.Toplevel()
    admin_window.title("Admin Panel")
    admin_window.geometry("400x350")

    tk.Label(admin_window, text="Admin Panel - Log Monitoring", font=("Arial", 12, "bold")).pack(pady=10)

    tk.Button(admin_window, text="View Logs", command=view_logs, width=20).pack(pady=5)
    tk.Button(admin_window, text="Manage Encrypted Files", command=manage_encrypted_files, width=20).pack(pady=5)
    tk.Button(admin_window, text="Show User Database", command=show_users, width=20).pack(pady=5)

if __name__ == "__main__":
    root = tk.Tk()
    root.title("Admin Panel")
    root.geometry("300x250")

    tk.Label(root, text="Admin Panel", font=("Arial", 14, "bold")).pack(pady=10)
    tk.Button(root, text="View Logs", command=view_logs, width=20).pack(pady=5)
    tk.Button(root, text="Manage Encrypted Files", command=manage_encrypted_files, width=20).pack(pady=5)
    tk.Button(root, text="Show User Database", command=show_users, width=20).pack(pady=5)

    root.mainloop()