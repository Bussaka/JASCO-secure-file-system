from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from database import save_encrypted_file, get_user_files, log_event  # Fixed import

def encrypt_file(file_path, sender, recipient):
    """Encrypts a file using AES and stores it in the database with sender and recipient details."""
    key = get_random_bytes(16)  # Generate a random 16-byte key
    cipher = AES.new(key, AES.MODE_EAX)

    with open(file_path, 'rb') as f:
        data = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Store encrypted file in the database
    filename = os.path.basename(file_path)
    save_encrypted_file(sender, recipient, filename, cipher.nonce + tag + ciphertext, key.hex())

    # Log encryption event
    log_event(sender, f"ENCRYPTED FILE '{filename}' AND SENT TO {recipient}")

    print(f"File '{filename}' encrypted and stored successfully.")
    return key.hex()  # Return the encryption key as a hexadecimal string

def decrypt_file(user, file_id, output_path):
    """Retrieves an encrypted file from the database and decrypts it."""
    files = get_user_files(user)  # Fetch files for the user

    # Find the file with the given ID
    selected_file = None
    for file in files:
        if file[0] == file_id:
            selected_file = file
            break

    if selected_file:
        filename, encrypted_data, key = selected_file[1], selected_file[2], selected_file[3]
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]

        cipher = AES.new(bytes.fromhex(key), AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        decrypted_file_path = os.path.join(output_path, filename)

        with open(decrypted_file_path, 'wb') as f:
            f.write(data)

        # Log decryption event
        log_event(user, f"DECRYPTED FILE '{filename}'")

        print(f"File '{filename}' decrypted successfully and saved to '{decrypted_file_path}'.")
        return decrypted_file_path
    else:
        print("File not found or access denied.")
        return None
