from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import os
from database import store_encrypted_file, retrieve_encrypted_file

def encrypt_file(file_path):
    """Encrypts a file using AES and stores it in the database."""
    key = get_random_bytes(16)  # Generate a random 16-byte key
    cipher = AES.new(key, AES.MODE_EAX)

    with open(file_path, 'rb') as f:
        data = f.read()

    ciphertext, tag = cipher.encrypt_and_digest(data)

    # Store encrypted file in the database
    filename = os.path.basename(file_path)
    store_encrypted_file(filename, cipher.nonce + tag + ciphertext, key)

    print(f"File '{filename}' encrypted and stored successfully.")
    return key.hex()  # Return the encryption key as a hexadecimal string

def decrypt_file(file_id, output_path):
    """Retrieves an encrypted file from the database and decrypts it."""
    result = retrieve_encrypted_file(file_id)

    if result:
        filename, encrypted_data, key = result
        nonce, tag, ciphertext = encrypted_data[:16], encrypted_data[16:32], encrypted_data[32:]

        cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
        data = cipher.decrypt_and_verify(ciphertext, tag)

        decrypted_file_path = os.path.join(output_path, filename)

        with open(decrypted_file_path, 'wb') as f:
            f.write(data)

        print(f"File '{filename}' decrypted successfully and saved to '{decrypted_file_path}'.")
        return decrypted_file_path
    else:
        print("File not found in database.")
        return None