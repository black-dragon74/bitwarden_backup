import base64
from cryptography.fernet import Fernet
import sys


def process_file(action, input_file, output_file, password):
    # Generate the key from the password
    key = base64.urlsafe_b64encode(password.encode().ljust(32)[:32])
    fernet = Fernet(key)

    with open(input_file, 'rb') as f:
        data = f.read()

    # Perform encryption or decryption
    if action == 'encrypt':
        processed_data = fernet.encrypt(data)
    elif action == 'decrypt':
        processed_data = fernet.decrypt(data)
    else:
        print("Invalid action. Use 'encrypt' or 'decrypt'.")
        return 1

    # Write the output file
    with open(output_file, 'wb') as f:
        f.write(processed_data)

    print(f'File {input_file} {action}ed and saved as {output_file}')
    return 0


if __name__ == '__main__':
    if len(sys.argv) != 5:
        print("Usage: python3 crypt.py <encrypt/decrypt> <input_file> <output_file> <password>")
        exit(1)

    a, i, o, p = sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4]

    process_file(a, i, o, p)
