import argparse
import bcrypt
import os
import getpass
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
import base64

def derive_key(pwd, salt):
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        iterations=600_000,
        salt = salt,
    )
    return base64.urlsafe_b64encode(kdf.derive(pwd.encode()))

def encrypt_file(path):
    password = getpass.getpass("Enter encryption password: ")
    salt = os.urandom(16)
    key = derive_key(password, salt)

    with open(path, 'rb') as file:
        data = file.read()

    f = Fernet(key)
    enc_data = f.encrypt(data)
    with open(path + ".enc", "wb") as file:
        file.write(salt + enc_data)
    print(f"File encrypted successfully at {path}.enc")

def decrypt_file(path):
    password = getpass.getpass("Enter decryption password: ")

    with open(path, 'rb') as file:
        file_data = file.read()

    salt = file_data[:16] #extract salt from first 16 bytes
    cipher = file_data[16:] #rest of the encrypted data of file
    key = derive_key(password, salt)
    f = Fernet(key)

    try:
        decrypted_data = f.decrypt(cipher)
    except Exception:
        print("Invalid password or corrupted file")

    original_file = path.replace(".enc", "")
    with open(original_file, 'wb') as file:
        file.write(decrypted_data)

    os.remove(path)
    print(f"Decrypted successfully at {original_file}")
        

    
    
def main():
    parser = argparse.ArgumentParser(description="Encrypt or Decrypt a file using a password")
    parser.add_argument("-e", "--encrypt", metavar="FILE", help="Encrypt a file")
    parser.add_argument("-d", "--decrypt", metavar="FILE", help="Decrypt a file")
    
    args = parser.parse_args()

    if args.encrypt:
        encrypt_file(args.encrypt)
    elif args.decrypt:
        decrypt_file(args.decrypt)
    else:
        argparse.print_help()

if __name__ == "__main__":
    main()
