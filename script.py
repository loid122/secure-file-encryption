from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
import secrets
import argparse
import sys

# Generating RSA pairs
def creating_rsa_pairs():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key = private_key.public_key()

    privatekey_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )

    publickey_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    return [publickey_pem, privatekey_pem]

# Saving rsa keys 
def save_rsa_keys_as_pem_file(keys_list):
    with open('public_key.pem', 'wb') as f:
        f.write(keys_list[0])
    print('Public key saved as public_key.pem')
    with open('private_key.pem', 'wb') as f:
        f.write(keys_list[1])
    print('Private key saved as private_key.pem')

def read_files(filename):
    with open(filename, 'rb') as f:
        return f.read()

# Reading pem specific file format files
def read_public_pem_file(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_public_key(f.read())

def read_private_pem_file(filename):
    with open(filename, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)

# Encrypting plaintext file using AES-GCM 
def aesgcm_encrypt(plaintext_file):
    aes_key = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)
    cipher = Cipher(algorithms.AES(aes_key), modes.GCM(nonce), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(read_files(plaintext_file)) + encryptor.finalize()
    tag = encryptor.tag
    return [ciphertext, aes_key, nonce, tag]

# Encrypting plaintext data using generated rsa publickey
def encrypt_data_with_rsa(data, publickey_file):
    encrypted_data = read_public_pem_file(publickey_file).encrypt(
        data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return encrypted_data

# Saving the encrypted file in a specific format
def saving_encrypted_file(encrypted_aes_key, nonce, tag, ciphertext, plaintext_file):
    with open(plaintext_file + '.enc', 'wb') as f:
        f.write(nonce + tag + encrypted_aes_key + ciphertext)
    print(f'Encrypted data saved as {plaintext_file}.enc')

def encrypt_file(plaintext_file):
    rsa_keys_list = creating_rsa_pairs()                                                     # Generating pairs         
    save_rsa_keys_as_pem_file(rsa_keys_list)                                                 # Saving rsa files in pem file format
    ciphertext, aes_key, nonce, tag = aesgcm_encrypt(plaintext_file)                         # Encrypting plaintext file 
    encrypted_aes_key = encrypt_data_with_rsa(aes_key, 'public_key.pem')                     # Encrypting AES-GCM's aes_key with rsa
    saving_encrypted_file(encrypted_aes_key, nonce, tag, ciphertext, plaintext_file)         # Saving the ciphertext and other data in specific format

# Decrypting data with rsa privatekey
def decrypt_data_with_rsa(encrypted_data, privatekey_file):
    private_key = read_private_pem_file(privatekey_file)
    decrypted_data = private_key.decrypt(
        encrypted_data,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None,
        ),
    )
    return decrypted_data

# Decrypting ciphertext using AES-GCM decryption
def aes_gcm_decrypt(ciphertext, aes_key, nonce, tag):
    decryptor = Cipher(algorithms.AES(aes_key), modes.GCM(nonce, tag), backend=default_backend()).decryptor()
    return decryptor.update(ciphertext) + decryptor.finalize()

# Decrypting them step by step
def decrypt_file(encrypted_file):
    with open(encrypted_file, 'rb') as f:
        nonce = f.read(12) 
        tag = f.read(16)    
        encrypted_aes_key = f.read(256)  
        ciphertext = f.read()  

    aes_key = decrypt_data_with_rsa(encrypted_aes_key, 'private_key.pem')       # Decrypting the encrypted_aes_key with rsa

    plaintext = aes_gcm_decrypt(ciphertext, aes_key, nonce, tag)                # Decrypting the ciphertext using the decrypted aes_key 
    return plaintext

# Saving decrypted file
def saving_decrypted_file(decrypted_data, encrypted_file):
    output_filename = encrypted_file.replace('.enc', '.dec')
    with open(output_filename, 'wb') as f:
        f.write(decrypted_data)
    print(f'Decrypted data saved as {output_filename}')

def main():
    # Define the argument parser with a custom usage example
    parser = argparse.ArgumentParser(
        description="Encrypt or decrypt files using RSA and AES-GCM.",
        epilog="Example usage:\n"
               "  python script.py encrypt plaintextfile.txt\n"
               "  python script.py decrypt plaintextfile.txt.enc",
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    parser.add_argument('action', choices=['encrypt', 'decrypt'], help="Action to perform: 'encrypt' or 'decrypt'")
    parser.add_argument('file', help="File to encrypt or decrypt")
    
    # If no arguments are provided, show the help message
    if len(sys.argv) == 1:
        parser.print_help(sys.stderr)
        sys.exit(1)

    args = parser.parse_args()

    if args.action == 'encrypt':
        encrypt_file(args.file)
    elif args.action == 'decrypt':
        decrypted_data = decrypt_file(args.file)
        saving_decrypted_file(decrypted_data, args.file)

if __name__ == "__main__":
    main()