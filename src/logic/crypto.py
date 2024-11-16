import os
import hashlib
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256, SHA512, MD5
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

HASH_ALGORITHMS = {
    'SHA256': SHA256,
    'SHA512': SHA512,
    'MD5': MD5
}

# Function to derive a key with PBKDF2
def derive_key(password: str, salt: bytes, algorithm, iterations: int) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=algorithm(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())

# Function to cipher a file
def encrypt_file(input_file: str, output_file: str, password: str, hash_alg: str, iterations: int):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt, HASH_ALGORITHMS[hash_alg], iterations)  # Derive the key
    iv = os.urandom(16)  # Initialization Vector

    with open(input_file, 'rb') as f:
        plaintext = f.read()

    # Calculate the hash from original file
    file_hash = hashlib.new(hash_alg.lower(), plaintext).digest()

    # Cipher the content
    packer = PKCS7(algorithms.AES.block_size).padder()
    padded_data = packer.update(plaintext) + packer.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Write the ciphered file
    with open(output_file, 'wb') as f:
        f.write(salt)  # 16 bytes
        f.write(iv)  # 16 bytes
        f.write(file_hash)  # Size
        f.write(ciphertext)  # Ciphered content

    print(f"File ciphered correctly in '{output_file}'.")

# Function to decipher a file
def decrypt_file(input_file: str, output_file: str, password: str, hash_alg: str, iterations: int):
    with open(input_file, 'rb') as f:
        salt = f.read(16)  # Read the Salt
        iv = f.read(16)    # Read the iv
        file_hash = f.read(hashlib.new(hash_alg.lower()).digest_size)  # Read the hash
        ciphertext = f.read()   # Read the ciphered content

    key = derive_key(password, salt, HASH_ALGORITHMS[hash_alg], iterations)  # Derive the key

    # Decipher the content
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decrypt = cipher.decryptor()
    padded_plaintext = decrypt.update(ciphertext) + decrypt.finalize()

    # Remove the padding
    unparsed = PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unparsed.update(padded_plaintext) + unparsed.finalize()

    # Verify the integrity
    computed_hash = hashlib.new(hash_alg.lower(), plaintext).digest()
    if computed_hash != file_hash:
        print("Error: the hash does not match.")
        return

    # Write the deciphered file
    with open(output_file, 'wb') as f:
        f.write(plaintext)

    print(f"File deciphered correctly in '{output_file}'.")