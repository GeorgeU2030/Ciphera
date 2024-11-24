import os
import hashlib

from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives.hashes import SHA256, SHA512, MD5
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.hazmat.backends import default_backend

from src.exceptions.exceptions import DecryptionError

# Dictionary of supported hash algorithms with their respective classes
HASH_ALGORITHMS = {
    'SHA256': SHA256,  # SHA-256 hash algorithm
    'SHA512': SHA512,  # SHA-512 hash algorithm
    'MD5': MD5  # MD5 hash algorithm
}


# Function to derive a cryptographic key from the password using PBKDF2
def derive_key(password: str, salt: bytes, algorithm, iterations: int) -> bytes:
    """
    Derives a key from the given password using the PBKDF2 key derivation function.

    :param password: The password used for key derivation.
    :param salt: The salt to add randomness to the key derivation.
    :param algorithm: The hash algorithm to use for key derivation (SHA256, SHA512, or MD5).
    :param iterations: The number of iterations to perform for key derivation.

    :return: The derived cryptographic key.
    """
    kdf = PBKDF2HMAC(
        algorithm=algorithm(),
        length=32,  # Length of the derived key in bytes
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(password.encode())


# Function to encrypt a file
def encrypt_file(input_file: str, output_file: str, password: str, hash_alg: str, iterations: int):
    """
    Encrypts a file using AES encryption and a key derived from the provided password and hash algorithm.

    :param input_file: The path to the input file to be encrypted.
    :param output_file: The name of the output file to save the encrypted content.
    :param password: The password used for key derivation.
    :param hash_alg: The hash algorithm to use for key derivation (SHA256, SHA512, or MD5).
    :param iterations: The number of iterations to perform for key derivation.
    """
    salt = os.urandom(16)  # Generate a random salt for key derivation
    key = derive_key(password, salt, HASH_ALGORITHMS[hash_alg], iterations)  # Derive the cryptographic key
    iv = os.urandom(16)  # Generate a random initialization vector (IV)

    with open(input_file, 'rb') as f:
        plaintext = f.read()  # Read the plaintext content of the file

    # Calculate the hash of the original file content
    file_hash = hashlib.new(hash_alg.lower(), plaintext).digest()

    # Apply PKCS7 padding to the plaintext data
    packer = PKCS7(algorithms.AES.block_size).padder()
    padded_data = packer.update(plaintext) + packer.finalize()

    # Encrypt the padded data using AES in CBC mode
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    ciphertext = encryptor.update(padded_data) + encryptor.finalize()

    # Save the encrypted content to a file
    output_dir = os.path.join(os.path.dirname(__file__), '../encrypted')
    os.makedirs(output_dir, exist_ok=True)

    output_file = os.path.join(output_dir, output_file)

    with open(output_file, 'wb') as f:
        f.write(salt)  # Write the salt (16 bytes)
        f.write(iv)  # Write the IV (16 bytes)
        f.write(file_hash)  # Write the file hash
        f.write(ciphertext)  # Write the encrypted content

    print(f"File encrypted successfully and saved to '{output_file}'.")


# Function to decrypt a file
def decrypt_file(input_file: str, output_file: str, password: str, hash_alg: str, iterations: int):
    """
    Decrypts a previously encrypted file using AES decryption and the same password, hash algorithm,
    and iterations used for encryption.

    :param input_file: The path to the encrypted input file.
    :param output_file: The name of the output file to save the decrypted content.
    :param password: The password used for key derivation.
    :param hash_alg: The hash algorithm to use for key derivation (SHA256, SHA512, or MD5).
    :param iterations: The number of iterations to perform for key derivation.

    :raises DecryptionError: If the decryption fails due to incorrect password or data integrity issues.
    """
    try:
        # Read the encrypted file components (salt, IV, file hash, and ciphertext)
        with open(input_file, 'rb') as f:
            salt = f.read(16)  # Read the salt
            iv = f.read(16)  # Read the IV
            file_hash = f.read(hashlib.new(hash_alg.lower()).digest_size)  # Read the file hash
            ciphertext = f.read()  # Read the encrypted content

        # Derive the cryptographic key using PBKDF2
        key = derive_key(password, salt, HASH_ALGORITHMS[hash_alg], iterations)

        # Decrypt the ciphertext using AES in CBC mode
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        padded_plaintext = decryptor.update(ciphertext) + decryptor.finalize()

        # Remove the padding using PKCS7 unpadding
        unparsed = PKCS7(algorithms.AES.block_size).unpadder()
        plaintext = unparsed.update(padded_plaintext) + unparsed.finalize()

        # Verify the integrity of the decrypted file by comparing the computed hash with the original file hash
        computed_hash = hashlib.new(hash_alg.lower(), plaintext).digest()
        if computed_hash != file_hash:
            print("Error: The hash does not match.")
            return

        # Save the decrypted content to a file
        output_dir = os.path.join(os.path.dirname(__file__), '../decrypted')

        os.makedirs(output_dir, exist_ok=True)

        output_file = os.path.join(output_dir, output_file.replace("ciphered", ""))
        with open(output_file, 'wb') as f:
            f.write(plaintext)  # Write the decrypted content to the file

        print(f"File decrypted successfully and saved to '{output_file}'.")

    except ValueError:
        raise DecryptionError("The decryption was incorrect. Please check the password, algorithm, and security level.")
