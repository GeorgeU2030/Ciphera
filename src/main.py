# Test the application without GUI
from src.logic.crypto import HASH_ALGORITHMS, encrypt_file, decrypt_file

# Function to test the application without GUI
def main():
    # Print the options, Menu
    print("Options:")
    print("1) Cipher file")
    print("2) Decipher file")
    choice = input("Select an option: ").strip()

    # Validate the choice, algorithm, and iterations
    print("\nOptions of Algorithms: ", ", ".join(HASH_ALGORITHMS.keys()))
    hash_alg = input("Select the algorithm hash: ").strip().upper()
    if hash_alg not in HASH_ALGORITHMS:
        print("Algorithm is not supported.")
        return

    iterations = int(input("Enter the number of iterations (is recommended between 100,000 y 1,000,000): ").strip())
    if iterations < 100000 or iterations > 1000000:
        print("Out of range, try again.")
        return

    # Cipher or Decipher the file
    # Encrypt the file
    if choice == '1':
        input_file = input("Enter the name of the file: ").strip()
        output_file = input("Enter the name of the cipher file that you want: ").strip()
        password = input("Enter the password: ").strip()
        encrypt_file(input_file, output_file, password, hash_alg, iterations)
    # Decrypt the file
    elif choice == '2':
        input_file = input("Enter the name of the file: ").strip()
        output_file = input("Enter the name of the cipher file that you want: ").strip()
        password = input("Enter the password: ").strip()
        decrypt_file(input_file, output_file, password, hash_alg, iterations)
    else:
        print("Ups something went wrong.")

if __name__ == "__main__":
    main()