from PyQt6.QtWidgets import QFileDialog

from src.exceptions.exceptions import DecryptionError
from src.logic.crypto import HASH_ALGORITHMS,encrypt_file, decrypt_file
from src.views.alert import show_alert
from PyQt6 import QtCore
import os
import binascii

class CipheraController:
    """
    This class controls the interactions between the view (graphical user interface)
    and the file encryption/decryption operations. It handles user inputs, selects
    the encryption algorithm, sets the security level, and performs file encryption
    and decryption operations based on user-selected options.
    """

    def __init__(self, view):
        """
        Constructor of the class. Initializes variables, sets up the view,
        and connects signals (events) from the graphical interface.

        :param view: The view containing the user interface elements.
        """
        self.view = view
        self.input_file_path = None  # Path of the selected file
        self.is_encrypt = False  # Flag indicating if the file is encrypted
        self.encrypt = True  # Flag to control if the process is encryption
        self.view.SecurityResumeLabel.setText("---")  # Initially empty security resume
        self.load_algotithms()  # Load the available algorithms
        self.view.AlgorithmSelect.currentIndexChanged.connect(self.update_algorithm_resume)  # Connect algorithm selection update
        self.view.HighButton.clicked.connect(lambda: self.set_security_resume("HIGH"))  # Connect high security button
        self.view.MediumButton.clicked.connect(lambda: self.set_security_resume("MEDIUM"))  # Connect medium security button
        self.view.LowButton.clicked.connect(lambda: self.set_security_resume("LOW"))  # Connect low security button
        self.view.CipherButton.clicked.connect(self.cipher_text)  # Connect cipher button
        self.view.LoadResultButton.clicked.connect(self.load_result_file)  # Connect load result file button
        self.view.DecipherButton.clicked.connect(self.decrypt_text)  # Connect decipher button

    def load_algotithms(self):
        """
        Loads the available algorithms from the `HASH_ALGORITHMS` dictionary
        into the algorithm selection combobox in the view.
        """
        for algorithm in HASH_ALGORITHMS:
            self.view.AlgorithmSelect.addItem(algorithm)

    def update_algorithm_resume(self):
        """
        Updates the selected algorithm resume in the view.
        """
        selected_algorithm = self.view.AlgorithmSelect.currentText()
        self.view.AlgorithmResumeLabel.setText(selected_algorithm)

    def set_security_resume(self, level):
        """
        Sets the selected security level and updates the security resume in the view.

        :param level: The security level to set ("HIGH", "MEDIUM", "LOW").
        """
        self.view.SecurityResumeLabel.setText(level)

    def load_file(self):
        """
        Opens a file dialog to select a file and loads its content into the view.
        If the file is a text, it is decoded in UTF-8. If not, the content is displayed in hexadecimal format.
        """
        file_path, _ = QFileDialog.getOpenFileName(None, "Select File", "", "All Files (*)")
        if file_path:
            try:
                with open(file_path, 'rb') as file:  # Open the file in binary mode
                    file_content = file.read()

                try:
                    self.view.textEdit.setPlainText(file_content.decode('utf-8'))
                    # Load the file name into the load button
                    file_name = QtCore.QFileInfo(file_path).fileName()
                    self.view.MessageFile.setText(file_name)
                    self.input_file_path = file_path  # Store the file path

                except UnicodeDecodeError:
                    hex_content = binascii.hexlify(file_content).decode('utf-8')
                    self.input_file_path = file_path
                    self.view.textEdit.setPlainText(hex_content)
                    file_name = QtCore.QFileInfo(file_path).fileName()
                    self.view.MessageFile.setText(file_name)
                    self.is_encrypt = True


            except Exception as e:
                self.view.textEdit.setPlainText(f"Error reading file: {str(e)}")

    def verify_inputs(self, action):
        """
        Verifies the inputs before performing encryption or decryption.
        Checks if the algorithm, security level, password, and text are provided.

        :param action: The action to verify ("encrypt" or "decrypt").
        :return: True if the inputs are valid, False otherwise.
        """
        algorithm = self.view.AlgorithmResumeLabel.text()
        security_level = self.view.SecurityResumeLabel.text()
        password = self.view.PasswordInput.text()
        text = self.view.textEdit.toPlainText()

        if not password:
            show_alert("Password is required.")
            return False

        if not algorithm or algorithm == "---":
            show_alert("Algorithm is required.")
            return False

        if not security_level or security_level == "---":
            show_alert("Security level is required.")
            return False

        if not text:
            show_alert("Text to cipher is required.")
            return False

        if self.is_encrypt and action == "encrypt":
            show_alert("You are attempting to encrypt a file that is already encrypted or contains hexadecimal data. Please provide a text file instead.")
            return False

        if not self.is_encrypt and action == "decrypt":
            show_alert("You are trying to decipher a text. Please, use a cipher file.")
            return False

        return True

    def get_iterations(self):
        """
        Determines the number of iterations based on the selected security level.

        :return: The number of iterations for the selected security level.
        """
        security_level = self.view.SecurityResumeLabel.text()
        if security_level == "HIGH":
            return 300000
        elif security_level == "MEDIUM":
            return 50000
        else:
            return 10000

    def cipher_text(self):
        """
        Encrypts the input text based on the selected algorithm and security level.
        If the inputs are valid, the text is encrypted, and the result is saved in a file.

        :raises: Exception if encryption fails.
        """
        if not self.verify_inputs("encrypt"):
            return

        algorithm = self.view.AlgorithmResumeLabel.text()
        iterations = self.get_iterations()
        password = self.view.PasswordInput.text()
        input_file = self.input_file_path
        file_name = self.view.MessageFile.text().split(".")[0]
        output_file = file_name + "ciphered.txt"

        # Encrypt the text with crypto logic method
        self.encrypt = True
        encrypt_file(input_file, output_file, password, algorithm, iterations)
        self.view.LoadResultButton.show()
        self.view.MessageFile.setText(output_file)

    def load_result_file(self):
        """
        Loads the result file after encryption or decryption and displays its content.
        If the content is in hexadecimal format, it is displayed accordingly.

        :raises: Exception if loading the result file fails.
        """
        output_file_name = self.view.MessageFile.text()
        print(output_file_name)
        if self.encrypt:
            dir_use = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'encrypted'))
        else:
            dir_use = os.path.abspath(os.path.join(os.path.dirname(__file__), '..', 'decrypted'))

        output_file = os.path.join(dir_use, output_file_name)
        try:
            with open(output_file, 'rb') as file:  # Open the file in binary mode
                file_content = file.read()
            try:
                # Try to decode as utf-8
                text_content = file_content.decode('utf-8')
                self.view.textEdit.setPlainText(text_content)
            except UnicodeDecodeError:
                # If it fails, show the hexadecimal content
                hex_content = binascii.hexlify(file_content).decode('utf-8')
                self.view.textEdit.setPlainText(hex_content)
                self.is_encrypt = True

        except Exception as e:
            show_alert(f"Error reading file: {str(e)}")

        self.input_file_path = output_file
        self.view.LoadResultButton.hide()
        self.view.PasswordInput.clear()
        self.view.SecurityResumeLabel.setText("---")

    def decrypt_text(self):
        """
        Decrypts the input file using the selected algorithm, password, and security level.
        The decrypted file is saved with a new name.

        :raises: DecryptionError if decryption fails.
        """
        try:
            if not self.verify_inputs("decrypt"):
                return
            algorithm = self.view.AlgorithmResumeLabel.text()
            iterations = self.get_iterations()
            password = self.view.PasswordInput.text()
            input_file = self.input_file_path
            file_name = self.view.MessageFile.text().split(".")[0]
            output_file = file_name + "decrypted.txt"
            output_file = output_file.replace("ciphered", "")

            # Decrypt the text with decrypt logic method
            self.encrypt = False
            decrypt_file(input_file, output_file, password, algorithm, iterations)
            self.view.LoadResultButton.show()
            self.view.MessageFile.setText(output_file)

        except DecryptionError:
            show_alert("The decryption was wrong. Please, check the password, the algorithm and security level.")
