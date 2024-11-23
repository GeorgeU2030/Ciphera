from PyQt6.QtWidgets import QFileDialog
from src.logic.crypto import HASH_ALGORITHMS,encrypt_file, decrypt_file
from src.views.alert import show_alert
from PyQt6 import QtCore
import os
import binascii

class CipheraController:

    # Constructor - load the initial values and change the information according to the selected options
    def __init__(self, view):
        self.view = view
        self.input_file_path = None
        self.is_encrypt = False
        self.view.SecurityResumeLabel.setText("---")
        self.load_algotithms()
        self.view.AlgorithmSelect.currentIndexChanged.connect(self.update_algorithm_resume)
        self.view.HighButton.clicked.connect(lambda: self.set_security_resume("HIGH"))
        self.view.MediumButton.clicked.connect(lambda: self.set_security_resume("MEDIUM"))
        self.view.LowButton.clicked.connect(lambda: self.set_security_resume("LOW"))
        self.view.CipherButton.clicked.connect(self.cipher_text)
        self.view.LoadResultButton.clicked.connect(self.load_result_file)
        self.view.DecipherButton.clicked.connect(self.decrypt_text)

    # Load the algorithms into the combobox, from the dictionary HASH_ALGORITHMS
    def load_algotithms(self):
        for algorithm in HASH_ALGORITHMS:
            self.view.AlgorithmSelect.addItem(algorithm)

    # Update the label with the selected algorithm
    def update_algorithm_resume(self):
        selected_algorithm = self.view.AlgorithmSelect.currentText()
        self.view.AlgorithmResumeLabel.setText(selected_algorithm)

    # Set the security level according to the button clicked
    def set_security_resume(self, level):
        self.view.SecurityResumeLabel.setText(level)

    def load_file(self):
        # Open the file dialog for select the file
        file_path, _ = QFileDialog.getOpenFileName(None, "Select File", "", "All Files (*)")
        if file_path:
            try:
                with open(file_path, 'rb') as file:  # Open the file in binary mode
                    file_content = file.read()

                try:
                    self.view.textEdit.setPlainText(file_content.decode('utf-8'))
                    # Load the file name in load button
                    file_name = QtCore.QFileInfo(file_path).fileName()
                    self.view.MessageFile.setText(file_name)
                    self.input_file_path = file_path  # Store the file path

                except UnicodeDecodeError:
                    hex_content = binascii.hexlify(file_content).decode('utf-8')
                    self.view.textEdit.setPlainText(hex_content)
                    self.is_encrypt = True


            except Exception as e:
                self.view.textEdit.setPlainText(f"Error reading file: {str(e)}")


    # Verify the inputs before ciphering
    def verify_inputs(self):
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

        if self.is_encrypt:
            show_alert("You are trying to cipher a hexadecimal or cipher file. Please, use a text.")
            return False


        return True

    def get_iterations(self):
        security_level = self.view.SecurityResumeLabel.text()
        if security_level == "HIGH":
            return 300000
        elif security_level == "MEDIUM":
            return 50000
        else:
            return 10000

    # Cipher the text
    def cipher_text(self):
        print("Hola carlitos, está conectado")
        if not self.verify_inputs():
            return

        algorithm = self.view.AlgorithmResumeLabel.text()
        iterations = self.get_iterations()
        password = self.view.PasswordInput.text()
        input_file = self.input_file_path
        file_name = self.view.MessageFile.text().split(".")[0]
        output_file = file_name + "ciphered.txt"

        # Cipher the text with crypto logic method
        encrypt_file(input_file, output_file, password, algorithm, iterations)

        self.view.LoadResultButton.show()
        self.view.MessageFile.setText(output_file)

    def load_result_file(self):
        output_file_name = self.view.MessageFile.text()
        output_file = os.path.join(os.path.dirname(__file__), '../encrypted', output_file_name)
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

        self.view.LoadResultButton.hide()
        self.view.PasswordInput.clear()
        self.view.SecurityResumeLabel.setText("---")

    #Decrypt text
    def decrypt_text(self):
        if not self.verify_inputs():
            return
        algorithm = self.view.AlgorithmResumeLabel.text()
        iterations = self.get_iterations()
        password = self.view.PasswordInput.text()
        input_file = self.input_file_path
        file_name = self.view.MessageFile.text().split(".")[0]
        output_file = file_name + "decrypted.txt"

        #Decrypt the text with decrypt logic method
        decrypt_file(input_file, output_file, password, algorithm, iterations)
        self.view.LoadResultButton.show()
        self.view.MessageFile.setText(output_file)


