import sys

from PyQt6 import QtWidgets

from src.views.ciphera import CipheraWindow

# Main function and file for the GUI application, runs the application
if __name__ == "__main__":
    app = QtWidgets.QApplication(sys.argv)
    window = CipheraWindow()
    window.show()
    sys.exit(app.exec())