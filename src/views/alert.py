from PyQt6.QtWidgets import QMessageBox

def show_alert(message, icon=QMessageBox.Icon.Warning):
    alert = QMessageBox()
    alert.setIcon(icon)
    alert.setText(message)
    alert.setWindowTitle("Warning - Input Validation")
    alert.setStyleSheet("""
            QMessageBox {
                background-color: white;
                font-size: 14px;
            }
            QMessageBox QLabel {
                color: black;
            }
            QMessageBox QPushButton {
                background-color: rgb(94, 20, 250);
                color: white;
                border-radius: 5px;
                padding: 5px;
            }
            QMessageBox QPushButton:hover {
                background-color: rgb(94, 20, 250);
            }
    """)
    alert.exec()