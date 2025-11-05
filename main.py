import sys
import os
import zipfile
import tempfile
from pathlib import Path

from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QMessageBox, QAction,
    QToolBar, QStatusBar
)
from PyQt5.QtGui import QKeySequence, QIcon
from PyQt5.QtCore import Qt

from des_alg import encryption, decryption
from designer.DES import Ui_MainWindow



class MainWindow(QMainWindow, Ui_MainWindow):
    """
    Main window class for the DES encryption/decryption application.
    Inherits from QMainWindow and Ui_MainWindow.
    """

    LIGHT_STYLE = ""  # Align with the system default
    DARK_STYLE = """
        QWidget { background: #2b2b2b; color: #e6e6e6; }
        QLineEdit, QTextEdit, QPlainTextEdit { background: #353535; color: #e6e6e6; }
        QPushButton { background: #3c3c3c; border: 1px solid #4d4d4d; padding: 4px; }
        QToolBar { background: #2b2b2b; }
    """


    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setupUi(self)
        self.file_path = ''  # Path of the file to be read
        self.use_file = False  # Whether the user imports the file
        self.zip_file_name = ''  # File name to be compressed
        self.file_name = ''  # File name after decompression
        self.mode = ''  # Encryption mode or decryption mode
        self.result = bytes()  # Encryption or decryption result in bytes
        self.dark_theme = False

        # Add toolbar
        self._create_toolbar()

        # Connect buttons to their respective functions
        self.selectFile_btn.clicked.connect(self.select_file)
        self.cipher_btn.clicked.connect(self.encryption)
        self.decipher_btn.clicked.connect(self.decryption)

    # -----------------------
    # Toolbar / Actions
    # -----------------------
    def _create_toolbar(self):
        toolbar = QToolBar("Main Toolbar", self)
        toolbar.setMovable(False)
        self.addToolBar(toolbar)

        # Save output
        save_act = QAction(QIcon.fromTheme("document-save"), "Save output...", self)
        save_act.setShortcut(QKeySequence.Save)
        save_act.triggered.connect(self.save_output_dialog)
        toolbar.addAction(save_act)

        toolbar.addSeparator()

        # Copy output
        copy_act = QAction(QIcon.fromTheme("edit-copy"), "Copy output", self)
        copy_act.setShortcut(QKeySequence.Copy)
        copy_act.triggered.connect(self.copy_output)
        toolbar.addAction(copy_act)

        # Clear input/output
        clear_act = QAction(QIcon.fromTheme("edit-clear"), "Clear", self)
        clear_act.setShortcut("Ctrl+L")
        clear_act.triggered.connect(self.clear_io)
        toolbar.addAction(clear_act)

        toolbar.addSeparator()

        # Theme toggle
        self.theme_act = QAction("Dark Theme", self)
        self.theme_act.setCheckable(True)
        self.theme_act.setChecked(self.dark_theme)
        self.theme_act.triggered.connect(self.toggle_theme)
        toolbar.addAction(self.theme_act)

        # Quick help
        help_act = QAction("About", self)
        help_act.triggered.connect(self.show_about)
        toolbar.addAction(help_act)

    # Sets the mode to 'encrypt' and calls the mainDES function.
    def encryption(self):
        self.mode = 'encrypt'
        self.mainDES()

    # Sets the mode to 'decrypt' and calls the mainDES function.
    def decryption(self):
        self.mode = 'decrypt'
        self.mainDES()

    # Main function to handle DES encryption and decryption.
    def mainDES(self):
        key = self.key_edit.text()    # Get the key and text from the Edit control object
        text = self.input_edit.toPlainText()
        # Clear the previous result
        self.result = bytes()

        # Check if key and text are provided
        if not key or not text:
            # Both key and plaintext are missing
            if not key and not text:
                msg = "key and {}text".format('plain' if self.mode == 'encrypt' else 'cipher')
            # Only key is missing
            elif not key:
                msg = "key"
            # Only plaintext is missing
            else:
                msg = "{}text".format('plain' if self.mode == 'encrypt' else 'cipher')
            # Display warning message
            QMessageBox.warning(self, 'Warning', 'You have not entered the {}'.format(msg), QMessageBox.Ok)
            return

        # Perform encryption or decryption
        # Select file mode
        if self.use_file:
            # Perform encryption, utf-8 encoding
            if self.mode == 'encrypt':
                self.compress_file()
                file_name = self.zip_file_name
            # Perform decryption, ascii encoding
            elif self.mode == 'decrypt':
                file_name = self.file_path
            with open(file_name, 'rb') as f:
                text = f.read()
        # Input text mode
        else:
            if self.mode == 'encrypt':
                text = text.encode()
            elif self.mode == 'decrypt':
                t = bytes()
                for i in text:
                    t += ord(i).to_bytes(1, byteorder='little')
                text = t

        # Convert key to binary and adjust length
        key = key.encode('utf-8')
        # Ensure key is exactly 8 bytes long
        # If key is shorter than 8 bytes, pad with '\0' until it is
        while len(key) < 8:
            key += '\0'.encode()
        # If key is longer than 8 bytes, truncate it
        if len(key) > 8:
            key = key[:8]
        # If text length is not a multiple of 8 bytes, pad with '\0' until it is
        while len(text) % 8 != 0:
            text += '\0'.encode()

        # Key processing
        key = [int(i) for i in ''.join([bin(i)[2:].rjust(8, '0') for i in key])]

        # Text processing
        for i in range(0, len(text), 8):
            # Group every 8 bytes
            if i % 8 == 0:
                # Convert to an array of length 64 consisting of 01 numbers
                input = [int(i) for i in ''.join([bin(i)[2:].rjust(8, '0') for i in text[i:i + 8]])]
                # Encrypt the key and text to get the result and output a string of length 64 consisting of 01
                output = ''.join(
                    [str(i) for i in (encryption(input, key) if self.mode == 'encrypt' else decryption(input, key))])

                result = bytes()
                for j in range(8):
                    byte_str = '0b' + output[j * 8:(j + 1) * 8]
                    byte = int(byte_str, 2).to_bytes(1, byteorder='little')
                    result += byte
                self.result += result

        # Select file mode
        if self.use_file:
            if self.mode == 'encrypt':
                self.save_file()
            elif self.mode == 'decrypt':
                self.uncompress_file()
        # Input text mode
        else:
            if self.mode == 'encrypt':
                result = "".join([chr(i) for i in self.result])
            elif self.mode == 'decrypt':
                result = self.result.decode()
            self.output_edit.setText('{}text: \n{}'.format('Cipher' if self.mode == 'encrypt' else 'Plain', result))

        # Reset the file path and use file flag
        self.file_path = ''
        self.use_file = False

    # Opens a file dialog to select a file and sets the file path.
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File', './', 'All Files (*)')
        if file_path:
            self.file_path = file_path
            self.use_file = True
            self.input_edit.setText('File selected: ' + self.file_path)


    # Saves the encrypted file to disk.
    def save_file(self):
        encrypted_file_path = self.file_path.replace('.', '(encrypted).')
        with open(encrypted_file_path, 'wb') as f:
            f.write(self.result)
        self.output_edit.setText('File saved: ' + encrypted_file_path)

    # Compresses the selected file into a zip archive.
    def compress_file(self):
        # Extract the file name without the path
        base_file_name = self.file_path.split('/')[-1]
        # Create a zip file name based on the base file name
        zip_file_name = f"{base_file_name.split('.')[0]}.zip"
        # Modify the file name inside the zip to indicate it has been encrypted or processed
        internal_file_name = f"encrypted_{base_file_name}"

        # Store the zip file name and the internal file name for later use
        self.zip_file_name = zip_file_name
        self.file_name = internal_file_name

        try:
            # Create and write to the zip file
            with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_BZIP2) as zf:
                zf.write(self.file_path, internal_file_name)
        except Exception as e:
            print(f"Error compressing file: {e}")
            QMessageBox.warning(self, 'Warning', 'An error occurred while compressing the file.', QMessageBox.Ok)
            return

    # Uncompresses the zip archive and extracts the file.
    def uncompress_file(self):
        # Determine the directory path to store the uncompressed files, same as the current file directory
        file_path = '/'.join(self.file_path.split("/")[:-1]) + '/'

        try:
            # Open the zipfile and extract all contents to the specified directory
            with zipfile.ZipFile(self.zip_file_name, 'r') as zf:
                zf.extractall(file_path)
            # Update the text browser widget to show where the file has been saved
            self.output_edit.setText(f"File decryption results have been saved to {file_path + self.file_name}")
        except Exception as e:
            # Handle exceptions and print an error message if an issue occurs during extraction
            self.output_edit.setText(f"Error during file extraction: {e}")


if __name__ == '__main__':
    # Instantiate the application and pass in arguments
    app = QApplication(sys.argv)
    # Create the main window object
    mainWindow = MainWindow()
    # Set the window title
    mainWindow.setWindowTitle('DES Tool - 22372126 Qiyue Zhu')
    # Show the window
    mainWindow.show()
    # Exit the application
    sys.exit(app.exec_())
