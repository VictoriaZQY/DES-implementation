import sys
import zipfile

from PyQt5.QtCore import Qt
from PyQt5.QtGui import QFont, QIcon, QClipboard
from PyQt5.QtWidgets import (
    QApplication,
    QMainWindow,
    QWidget,
    QFileDialog,
    QMessageBox,
    QLabel,
    QLineEdit,
    QTextEdit,
    QPushButton,
    QHBoxLayout,
    QVBoxLayout,
    QSplitter,
    QSizePolicy, QStyle,
)

# algorithm imports
from des_alg import encryption, decryption


class MainWindow(QMainWindow):
    """
    Main window class for the DES encryption/decryption application.
    Inherits from QMainWindow and Ui_MainWindow.
    """

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)

        # Initialize state variables
        self.file_path = ''  # Path of the file to be read
        self.use_file = False  # Whether the user imports the file
        self.zip_file_name = ''  # File name to be compressed
        self.file_name = ''  # File name after decompression
        self.mode = ''  # Encryption mode or decryption mode
        self.result = bytes()  # Encryption or decryption result in bytes

        # --- build UI programmatically ---
        self.setMinimumSize(700, 560)

        # Central widget + layout
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        self.setWindowTitle('DES Tool')
        main_layout.setContentsMargins(12, 12, 12, 12)
        main_layout.setSpacing(10)

        # === TOP SECTION: split into two equal columns ===
        top_container = QWidget()
        top_hlayout = QHBoxLayout()
        top_hlayout.setSpacing(20)
        top_container.setLayout(top_hlayout)

        # Left column (Key input + hint)
        left_widget = QWidget()
        left_vlayout = QVBoxLayout()
        left_vlayout.setContentsMargins(1, 1, 1, 1)
        left_vlayout.setSpacing(6)
        left_widget.setLayout(left_vlayout)

        key_row = QHBoxLayout()
        key_label = QLabel('Key:')
        key_label.setFont(QFont('Segoe UI', 11))
        key_row.addWidget(key_label, alignment=Qt.AlignHCenter)

        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText('Enter 8-character key...')
        self.key_edit.setFixedHeight(36)
        self.key_edit.setFont(QFont('Consolas', 11))
        self.key_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        key_row.addWidget(self.key_edit)
        left_vlayout.addStretch(1)  # push it lower a little bit

        left_vlayout.addLayout(key_row)

        # Hint under the key input box
        self.key_hint_label = QLabel('Tip: The key will be padded or truncated to 8 bytes. Use ASCII characters.')
        self.key_hint_label.setStyleSheet('color: gray; font-size: 10pt;')
        self.key_hint_label.setFont(QFont('Consolas', 9))
        self.key_hint_label.setWordWrap(True)
        left_vlayout.addWidget(self.key_hint_label)
        left_vlayout.addStretch(1)  # push it up a little bit

        # Right column (Select file button + filename display)
        right_widget = QWidget()
        right_vlayout = QVBoxLayout()
        right_vlayout.setContentsMargins(0, 0, 0, 0)
        right_vlayout.setSpacing(6)
        right_widget.setLayout(right_vlayout)

        file_btn_row = QHBoxLayout()
        file_btn_row.addStretch()
        self.selectFile_btn = QPushButton(' Select File ')
        self.selectFile_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        self.selectFile_btn.setFixedWidth(240)
        self.selectFile_btn.setFixedHeight(140)
        self.selectFile_btn.setFont(QFont('Segoe UI', 12))
        file_btn_row.addWidget(self.selectFile_btn)
        file_btn_row.addStretch()
        right_vlayout.addLayout(file_btn_row)

        # Filename display under the button (centered)
        self.selected_file_label = QLabel('No file selected')
        self.selected_file_label.setStyleSheet('color: gray; font-size: 10pt;')
        self.selected_file_label.setFont(QFont('Consolas', 12))
        self.selected_file_label.setAlignment(Qt.AlignCenter)
        right_vlayout.addWidget(self.selected_file_label)

        # Add left and right columns to top_hlayout and make them stretch equally
        top_hlayout.addWidget(left_widget, 1)
        top_hlayout.addWidget(right_widget, 1)

        main_layout.addWidget(top_container)


        # Middle: Splitter with Input (left) and Output (right)
        splitter = QSplitter(Qt.Horizontal)

        # Input side
        input_widget = QWidget()
        input_layout = QVBoxLayout(input_widget)
        input_layout.setContentsMargins(6, 6, 6, 6)
        input_layout.setSpacing(6)

        input_header = QHBoxLayout()
        input_title = QLabel('Input')
        input_title.setFont(QFont('Segoe UI', 14, QFont.Bold))
        input_header.addWidget(input_title)
        input_header.addStretch()

        # buttons for input: clear / copy
        self.copy_input_btn = QPushButton(' Copy ')
        self.copy_input_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.copy_input_btn.setFixedHeight(30)
        self.copy_input_btn.setFont(QFont('Segoe UI', 9))
        input_header.addWidget(self.copy_input_btn)

        self.clear_input_btn = QPushButton(' Clear ')
        self.clear_input_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogResetButton))
        self.clear_input_btn.setFixedHeight(30)
        self.clear_input_btn.setFont(QFont('Segoe UI', 9))
        input_header.addWidget(self.clear_input_btn)

        input_layout.addLayout(input_header)

        self.input_edit = QTextEdit()
        self.input_edit.setPlaceholderText('Type plain ASCII text (for encryption) or paste cipher bytes text (for decryption). Or select a file above to enable file-mode.')
        self.input_edit.setFont(QFont('Consolas', 11))
        input_layout.addWidget(self.input_edit)


        splitter.addWidget(input_widget)

        # Output side
        output_widget = QWidget()
        output_layout = QVBoxLayout(output_widget)
        output_layout.setContentsMargins(6, 6, 6, 6)
        output_layout.setSpacing(6)

        output_header = QHBoxLayout()
        output_title = QLabel('Output')
        output_title.setFont(QFont('Segoe UI', 14, QFont.Bold))
        output_header.addWidget(output_title)
        output_header.addStretch()

        self.copy_output_btn = QPushButton(' Copy ')
        self.copy_output_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        self.copy_output_btn.setFixedHeight(30)
        self.copy_output_btn.setFont(QFont('Segoe UI', 9))
        output_header.addWidget(self.copy_output_btn)

        self.clear_output_btn = QPushButton(' Clear ')
        self.clear_output_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogResetButton))
        self.clear_output_btn.setFixedHeight(30)
        self.clear_output_btn.setFont(QFont('Segoe UI', 9))
        output_header.addWidget(self.clear_output_btn)

        output_layout.addLayout(output_header)

        self.output_edit = QTextEdit()
        self.output_edit.setReadOnly(True)
        self.output_edit.setFont(QFont('Consolas', 11))
        output_layout.addWidget(self.output_edit)

        splitter.addWidget(output_widget)

        splitter.setSizes([480, 480])
        main_layout.addWidget(splitter)

        # === BOTTOM BUTTONS ===
        bottom_layout = QHBoxLayout()
        self.cipher_btn = QPushButton('Encrypt')
        self.cipher_btn.setStyleSheet('background-color: #5cb85c; color: white; font-weight: bold;')
        self.cipher_btn.setFixedHeight(40)
        self.cipher_btn.setFont(QFont('Segoe UI', 14))

        self.decipher_btn = QPushButton('Decrypt')
        self.decipher_btn.setStyleSheet('background-color: #d9534f; color: white; font-weight: bold;')
        self.decipher_btn.setFixedHeight(40)
        self.decipher_btn.setFont(QFont('Segoe UI', 14))

        bottom_layout.addStretch()
        bottom_layout.addWidget(self.cipher_btn)
        bottom_layout.addWidget(self.decipher_btn)
        bottom_layout.addStretch()

        main_layout.addLayout(bottom_layout)


        # small status/help area
        status_layout = QHBoxLayout()
        self.status_label = QLabel('Ready')
        self.status_label.setStyleSheet('color: gray; font-size: 10pt;')
        self.status_label.setFont(QFont('Segoe UI', 12))
        self.status_label.setAlignment(Qt.AlignCenter)
        status_layout.addWidget(self.status_label)
        main_layout.addLayout(status_layout)

        # --- styling (simple, modern) ---
        self.setStyleSheet('''
            QMainWindow { background: #f7f9fc; }
            QTextEdit { background: white; border: 1px solid #d6dbe8; border-radius: 6px; }
            QLineEdit { background: white; border: 1px solid #d6dbe8; border-radius: 6px; padding-left: 6px; }
            QPushButton { background: #3a86ff; color: white; border-radius: 6px; padding: 6px 10px; }
            QPushButton[flat="true"] { background: transparent; color: #3a86ff; }
            QPushButton:disabled { background: #c9d6ff; }
            QLabel { color: #222; }
        ''')

        # --- keep logic method names and connect signals exactly as original code expects ---
        self.selectFile_btn.clicked.connect(self.select_file)
        self.cipher_btn.clicked.connect(self.encryption)
        self.decipher_btn.clicked.connect(self.decryption)

        # Connect clear & copy buttons
        self.clear_input_btn.clicked.connect(self.clear_input_and_reset)
        self.clear_output_btn.clicked.connect(lambda: self.output_edit.clear())
        self.copy_input_btn.clicked.connect(self._copy_input_to_clipboard)
        self.copy_output_btn.clicked.connect(self._copy_output_to_clipboard)

    # ---------------------- helper copy functions ----------------------
    def _copy_input_to_clipboard(self):
        text = self.input_edit.toPlainText()
        QApplication.clipboard().setText(text)
        self.status_label.setText('Input copied to clipboard')

    def _copy_output_to_clipboard(self):
        text = self.output_edit.toPlainText()
        QApplication.clipboard().setText(text)
        self.status_label.setText('Output copied to clipboard')

    # Clear input area and reset file-selection related state and status.
    def clear_input_and_reset(self):
        self.input_edit.clear()
        self.selected_file_label.setText('No file selected')
        self.file_path = ''
        self.use_file = False
        self.zip_file_name = ''
        self.file_name = ''
        self.status_label.setText('Ready')

    # ---------------------- logic methods ----------------------

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

        # File mode: if user has selected a file before pressing encrypt/decrypt
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
                input_block = [int(i) for i in ''.join([bin(i)[2:].rjust(8, '0') for i in text[i:i + 8]])]
                # Encrypt the key and text to get the result and output a string of length 64 consisting of 01
                output = ''.join(
                    [str(i) for i in (encryption(input_block, key) if self.mode == 'encrypt' else decryption(input_block, key))])

                result = bytes()
                for j in range(8):
                    byte_str = '0b' + output[j * 8:(j + 1) * 8]
                    byte = int(byte_str, 2).to_bytes(1, byteorder='little')
                    result += byte
                self.result += result

        # Select file mode
        if self.use_file:
            if self.mode == 'encrypt':
                self.status_label.setText('File saved')
                self.save_file()
            elif self.mode == 'decrypt':
                self.uncompress_file()
        # Input text mode
        else:
            if self.mode == 'encrypt':
                result = "".join([chr(i) for i in self.result])
            elif self.mode == 'decrypt':
                result = self.result.decode()
            self.output_edit.setText('{}text: {}'.format('Cipher' if self.mode == 'encrypt' else 'Plain', result))

        # reset file flags
        self.file_path = ''
        self.use_file = False
        self.status_label.setText('Done')

    # Opens a file dialog to select a file and sets the file path.
    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File', './', 'All Files (*)')
        if file_path:
            self.file_path = file_path
            self.use_file = True
            self.input_edit.setText('File selected: ' + self.file_path)
            self.selected_file_label.setText(self.file_path.split('/')[-1])
            self.status_label.setText('File selected')

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
        # Open the zipfile and extract all contents to the specified directory
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
            self.status_label.setText('Extraction failed')


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    # Set the window title
    mainWindow.setWindowTitle('DES Tool - 22372126 Qiyue Zhu')
    mainWindow.show()
    sys.exit(app.exec_())
