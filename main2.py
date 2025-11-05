import sys
import zipfile
from PyQt5.QtWidgets import (
    QApplication, QMainWindow, QFileDialog, QMessageBox, QWidget,
    QVBoxLayout, QHBoxLayout, QTextEdit, QPushButton, QLineEdit, QLabel,
    QSplitter, QFrame, QStyle, QToolButton, QSizePolicy
)
from PyQt5.QtCore import Qt
from PyQt5.QtGui import QIcon, QFont

from des_alg import encryption, decryption


class MainWindow(QMainWindow):
    """
    Redesigned Main window class for the DES encryption/decryption application.
    The application logic (encryption/decryption/compression) is kept exactly as
    in the original file — only the UI layout and styles are changed here.
    """

    def __init__(self, parent=None):
        super(MainWindow, self).__init__(parent)
        self.setWindowTitle('DES Tool - Enhanced UI')
        self.resize(1000, 650)

        # Initialize state variables
        self.file_path = ''
        self.use_file = False
        self.zip_file_name = ''
        self.file_name = ''
        self.mode = ''
        self.result = bytes()

        # --- Main Layout ---
        main_widget = QWidget()
        main_layout = QVBoxLayout()
        main_widget.setLayout(main_layout)
        self.setCentralWidget(main_widget)
        self.setWindowTitle('DES Tool')

        # === TOP SECTION: split into two equal columns ===
        top_container = QWidget()
        top_hlayout = QHBoxLayout()
        top_hlayout.setSpacing(20)
        top_container.setLayout(top_hlayout)

        # Left column (Key input + hint)
        left_widget = QWidget()
        left_vlayout = QVBoxLayout()
        left_vlayout.setContentsMargins(0, 0, 0, 0)
        left_vlayout.setSpacing(6)
        left_widget.setLayout(left_vlayout)

        key_row = QHBoxLayout()
        key_label = QLabel('Key:')
        key_label.setFont(QFont('Arial', 11))
        key_row.addWidget(key_label)

        self.key_edit = QLineEdit()
        self.key_edit.setPlaceholderText('Enter 8-character key...')
        self.key_edit.setFont(QFont('Segoe UI', 11))
        self.key_edit.setSizePolicy(QSizePolicy.Expanding, QSizePolicy.Fixed)
        key_row.addWidget(self.key_edit)

        left_vlayout.addLayout(key_row)

        # Hint under the key input box
        self.key_hint_label = QLabel('Hint: The key will be padded or truncated to 8 bytes. Use ASCII characters.')
        self.key_hint_label.setStyleSheet('color: gray; font-size: 10pt;')
        self.key_hint_label.setWordWrap(True)
        left_vlayout.addWidget(self.key_hint_label)

        # Right column (Select file button + filename display)
        right_widget = QWidget()
        right_vlayout = QVBoxLayout()
        right_vlayout.setContentsMargins(0, 0, 0, 0)
        right_vlayout.setSpacing(6)
        right_widget.setLayout(right_vlayout)

        file_btn_row = QHBoxLayout()
        file_btn_row.addStretch()
        self.selectFile_btn = QPushButton('Select File')
        self.selectFile_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogOpenButton))
        self.selectFile_btn.setFixedWidth(140)
        file_btn_row.addWidget(self.selectFile_btn)
        file_btn_row.addStretch()
        right_vlayout.addLayout(file_btn_row)

        # Filename display under the button (centered)
        self.selected_file_label = QLabel('No file selected')
        self.selected_file_label.setStyleSheet('color: gray; font-size: 10pt;')
        self.selected_file_label.setAlignment(Qt.AlignCenter)
        right_vlayout.addWidget(self.selected_file_label)

        # Add left and right columns to top_hlayout and make them stretch equally
        top_hlayout.addWidget(left_widget, 1)
        top_hlayout.addWidget(right_widget, 1)

        main_layout.addWidget(top_container)

        # === CENTER SECTION ===
        splitter = QSplitter(Qt.Horizontal)

        # --- Input Section ---
        input_frame = QFrame()
        input_layout = QVBoxLayout()
        input_frame.setLayout(input_layout)

        input_label_layout = QHBoxLayout()
        input_label = QLabel('Input Text / File Content:')
        clear_input_btn = QPushButton('Clear')
        clear_input_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogResetButton))
        copy_input_btn = QPushButton('Copy')
        copy_input_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        input_label_layout.addWidget(input_label)
        input_label_layout.addStretch()
        input_label_layout.addWidget(clear_input_btn)
        input_label_layout.addWidget(copy_input_btn)
        input_layout.addLayout(input_label_layout)

        self.input_edit = QTextEdit()
        self.input_edit.setFont(QFont('Consolas', 11))
        input_layout.addWidget(self.input_edit)

        splitter.addWidget(input_frame)

        # --- Output Section ---
        output_frame = QFrame()
        output_layout = QVBoxLayout()
        output_frame.setLayout(output_layout)

        output_label_layout = QHBoxLayout()
        output_label = QLabel('Output Text / File Result:')
        clear_output_btn = QPushButton('Clear')
        clear_output_btn.setIcon(self.style().standardIcon(QStyle.SP_DialogResetButton))
        copy_output_btn = QPushButton('Copy')
        copy_output_btn.setIcon(self.style().standardIcon(QStyle.SP_FileDialogDetailedView))
        output_label_layout.addWidget(output_label)
        output_label_layout.addStretch()
        output_label_layout.addWidget(clear_output_btn)
        output_label_layout.addWidget(copy_output_btn)
        output_layout.addLayout(output_label_layout)

        self.output_edit = QTextEdit()
        self.output_edit.setFont(QFont('Consolas', 11))
        output_layout.addWidget(self.output_edit)

        splitter.addWidget(output_frame)
        splitter.setSizes([480, 480])

        main_layout.addWidget(splitter)

        # === BOTTOM BUTTONS ===
        bottom_layout = QHBoxLayout()
        self.cipher_btn = QPushButton('Encrypt')
        self.cipher_btn.setStyleSheet('background-color: #5cb85c; color: white; font-weight: bold;')
        self.decipher_btn = QPushButton('Decrypt')
        self.decipher_btn.setStyleSheet('background-color: #d9534f; color: white; font-weight: bold;')
        bottom_layout.addStretch()
        bottom_layout.addWidget(self.cipher_btn)
        bottom_layout.addWidget(self.decipher_btn)
        bottom_layout.addStretch()
        main_layout.addLayout(bottom_layout)

        # --- Connections ---
        clear_input_btn.clicked.connect(lambda: self.input_edit.clear())
        clear_output_btn.clicked.connect(lambda: self.output_edit.clear())
        copy_input_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.input_edit.toPlainText()))
        copy_output_btn.clicked.connect(lambda: QApplication.clipboard().setText(self.output_edit.toPlainText()))

        self.selectFile_btn.clicked.connect(self.select_file)
        self.cipher_btn.clicked.connect(self.encryption)
        self.decipher_btn.clicked.connect(self.decryption)

    # --- Logic Functions (unchanged) ---
    def encryption(self):
        self.mode = 'encrypt'
        self.mainDES()

    def decryption(self):
        self.mode = 'decrypt'
        self.mainDES()

    def mainDES(self):
        key = self.key_edit.text()
        text = self.input_edit.toPlainText()
        self.result = bytes()

        if not key or not text:
            if not key and not text:
                msg = "key and {}text".format('plain' if self.mode == 'encrypt' else 'cipher')
            elif not key:
                msg = "key"
            else:
                msg = "{}text".format('plain' if self.mode == 'encrypt' else 'cipher')
            QMessageBox.warning(self, 'Warning', 'You have not entered the {}'.format(msg), QMessageBox.Ok)
            return

        if self.use_file:
            if self.mode == 'encrypt':
                self.compress_file()
                file_name = self.zip_file_name
            elif self.mode == 'decrypt':
                file_name = self.file_path
            with open(file_name, 'rb') as f:
                text = f.read()
        else:
            if self.mode == 'encrypt':
                text = text.encode()
            elif self.mode == 'decrypt':
                t = bytes()
                for i in text:
                    t += ord(i).to_bytes(1, byteorder='little')
                text = t

        key = key.encode('utf-8')
        while len(key) < 8:
            key += '\0'.encode()
        if len(key) > 8:
            key = key[:8]
        while len(text) % 8 != 0:
            text += '\0'.encode()

        key = [int(i) for i in ''.join([bin(i)[2:].rjust(8, '0') for i in key])]

        for i in range(0, len(text), 8):
            if i % 8 == 0:
                input_block = [int(i) for i in ''.join([bin(i)[2:].rjust(8, '0') for i in text[i:i + 8]])]
                output_block = ''.join([str(i) for i in (encryption(input_block, key) if self.mode == 'encrypt' else decryption(input_block, key))])
                result = bytes()
                for j in range(8):
                    byte_str = '0b' + output_block[j * 8:(j + 1) * 8]
                    byte = int(byte_str, 2).to_bytes(1, byteorder='little')
                    result += byte
                self.result += result

        if self.use_file:
            if self.mode == 'encrypt':
                self.save_file()
            elif self.mode == 'decrypt':
                self.uncompress_file()
        else:
            if self.mode == 'encrypt':
                result = "".join([chr(i) for i in self.result])
            elif self.mode == 'decrypt':
                result = self.result.decode()
            self.output_edit.setText('{}text:\n{}'.format('Cipher' if self.mode == 'encrypt' else 'Plain', result))

        self.file_path = ''
        self.use_file = False

    def select_file(self):
        file_path, _ = QFileDialog.getOpenFileName(self, 'Select File', './', 'All Files (*)')
        if file_path:
            self.file_path = file_path
            self.use_file = True
            self.input_edit.setText('File selected: ' + self.file_path)
            self.selected_file_label.setText(file_path.split('/')[-1])

    def save_file(self):
        encrypted_file_path = self.file_path.replace('.', '(encrypted).')
        with open(encrypted_file_path, 'wb') as f:
            f.write(self.result)
        self.output_edit.setText('File saved: ' + encrypted_file_path)

    def compress_file(self):
        base_file_name = self.file_path.split('/')[-1]
        zip_file_name = f"{base_file_name.split('.')[0]}.zip"
        internal_file_name = f"encrypted_{base_file_name}"
        self.zip_file_name = zip_file_name
        self.file_name = internal_file_name
        try:
            with zipfile.ZipFile(zip_file_name, 'w', zipfile.ZIP_BZIP2) as zf:
                zf.write(self.file_path, internal_file_name)
        except Exception as e:
            QMessageBox.warning(self, 'Warning', f'Error compressing file: {e}', QMessageBox.Ok)

    def uncompress_file(self):
        file_path = '/'.join(self.file_path.split("/")[:-1]) + '/'
        try:
            with zipfile.ZipFile(self.zip_file_name, 'r') as zf:
                zf.extractall(file_path)
            self.output_edit.setText(f"File decryption results saved to {file_path + self.file_name}")
        except Exception as e:
            self.output_edit.setText(f"Error during file extraction: {e}")


if __name__ == '__main__':
    app = QApplication(sys.argv)
    mainWindow = MainWindow()
    mainWindow.show()
    sys.exit(app.exec_())