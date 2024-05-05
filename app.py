from flask import Flask, render_template, request, jsonify
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.backends import default_backend

app = Flask(__name__, template_folder='templates')

UPLOAD_FOLDER = 'uploads'
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/upload', methods=['POST'])
def upload():
    file = request.files['file']
    key = request.form['key']
    key_size = int(request.form['keySize'])

    # Save the uploaded file to a temporary location
    file_path = os.path.join(app.config['UPLOAD_FOLDER'], file.filename)
    file.save(file_path)

    # Perform encryption or decryption based on the selected action
    if request.form['action'] == 'encrypt':
        encrypt_file(file_path, key.encode('ascii'), key_size)
        message = f"File encrypted with {key_size}-bit key."
    elif request.form['action'] == 'decrypt':
        decrypt_file(file_path, key.encode('ascii'), key_size)
        message = f"File decrypted with {key_size}-bit key."

    return jsonify({'message': message})

def encrypt_file(file_path, key, key_size):
    if key_size == 128:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    elif key_size == 192:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key[:24]), modes.CBC(iv), backend=default_backend())
    elif key_size == 256:
        iv = os.urandom(16)
        cipher = Cipher(algorithms.AES(key[:32]), modes.CBC(iv), backend=default_backend())
    else:
        raise ValueError("Invalid key size. Key size must be 128, 192, or 256 bits.")

    encryptor = cipher.encryptor()

    with open(file_path, 'rb') as file:
        plaintext = file.read()

    # Pad the plaintext before encryption
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_plaintext = padder.update(plaintext) + padder.finalize()

    ciphertext = encryptor.update(padded_plaintext) + encryptor.finalize()

    output_file = f'encrypted_file_{key_size}_bits.txt'
    with open(os.path.join(app.config['UPLOAD_FOLDER'], output_file), 'wb') as encrypted_file:
        encrypted_file.write(iv + ciphertext)

def decrypt_file(file_path, key, key_size):
    if key_size == 128:
        key = key[:16]
    elif key_size == 192:
        key = key[:24]
    elif key_size == 256:
        key = key[:32]
    else:
        raise ValueError("Invalid key size. Key size must be 128, 192, or 256 bits.")

    with open(file_path, 'rb') as file:
        iv = file.read(16)  # Read the IV from the file
        ciphertext = file.read()

    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    decryptor = cipher.decryptor()

    plaintext_padded = decryptor.update(ciphertext) + decryptor.finalize()

    # Remove padding
    unpadder = padding.PKCS7(algorithms.AES.block_size).unpadder()
    plaintext = unpadder.update(plaintext_padded) + unpadder.finalize()

    output_file = f'decrypted_file_{key_size}_bits.txt'
    with open(os.path.join(app.config['UPLOAD_FOLDER'], output_file), 'wb') as decrypted_file:
        decrypted_file.write(plaintext)

if __name__ == '__main__':
    app.run(debug=True)
