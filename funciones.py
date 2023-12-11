from flask import Flask, render_template, request, send_file, redirect, url_for
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import os
from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from flask import Flask, render_template, send_from_directory
from cryptography.hazmat.primitives import serialization
from flask import Flask, render_template, request, send_file, render_template_string
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet
from flask import Flask, render_template, request, send_file
from Crypto.Cipher import AES, DES
from Crypto.Random import get_random_bytes

app = Flask(__name__)
public_keys = []  # Lista para almacenar los nombres de las claves públicas

# Funciones para AES
def encrypt_file_aes(plaintext, key):
    cipher = AES.new(key, AES.MODE_EAX)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return cipher.nonce + tag + ciphertext

def decrypt_file_aes(ciphertext, key):
    nonce = ciphertext[:16]
    tag = ciphertext[16:32]
    encrypted_data = ciphertext[32:]
    cipher = AES.new(key, AES.MODE_EAX, nonce)
    plaintext = cipher.decrypt_and_verify(encrypted_data, tag)
    return plaintext

# Funciones para DES
def encrypt_file_des(plaintext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    while len(plaintext) % 8 != 0:
        plaintext += b' '
    return cipher.encrypt(plaintext)

def decrypt_file_des(ciphertext, key):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.decrypt(ciphertext)


# Función para cargar la clave
def cargar_clave():
    if os.path.isfile('key.key'):
        with open('key.key', 'rb') as key_file:
            return key_file.read()
    return None

# Función para descifrar los datos
def descifrar_datos(encrypted_data, key):
    cipher_suite = Fernet(key)
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        return decrypted_data
    except Exception as e:
        raise Exception(f"Error al descifrar los datos: {str(e)}")









