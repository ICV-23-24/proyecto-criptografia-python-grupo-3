from datetime import datetime
from flask import Flask, render_template, request
import functions as f

app = Flask(__name__)


# Replace the existing home function with the one below
@app.route("/")
def home():
    return render_template("home.html")

@app.route("/csimetrico/", methods=['GET','POST'])
def csimetrico():
    if request.method == 'POST':
        message = request.form['message']
        key = request.form['key']
        mode = request.form['mode']

        if mode == 'encrypt':
            encrypted_message = f.encrypt_message(message, key)
            return render_template('csimetrico.html', encrypted_message=encrypted_message, mode=mode)
        elif mode == 'decrypt':
            decrypted_message = f.decrypt_message(message, key)
            return render_template('csimetrico.html', decrypted_message=decrypted_message, mode=mode)

    return render_template("csimetrico.html")

@app.route("/casimetrico/")
def casimetrico():
    return render_template("casimetrico.html")

@app.route("/hola/")
def hola():
    return render_template("about.html")

@app.route("/about/")
def about():
    return render_template("about.html")

@app.route("/doc/")
def doc():
    return render_template("doc.html")

@app.route("/otro/")
def otro():
    return render_template("otro.html")

@app.route("/hola2/")
def hola2():
    return render_template("formulario.html")


@app.route("/hello/")
@app.route("/hello/<name>")
def hello_there(name = None):
    return render_template(
        "hello_there.html",
        name=name,
        date=datetime.now()
    )


@app.route("/api/data")
def get_data():
    return app.send_static_file("data.json")


#####################################################################################################################
from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import padding
app = Flask(__name__)

@app.route('/descargar_clave', methods=['GET'])
def descargar_clave():
    key = cargar_clave()
    if key:
        with open('key.key', 'wb') as key_file:
            key_file.write(key)
        return send_file('key.key', as_attachment=True)
    return "No se ha generado ninguna clave aún."

def cargar_clave():
    if os.path.isfile('key.key'):
        with open('key.key', 'rb') as key_file:
            return key_file.read()
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/cifrar', methods=['POST'])
def cifrar():
    if 'file' not in request.files or 'algorithm' not in request.form:
        return "Falta seleccionar algún archivo o algoritmo"

    file = request.files['file']
    algorithm = request.form['algorithm']

    if file.filename == '' or algorithm not in ['AES', '3DES']:
        return "Falta seleccionar algún archivo o algoritmo válido"

    file_contents = file.read()

    # Generar clave AES de 128 bits (16 bytes)
    key = os.urandom(16)

    if algorithm == 'AES':
        cipher = Cipher(algorithms.AES(key), modes.CBC(os.urandom(16)), backend=default_backend())
    else:
        cipher = Cipher(algorithms.TripleDES(key), modes.CBC(os.urandom(8)), backend=default_backend())

    encryptor = cipher.encryptor()
    padder = padding.PKCS7(algorithms.AES.block_size).padder()
    padded_data = padder.update(file_contents) + padder.finalize()

    encrypted_data = encryptor.update(padded_data) + encryptor.finalize()

    with open('encrypted_file.txt', 'wb') as encrypted_file:
        encrypted_file.write(encrypted_data)

    return send_file('encrypted_file.txt', as_attachment=True)
###########################################################
def descifrar():
    if 'file' not in request.files or 'key' not in request.files:
        return "No se ha seleccionado algún archivo o clave"

    file = request.files['file']
    key_file = request.files['key']
    if file.filename == '' or key_file.filename == '':
        return "No se ha seleccionado algún archivo o clave"

    encrypted_data = file.read()
    key = key_file.read()

    cipher_suite = Fernet(key)
    try:
        decrypted_data = cipher_suite.decrypt(encrypted_data)
        with open('decrypted_file.txt', 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)
        return send_file('decrypted_file.txt', as_attachment=True)
    except Exception as e:
        return f"Error al descifrar el archivo: {str(e)}"

if __name__ == '__main__':
    app.run(debug=True)

#Si lees esto has hecho un pull bien



