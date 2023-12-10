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


@app.route("/about/")
def about():
    return render_template("about.html")

@app.route("/doc/")
def doc():
    return render_template("doc.html")

@app.route("/otro/")
def otro():
    return render_template("index.html")



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

################################################################################
from flask import send_file
from Crypto.Random import get_random_bytes
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


from funciones import encrypt_file_aes
from funciones import decrypt_file_aes
from funciones import encrypt_file_des
from funciones import decrypt_file_des
from funciones import public_keys

#################################################################################

  #####    ####    ##   ##  #######  ######   ######    ####      ####    #####
 ##   ##    ##     ### ###   ##   #  # ## #    ##  ##    ##      ##  ##  ##   ##
 #          ##     #######   ## #      ##      ##  ##    ##     ##       ##   ##
  #####     ##     #######   ####      ##      #####     ##     ##       ##   ##
      ##    ##     ## # ##   ## #      ##      ## ##     ##     ##       ##   ##
 ##   ##    ##     ##   ##   ##   #    ##      ##  ##    ##      ##  ##  ##   ##
  #####    ####    ##   ##  #######   ####    #### ##   ####      ####    #####

#################################################################################

#GENERAR LA CLAVE EN EL SIMETRICO
@app.route('/otro/generate-key', methods=['GET'])
def generate_key_aes():
    # Genera una clave AES aleatoria de 16 bytes
    key = get_random_bytes(16)
    # Abre un archivo en modo escritura binaria y le escribe la clave dentro
    with open("encryption_key_aes.key", "wb") as key_file:
        key_file.write(key)
    # Esto ya permite la descarga de la clave
    return send_file("encryption_key_aes.key", as_attachment=True)


#SUBIR LA CLAVE AL NAS
@app.route('/subir_clave', methods=['POST'])
def subir_clave():
    clave_file = request.files['clave']

    if clave_file.filename == '':
        return "No se ha seleccionado ningún archivo de clave"

    # Ruta de destino para la clave en la carpeta compartida
    carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Guardar la clave en la carpeta compartida
    ruta_destino_clave = os.path.join(carpeta_destino, clave_file.filename)
    clave_file.save(ruta_destino_clave)

    return f'Clave guardada con éxito en {ruta_destino_clave}'

#ENCRIPTAR CON AES
@app.route('/encrypt-file', methods=['POST'])
def encrypt_file_route_aes():
# Se espera que se adjunte un archivo de clave en la solicitud.
# este archivo se lee para obtener la clave para el cifrado AES
    key_file = request.files['key']
    key = key_file.read()
# Se espera que se adjunte un archivo (file) para encriptarlo
# El contenido del archivo se lee para obtener el texto que será encriptado
    plaintext_file = request.files['file']
    plaintext = plaintext_file.read()
# Llama a la funcion que toma el texto plano y la clave
# y devuelve el texto cifrado utilizando AES
    ciphertext = encrypt_file_aes(plaintext, key)

    # Guardar localmente o en una ruta
    save_option = request.form.get('save_option')

    if save_option == 'local':
        with open("encrypted_file_aes.txt", "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        return send_file("encrypted_file_aes.txt", as_attachment=True)
    elif save_option == 'destino':
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        nombre_archivo_cifrado = secure_filename(plaintext_file.filename)
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado + '_cifrado.txt')

        with open(ruta_destino, 'wb') as encrypted_file:
            encrypted_file.write(ciphertext)
        return f'Archivo cifrado guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

#DESENCRIPTAR CON AES
@app.route('/decrypt-file', methods=['POST'])
def decrypt_file_route_aes():
    key_file = request.files['key']
    key = key_file.read()
    ciphertext_file = request.files['file']
    ciphertext = ciphertext_file.read()

    plaintext = decrypt_file_aes(ciphertext, key)

    # Guardar el archivo descifrado
    save_option = request.form.get('save_option')

    if save_option == 'local':
        with open("decrypted_file_aes.txt", "wb") as decrypted_file:
            decrypted_file.write(plaintext)
        return send_file("decrypted_file_aes.txt", as_attachment=True)
    elif save_option == 'destino':
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        nombre_archivo_descifrado = secure_filename(ciphertext_file.filename)
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_descifrado + '_descifrado.txt')

        with open(ruta_destino, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)
        return f'Archivo descifrado guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

#GENERAR CLAVE DES
@app.route('/generate-keydes', methods=['GET'])
def generate_key_des():
    key = get_random_bytes(8)
    with open("encryption_key_des.key", "wb") as key_file:
        key_file.write(key)
    return send_file("encryption_key_des.key", as_attachment=True)

#ENCRIPTAR CON EL DES
@app.route('/encrypt-filedes', methods=['POST'])
def encrypt_file_route_des():
    key_file = request.files['key']
    key = key_file.read()
    plaintext_file = request.files['file']
    plaintext = plaintext_file.read()

    ciphertext = encrypt_file_des(plaintext, key)  # Debes tener tu propia implementación de cifrado DES

    # Guardar el archivo cifrado DES
    save_option = request.form.get('save_option')

    if save_option == 'local':
        with open("encrypted_file_des.txt", "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        return send_file("encrypted_file_des.txt", as_attachment=True)
    elif save_option == 'destino':
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        nombre_archivo_cifrado = secure_filename(plaintext_file.filename)
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado + '_cifrado_des.txt')

        with open(ruta_destino, 'wb') as encrypted_file:
            encrypted_file.write(ciphertext)
        return f'Archivo cifrado DES guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

#DESENCRIPTAR CON EL DES
@app.route('/decrypt-filedes', methods=['POST'])
def decrypt_file_route_des():
    key_file = request.files['key']
    key = key_file.read()
    ciphertext_file = request.files['file']
    ciphertext = ciphertext_file.read()

    plaintext = decrypt_file_des(ciphertext, key)

    with open("decrypted_file_des.txt", "wb") as decrypted_file:
        decrypted_file.write(plaintext)

    return send_file("decrypted_file_des.txt", as_attachment=True)

############################################################################################

   ##      #####    ####    ##   ##  #######  ######   ######    ####      ####    #####
  ####    ##   ##    ##     ### ###   ##   #  # ## #    ##  ##    ##      ##  ##  ##   ##
 ##  ##   #          ##     #######   ## #      ##      ##  ##    ##     ##       ##   ##
 ##  ##    #####     ##     #######   ####      ##      #####     ##     ##       ##   ##
 ######        ##    ##     ## # ##   ## #      ##      ## ##     ##     ##       ##   ##
 ##  ##   ##   ##    ##     ##   ##   ##   #    ##      ##  ##    ##      ##  ##  ##   ##
 ##  ##    #####    ####    ##   ##  #######   ####    #### ##   ####      ####    #####

############################################################################################

#GENERAR LAS CLAVES PRIV Y PUBL
@app.route('/generate_keys')
def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )

    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    return render_template('casimetrico.html', public_key=public_key_pem, private_key=private_key_pem)

#DESCARGAR LA CLAVE PUBLICA
@app.route('/download_public_key')
def download_public_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode('utf-8')

    filename = 'public_key.pem'
    with open(filename, 'w') as file:
        file.write(public_key_pem)

    return send_from_directory(os.getcwd(), filename, as_attachment=True)

#DESCARGAR LA CLAVE PRIVADA
@app.route('/download_private_key')
def download_private_key():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode('utf-8')

    filename = 'private_key.pem'
    with open(filename, 'w') as file:
        file.write(private_key_pem)

    return send_from_directory(os.getcwd(), filename, as_attachment=True)

#DESCIFRAR CON LA CLAVE PRIVADA (NO FUNCIONA)
@app.route('/descifrar_con_clave_privada', methods=['POST'])
def descifrar_con_clave_privada():
    if 'file' not in request.files or 'private_key_file' not in request.files:
        return "Falta el archivo o la clave privada"

    file = request.files['file']
    private_key_file = request.files['private_key_file']

    if file.filename == '' or private_key_file.filename == '':
        return "Falta el archivo o la clave privada"

    encrypted_data = file.read()
    private_key_pem = private_key_file.read()

    private_key = serialization.load_pem_private_key(private_key_pem, password=None, backend=default_backend())

    try:
        # Descifrar utilizando la clave privada
        decrypted_data = private_key.decrypt(
            encrypted_data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        # Guardar el archivo descifrado localmente
        with open('decrypted_file.txt', 'wb') as decrypted_file:
            decrypted_file.write(decrypted_data)

        return send_file('decrypted_file.txt', as_attachment=True)

    except Exception as e:
        return f"Error al descifrar el archivo: {str(e)}"


#CIFRAR CON LA CLAVE PUBLICA
@app.route('/cifrar_con_clave_publica', methods=['POST'])
def cifrar_con_clave_publica():
    if 'file' not in request.files or 'public_key_file' not in request.files:
        return "No se ha seleccionado algún archivo o clave pública"

    file = request.files['file']
    public_key_file = request.files['public_key_file']
    save_option = request.form.get('save_option')  # Obtener la opción de guardado

    if file.filename == '' or public_key_file.filename == '':
        return "No se ha seleccionado algún archivo o clave pública"

    file_contents = file.read()
    public_key_pem = public_key_file.read()

    public_key = serialization.load_pem_public_key(public_key_pem, backend=default_backend())

    try:
        encrypted_data = public_key.encrypt(
            file_contents,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        if save_option == 'local':
            with open('encrypted_file.txt', 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            return send_file('encrypted_file.txt', as_attachment=True)
        elif save_option == 'destino':
            carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'
            if not os.path.exists(carpeta_destino):
                os.makedirs(carpeta_destino)

            nombre_archivo_cifrado = secure_filename(file.filename)
            ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado + '_cifrado_rsa.txt')

            with open(ruta_destino, 'wb') as encrypted_file:
                encrypted_file.write(encrypted_data)
            return f'Archivo cifrado RSA guardado con éxito en {ruta_destino}'
        else:
            return "Opción de guardado no válida"

    except Exception as e:
        return f"Error al cifrar el archivo: {str(e)}"

#SUBIR CLAVE AL NAS
@app.route('/upload_public_key', methods=['POST'])
def upload_public_key():
    uploaded_file = request.files['public_key_file']
    if uploaded_file.filename != '':
        filename = uploaded_file.filename
        uploaded_file.save(filename)
        # Puedes acceder al contenido del archivo guardado para realizar operaciones adicionales si lo necesitas
        with open(filename, 'r') as file:
            public_key_content = file.read()
            # Puedes imprimir el contenido si quieres verificar que se cargó correctamente
            print(public_key_content)
        return "Clave pública subida exitosamente"
    else:
        return "No se ha seleccionado ningún archivo"

#LISTAR LAS CLAVES PUBLICAS
from flask import request, send_file

@app.route('/listar_claves_publicas', methods=['GET', 'POST'])
def listar_claves_publicas():
    if request.method == 'POST':
        selected_keys = request.form.getlist('selected_keys')
        # Lógica para descargar las claves seleccionadas
        for key in selected_keys:
            # Lógica para descargar cada clave seleccionada, por ejemplo:
            return send_file(key, as_attachment=True)
    
    files = os.listdir('.')
    public_keys = []  # Lista para almacenar las claves públicas
    for file in files:
        if file.endswith('.pem') and 'public' in file.lower():
            public_keys.append(file)

    return render_template('casimetrico.html', public_keys=public_keys)

 
    
#SUBIR CLAVE PUBLICA
@app.route('/subir_archivo', methods=['POST'])
def subir_archivo():
    if 'archivo' not in request.files:
        return 'No se encontró el archivo en la solicitud'

    archivo = request.files['archivo']

    if archivo.filename == '':
        return 'No se seleccionó ningún archivo'

    # Ruta de destino en la red
    carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'

    # Asegúrate de que la carpeta de destino exista
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Ruta completa del archivo en la carpeta de destino
    ruta_destino = os.path.join(carpeta_destino, secure_filename(archivo.filename))

    # Copiar el archivo a la carpeta de destino
    archivo.save(ruta_destino)

    return f'Archivo subido con éxito a {ruta_destino}'



############################################################################################################################################################################################################################
                                                                                    ##                                                      ##
  ####    ######    ####     ####              ######  ##  ##    ####              #####    ####    #####     ### ##   ####                 ##    ####    ######   ######    ####     #####    ###      ####    #####
 ##  ##    ##  ##  ##  ##   ##  ##            ##  ##   ##  ##   ##  ##              ##     ##  ##   ##  ##   ##  ##   ##  ##             #####   ##  ##    ##  ##   ##  ##  ##  ##   ##         ##     ##  ##   ##  ##
 ##        ##      ######   ##  ##            ##  ##   ##  ##   ######              ##     ######   ##  ##   ##  ##   ##  ##            ##  ##   ######    ##  ##   ##      ######    #####     ##     ##  ##   ##  ##
 ##  ##    ##      ##       ##  ##             #####   ##  ##   ##                  ## ##  ##       ##  ##    #####   ##  ##            ##  ##   ##        #####    ##      ##            ##    ##     ##  ##   ##  ##
  ####    ####      #####    ####                 ##    ######   #####               ###    #####   ##  ##       ##    ####              ######   #####    ##      ####      #####   ######    ####     ####    ##  ##
                                                 ####                                                        #####                                        ####

############################################################################################################################################################################################################################
