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
from flask import Flask, render_template, request, send_file, send_from_directory
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
from flask import request, send_file


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
    
    # Si no has seleccionado nada sale ese mensaje 
    if clave_file.filename == '':
        return "No se ha seleccionado ningún archivo de clave"

    # Ruta de destino para la clave en la carpeta compartida
    carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back\\Claves Simetrico'
    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Guardar la clave en la carpeta compartida
    ruta_destino_clave = os.path.join(carpeta_destino, clave_file.filename)
    clave_file.save(ruta_destino_clave)

    return f'Clave guardada con éxito en {ruta_destino_clave}'


from flask import Flask, request, send_file
from werkzeug.utils import secure_filename


#ENCRIPTAR CON AES
@app.route('/encrypt-file', methods=['POST'])
def encrypt_file_route_aes():
# Se espera que se adjunte un archivo .key en la solicitud
# este archivo se lee para obtener la clave para el cifrado AES
    key_file = request.files['key']
    key = key_file.read()
# Se espera que se adjunte un archivo para encriptarlo
# El contenido del archivo se lee para obtener el texto que será encriptado
    plaintext_file = request.files['file']
    plaintext = plaintext_file.read()
# Llama a la funcion que toma el texto plano y la clave
# y devuelve el texto cifrado utilizando AES
    ciphertext = encrypt_file_aes(plaintext, key)
    
# Guardar localmente o en una ruta
    save_option = request.form.get('save_option')

# Opción para guardar en local
    if save_option == 'local':
        with open("encrypted_file_aes.txt", "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        return send_file("encrypted_file_aes.txt", as_attachment=True)
    
# Opción para guardar en el NAS   
    elif save_option == 'destino':
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back\\Cifrados AES'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

# Obtener el nombre del archivo de texto plano
        nombre_archivo_cifrado = secure_filename(plaintext_file.filename)
# Establecer la ruta de destino para el archivo encriptado
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado)
        
# Verificar si ya existe un archivo con el mismo nombre en la carpeta de destino
        if os.path.exists(ruta_destino):
# Si existe, agregar un contador al nombre del archivo para hacerlo único
            base, extension = os.path.splitext(nombre_archivo_cifrado)
            contador = 1
            while os.path.exists(os.path.join(carpeta_destino, f"{base}_{contador}{extension}")):
                contador += 1
            nombre_archivo_cifrado = f"{base}_{contador}{extension}"
            ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado)
            
# Escribir los datos encriptados en el archivo en el destino especificado
        with open(ruta_destino, 'wb') as encrypted_file:
            encrypted_file.write(ciphertext)
        return f'Archivo cifrado guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

#DESENCRIPTAR CON AES
@app.route('/decrypt-file', methods=['POST'])
def decrypt_file_route_aes():
# Se espera que se adjunte un archivo .key en la solicitud
# este archivo se lee para obtener la clave para el descifrado AES
    key_file = request.files['key']
    key = key_file.read()
# Se espera que se adjunte un archivo para desencriptarlo
# El contenido del archivo se lee para obtener el texto que será desencriptado
    ciphertext_file = request.files['file']
    ciphertext = ciphertext_file.read()
# Llama a la función desencripta usando aes
    plaintext = decrypt_file_aes(ciphertext, key)

    save_option = request.form.get('save_option')

    if save_option == 'local':
        with open("decrypted_file_aes.txt", "wb") as decrypted_file:
            decrypted_file.write(plaintext)
        return send_file("decrypted_file_aes.txt", as_attachment=True)
    
    elif save_option == 'destino':
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back\\Descifrados AES'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        nombre_archivo_descifrado = secure_filename(ciphertext_file.filename)
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_descifrado)

        if os.path.exists(ruta_destino):
            base, extension = os.path.splitext(nombre_archivo_descifrado)
            contador = 1
            while os.path.exists(os.path.join(carpeta_destino, f"{base}_{contador}{extension}")):
                contador += 1
            nombre_archivo_descifrado = f"{base}_{contador}{extension}"
            ruta_destino = os.path.join(carpeta_destino, nombre_archivo_descifrado)

        with open(ruta_destino, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)
        return f'Archivo descifrado guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

#GENERAR CLAVE DES
@app.route('/generate-keydes', methods=['GET'])
def generate_key_des():
# Genera una clave de 8 bytes
    key = get_random_bytes(8)
# Abre un archivo en modo escritura binaria con wb y le escribe la clave dentro
    with open("encryption_key_des.key", "wb") as key_file:
        key_file.write(key)
    return send_file("encryption_key_des.key", as_attachment=True)

# ENCRIPTAR CON DES
@app.route('/encrypt-filedes', methods=['POST'])
def encrypt_file_route_des():
# Se espera que se adjunte un archivo .key en la solicitud
# este archivo se lee para obtener la clave para el cifrado DES
    key_file = request.files['key']
    key = key_file.read()
# Se espera que se adjunte un archivo para encriptarlo
# El contenido del archivo se lee para obtener el texto que será encriptado
    plaintext_file = request.files['file']
    plaintext = plaintext_file.read()
# Llama a la funcion que toma el texto plano y la clave
# y devuelve el texto cifrado utilizando DES
    ciphertext = encrypt_file_des(plaintext, key)

# Guardar localmente o en una ruta
    save_option = request.form.get('save_option')

    if save_option == 'local':
        with open("encrypted_file_des.txt", "wb") as encrypted_file:
            encrypted_file.write(ciphertext)
        return send_file("encrypted_file_des.txt", as_attachment=True)
    
    elif save_option == 'destino':
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back\\Cifrados DES'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        nombre_archivo_cifrado = secure_filename(plaintext_file.filename)
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado)

        if os.path.exists(ruta_destino):
            base, extension = os.path.splitext(nombre_archivo_cifrado)
            contador = 1
            while os.path.exists(os.path.join(carpeta_destino, f"{base}_{contador}{extension}")):
                contador += 1
            nombre_archivo_cifrado = f"{base}_{contador}{extension}"
            ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado)

        with open(ruta_destino, 'wb') as encrypted_file:
            encrypted_file.write(ciphertext)
        return f'Archivo cifrado DES guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

#DESENCRIPTAR CON EL DES
@app.route('/decrypt-filedes', methods=['POST'])
def decrypt_file_route_des():
# Se espera que se adjunte un archivo de clave en la solicitud
# este archivo se lee para obtener la clave para el descifrado DES
    key_file = request.files['key']
    key = key_file.read()
# Se espera que se adjunte un archivo (file) para descifrarlo
# El contenido del archivo se lee para obtener el texto que será descifrado  
    ciphertext_file = request.files['file']
    ciphertext = ciphertext_file.read()

    # Desencriptar el archivo
    plaintext = decrypt_file_des(ciphertext, key)

    # Obtener la opción de guardado 
    save_option = request.form.get('save_option')

    # Lógica para guardar en local o en una ruta compartida
    if save_option == 'local':
        # Guardar el archivo desencriptado en local
        with open("decrypted_file_des.txt", "wb") as decrypted_file:
            decrypted_file.write(plaintext)
        return send_file("decrypted_file_des.txt", as_attachment=True)
    elif save_option == 'destino':
        # Guardar en el nas
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back\\Descifrados DES'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        nombre_archivo_desencriptado = secure_filename(ciphertext_file.filename)
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_desencriptado)

        with open(ruta_destino, 'wb') as decrypted_file:
            decrypted_file.write(plaintext)
        return f'Archivo descifrado DES guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

############################################################################################

   ##      #####    ####    ##   ##  #######  ######   ######    ####      ####    #####
  ####    ##   ##    ##     ### ###   ##   #  # ## #    ##  ##    ##      ##  ##  ##   ##
 ##  ##   #          ##     #######   ## #      ##      ##  ##    ##     ##       ##   ##
 ##  ##    #####     ##     #######   ####      ##      #####     ##     ##       ##   ##
 ######        ##    ##     ## # ##   ## #      ##      ## ##     ##     ##       ##   ##
 ##  ##   ##   ##    ##     ##   ##   ##   #    ##      ##  ##    ##      ##  ##  ##   ##
 ##  ##    #####    ####    ##   ##  #######   ####    #### ##   ####      ####    #####

############################################################################################
app.config['UPLOAD_FOLDER'] = 'upload'

@app.route('/generate-keys', methods=['POST'])
def generate_keys():
    key = RSA.generate(2048)
    private_key = key.export_key()
    public_key = key.publickey().export_key()

    with open('private_key.pem', 'wb') as private_file:
        private_file.write(private_key)

    with open('public_key.pem', 'wb') as public_file:
        public_file.write(public_key)

    return 'Claves generadas. <a href="/casimetrico">Volver</a>'

@app.route('/download-private-key')
def download_private_key():
    return send_file('private_key.pem', as_attachment=True)

@app.route('/download-public-key')
def download_public_key():
    return send_file('public_key.pem', as_attachment=True)

# CIFRAR CON CLAVE PÚBLICA
@app.route('/encrypt', methods=['POST'])
def encrypt():
    # Se recibe el archivo y se guarda en el servidor que es la carpeta uploads esa
    file = request.files['file']
    file.save(os.path.join(app.config['UPLOAD_FOLDER'], 'file_to_encrypt.txt'))

    # Se recibe la clave pública RSA y se guarda en el proyecto como public_key.pem
    public_key = request.files['public_key']
    public_key.save(os.path.join(app.config['UPLOAD_FOLDER'], 'public_key.pem'))

    # Se importa la clave pública RSA para usarla en el cifrado RSA
    recipient_key = RSA.import_key(open(os.path.join(app.config['UPLOAD_FOLDER'], 'public_key.pem')).read())
    cipher_rsa = PKCS1_OAEP.new(recipient_key)  # Se crea un objeto de cifrado RSA

    # Se genera una clave aleatoria para AES
    aes_key = get_random_bytes(16)
    aes_cipher = AES.new(aes_key, AES.MODE_EAX)  # Se crea un objeto de cifrado AES

    # Se lee el contenido del archivo que se va a cifrar
    with open(os.path.join(app.config['UPLOAD_FOLDER'], 'file_to_encrypt.txt'), 'rb') as f:
        plaintext = f.read()

    # Se cifra el archivo con AES PARA PERMITIR CIFRAR ARCHIVOS GRANDES
    ciphertext, tag = aes_cipher.encrypt_and_digest(plaintext)

    # Se cifra la clave AES con RSA
    encrypted_aes_key = cipher_rsa.encrypt(aes_key)

    # Se escribe un archivo binario 'encrypted_file.bin' con la clave AES cifrada
    with open(os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_file.bin'), 'wb') as ef:
        ef.write(encrypted_aes_key)  # Clave AES cifrada
        ef.write(aes_cipher.nonce)  # Nonce de AES
        ef.write(tag)  # Tag de autenticación
        ef.write(ciphertext)  # Texto cifrado

    # Se envía el archivo binario como una descarga adjunta al cliente
    return send_file(os.path.join(app.config['UPLOAD_FOLDER'], 'encrypted_file.bin'), as_attachment=True)

# DESCIFRAR CON LA CLAVE PRIVADA 
@app.route('/decrypt', methods=['POST'])
def decrypt():
    try:
        file_to_decrypt = request.files['file_to_decrypt']
        file_to_decrypt.save(os.path.join(app.config['UPLOAD_FOLDER'], 'file_to_decrypt.bin'))

        private_key = request.files['private_key']
        private_key.save(os.path.join(app.config['UPLOAD_FOLDER'], 'private_key.pem'))

        private_key = RSA.import_key(open(os.path.join(app.config['UPLOAD_FOLDER'], 'private_key.pem')).read())
        cipher_rsa = PKCS1_OAEP.new(private_key)

        # Leer el archivo cifrado
        with open(os.path.join(app.config['UPLOAD_FOLDER'], 'file_to_decrypt.bin'), 'rb') as f:
            encrypted_aes_key = f.read(256)  # Tamaño de la clave RSA cifrada
            nonce = f.read(16)
            tag = f.read(16)
            ciphertext = f.read()

        # Descifrar la clave AES con RSA
        aes_key = cipher_rsa.decrypt(encrypted_aes_key)

        # Descifrar el archivo con AES
        aes_cipher = AES.new(aes_key, AES.MODE_EAX, nonce=nonce)
        decrypted_file = aes_cipher.decrypt_and_verify(ciphertext, tag)

        with open(os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_file.txt'), 'wb') as df:
            df.write(decrypted_file)

        return send_file(os.path.join(app.config['UPLOAD_FOLDER'], 'decrypted_file.txt'), as_attachment=True)
    except Exception as e:
        return f'Error al descifrar el archivo: {str(e)}. <a href="/casimetrico">Volver</a>'


#SUBIR CLAVE AL NAS
@app.route('/upload_public_key', methods=['POST'])
def upload_public_key():
    # Intenta obtener el archivo de clave publica
    uploaded_file = request.files['public_key_file']
    
    if uploaded_file.filename != '':
        # Obtiene el nombre del archivo
        filename = uploaded_file.filename
        # Guarda el archivo en el sistema 
        uploaded_file.save(filename)
        
        # Abre el archivo recién guardado en modo lectura
        with open(filename, 'r') as file:
            # Lee el contenido del archivo y lo almacena en la variable public_key_content
            public_key_content = file.read()
            print(public_key_content)
        
        return "Clave pública subida exitosamente"
    else:
        return "No se ha seleccionado ningún archivo"


#LISTAR LAS CLAVES PUBLICAS

# Definición de la ruta para listar claves públicas
@app.route('/listar_claves_publicas', methods=['GET', 'POST'])
def listar_claves_publicas():
    if request.method == 'POST':
        # Obtiene una lista de las claves seleccionadas
        selected_keys = request.form.getlist('selected_keys')
        
        # Bucle for para descargar las claves seleccionadas
        for key in selected_keys:
            # Envía cada clave seleccionada como un archivo pa descargar
            return send_file(key, as_attachment=True)
    
    # Obtiene la lista de archivos en el directorio actual
    files = os.listdir('.')
    public_keys = []  # Array para almacenar las claves públicas
    
    # Filtra los archivos para obtener las claves públicas
    for file in files:
        if file.endswith('.pem') and 'public' in file.lower():
            public_keys.append(file)
    # Deuvelve las claves
    return render_template('casimetrico.html', public_keys=public_keys)
 
    
#SUBIR CLAVE PUBLICA
@app.route('/subir_archivo', methods=['POST'])
def subir_archivo():
    # Verifica si se ha enviado un archivo en la solicitud
    if 'archivo' not in request.files:
        return 'No se encontró el archivo en la solicitud'

    # oobtiene el archivo enviado en la solicitud
    archivo = request.files['archivo']

    if archivo.filename == '':
        return 'No se seleccionó ningún archivo'
    # Donde se va a subir
    carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back\\Claves Asimetrico'

    if not os.path.exists(carpeta_destino):
        os.makedirs(carpeta_destino)

    # Ruta completa del archivo en el NAS
    ruta_destino = os.path.join(carpeta_destino, secure_filename(archivo.filename))
    # Guarda el archivo en la carpeta de destino
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
