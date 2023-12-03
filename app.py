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

app = Flask(__name__)
public_keys = []  # Lista para almacenar los nombres de las claves públicas

@app.route('/listar_claves_publicas')
def listar_claves_publicas():
    files = os.listdir('.')  # Obtener todos los archivos en el directorio actual
    public_keys.clear()  # Limpiar la lista de claves públicas antes de añadir nombres nuevos
    for file in files:
        if file.endswith('.pem') and 'public' in file.lower():  # Filtrar por archivos .pem y que contengan 'public' en el nombre
            public_keys.append(file)
    print(public_keys)  # Agregar esta línea para imprimir los nombres de los archivos
    return render_template_string(open('templates/index.html', 'r', encoding='utf-8').read(), public_keys=public_keys)

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

@app.route('/')
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

    return render_template('index.html', public_key=public_key_pem, private_key=private_key_pem)

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

# Ruta para descargar la clave
@app.route('/descargar_clave', methods=['GET'])
def descargar_clave():
    key = cargar_clave()
    if key:
        with open('key.key', 'wb') as key_file:
            key_file.write(key)
        return send_file('key.key', as_attachment=True)
    return "No se ha generado ninguna clave aún."

# Ruta principal
@app.route('/')
def index():
    return render_template('index.html')

# Ruta para cifrar archivos
@app.route('/cifrar', methods=['POST'])
def cifrar():
    if 'file' not in request.files or 'key' not in request.files:
        return "No se ha seleccionado algún archivo o clave"

    file = request.files['file']
    key_file = request.files['key']

    if file.filename == '' or key_file.filename == '':
        return "No se ha seleccionado algún archivo o clave"

    file_contents = file.read()
    key = key_file.read()

    cipher_suite = Fernet(key)
    encrypted_data = cipher_suite.encrypt(file_contents)

    # Obtén la opción de guardado del formulario
    save_option = request.form.get('save_option')

    if save_option == 'local':
        # Guardar localmente
        with open('encrypted_file.txt', 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        return send_file('encrypted_file.txt', as_attachment=True)
    elif save_option == 'destino':
        # Guardar en la carpeta de destino
        carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'
        if not os.path.exists(carpeta_destino):
            os.makedirs(carpeta_destino)

        # Utilizar el nombre del archivo cifrado para construir la ruta de destino
        nombre_archivo_cifrado = secure_filename(file.filename)
        ruta_destino = os.path.join(carpeta_destino, nombre_archivo_cifrado + '_cifrado.txt')

        with open(ruta_destino, 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)
        return f'Archivo cifrado guardado con éxito en {ruta_destino}'

    return "Opción de guardado no válida"

# Ruta para descifrar archivos
@app.route('/descifrar', methods=['POST'])
def descifrar():
    if 'file' not in request.files or 'key' not in request.files:
        return "No se ha seleccionado algún archivo o clave"

    try:
        file = request.files['file']
        key_file = request.files['key']

        if file.filename == '' or key_file.filename == '':
            return "No se ha seleccionado algún archivo o clave"

        encrypted_data = file.read()
        key = key_file.read()

        # Obtén la opción de guardado del formulario
        save_option = request.form.get('save_option')

        decrypted_data = descifrar_datos(encrypted_data, key)

        if save_option == 'local':
            # Guardar localmente
            with open('decrypted_file.txt', 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            return send_file('decrypted_file.txt', as_attachment=True)
        elif save_option == 'destino':
            # Guardar en la carpeta de destino
            carpeta_destino = '\\\\DESKTOP-2HO19U6\\Colombia is Back'
            if not os.path.exists(carpeta_destino):
                os.makedirs(carpeta_destino)

            # Utilizar el nombre del archivo descifrado para construir la ruta de destino
            nombre_archivo_descifrado = secure_filename(file.filename.replace('_cifrado.txt', '_descifrado.txt'))
            ruta_destino = os.path.join(carpeta_destino, nombre_archivo_descifrado)

            with open(ruta_destino, 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            return f'Archivo descifrado guardado con éxito en {ruta_destino}'

        return "Opción de guardado no válida"

    except Exception as e:
        return f"Error al descifrar el archivo: {str(e)}"

# Ruta para subir archivos
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

# Ruta para descargar archivos desde la carpeta compartida
@app.route('/descargar_archivo', methods=['GET'])
def descargar_archivo():
    nombre_archivo = request.args.get('nombre_archivo')

    if not nombre_archivo:
        return
