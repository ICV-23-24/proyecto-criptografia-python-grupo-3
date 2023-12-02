from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet
from werkzeug.utils import secure_filename
import os

app = Flask(__name__)

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
        return 'Nombre de archivo no proporcionado'

   
