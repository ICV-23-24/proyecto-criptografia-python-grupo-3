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


#########################################################################################################################
# from flask import Flask, render_template, request, send_file
# from cryptography.fernet import Fernet
# import os
# from googleapiclient.discovery import build
# from googleapiclient.http import MediaFileUpload

# app = Flask(__name__)

# # Clave para el cifrado
# key = Fernet.generate_key()
# cipher_suite = Fernet(key)

# # Credenciales de Google Drive API
# # Reemplaza 'credentials.json' con el archivo de credenciales de tu aplicación en Google Cloud Platform
# # Asegúrate de tener habilitada la API de Google Drive y descargado el archivo JSON de credenciales
# # https://console.cloud.google.com/
# creds = None
# if os.path.exists('token.json'):
#     creds = 'token.json'  # Reemplaza 'token.json' con tu token generado

# drive_service = None
# if creds:
#     drive_service = build('drive', 'v3', credentials=creds)

# @app.route('/')
# def index():
#     return render_template('formulario.html')

# @app.route('/descargar')
# def descargar():
#     return send_file('encrypted_file.txt', as_attachment=True, download_name='encrypted_file.txt', mimetype='text/plain')

# @app.route('/subir_drive')
# def subir_drive():
#     file_metadata = {'name': 'encrypted_file.txt'}
#     media = MediaFileUpload('encrypted_file.txt', mimetype='text/plain')

#     # Sube el archivo cifrado a Google Drive
#     if drive_service:
#         file = drive_service.files().create(body=file_metadata, media_body=media, fields='id').execute()
#         return f'Archivo subido a Google Drive con ID: {file.get("id")}'

#     return 'Error: No se pudo subir el archivo a Google Drive'

# if __name__ == '__main__':
#     app.run(debug=True)
# ###################################################################
# @app.route('/cifrar', methods=['POST'])
# def cifrar():
#     uploaded_file = request.files['file']
    
#     # Verifica si se cargó un archivo y si tiene una extensión .txt
#     if uploaded_file.filename != '' and uploaded_file.filename.endswith('.txt'):
#         file_contents = uploaded_file.read()
#         encrypted_data = cipher_suite.encrypt(file_contents)

#         # Guarda el archivo cifrado temporalmente
#         with open('encrypted_file.txt', 'wb') as encrypted_file:
#             encrypted_file.write(encrypted_data)
        
#         return render_template('resultado.html')
#     else:
#         return "Por favor, seleccione un archivo de texto (.txt)"

# @app.route('/descifrar', methods=['POST'])
# def descifrar():
#     uploaded_file = request.files['file']
    
#     # Verifica si se cargó un archivo y si tiene una extensión .txt
#     if uploaded_file.filename != '' and uploaded_file.filename.endswith('.txt'):
#         file_contents = uploaded_file.read()
#         decrypted_data = cipher_suite.decrypt(file_contents)

#         # Guarda el archivo descifrado temporalmente
#         with open('decrypted_file.txt', 'wb') as decrypted_file:
#             decrypted_file.write(decrypted_data)
        
#         return send_file('decrypted_file.txt', as_attachment=True, download_name='decrypted_file.txt', mimetype='text/plain')
#     else:
#         return "Por favor, seleccione un archivo de texto (.txt)"
from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet

app = Flask(__name__)

# Genera una clave para el cifrado
key = Fernet.generate_key()
cipher_suite = Fernet(key)

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/cifrar', methods=['POST'])
def cifrar():
    if 'file' not in request.files:
        return "No se ha seleccionado ningún archivo"

    file = request.files['file']
    if file.filename == '':
        return "No se ha seleccionado ningún archivo"

    if file:
        # Lee el archivo y cifra su contenido
        file_contents = file.read()
        encrypted_data = cipher_suite.encrypt(file_contents)

        # Crea un nuevo archivo con el contenido cifrado
        with open('encrypted_file.txt', 'wb') as encrypted_file:
            encrypted_file.write(encrypted_data)

        return send_file('encrypted_file.txt', as_attachment=True)

    return "Error al cifrar el archivo"

@app.route('/descifrar', methods=['POST'])
def descifrar():
    if 'file' not in request.files:
        return "No se ha seleccionado ningún archivo"

    file = request.files['file']
    if file.filename == '':
        return "No se ha seleccionado ningún archivo"

    if file:
        encrypted_data = file.read()
        try:
            decrypted_data = cipher_suite.decrypt(encrypted_data)
            with open('decrypted_file.txt', 'wb') as decrypted_file:
                decrypted_file.write(decrypted_data)
            return send_file('decrypted_file.txt', as_attachment=True)
        except Exception as e:
            return f"Error al descifrar el archivo: {str(e)}"

    return "Error al descifrar el archivo"

if __name__ == '__main__':
    app.run(debug=True)



