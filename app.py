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
from flask import Flask, render_template, request, send_file
from cryptography.fernet import Fernet

# from google.auth.transport.requests import Request
# from google.oauth2.credentials import Credentials
# from google_auth_oauthlib.flow import InstalledAppFlow
# from googleapiclient.discovery import build
# import os


# # Las credenciales de la API de Google Drive se deben configurar previamente
# SCOPES = ['https://www.googleapis.com/auth/drive.file']
# CLIENT_SECRET_FILE = 'client_secret.json'
# CLIENT_SECRET_FILE = os.environ.get('CLIENT_SECRET_FILE', 'client_secret.json')
# API_NAME = 'drive'
# API_VERSION = 'v3'

# def get_drive_service():
#     creds = None
#     if os.path.exists('token.json'):
#         creds = Credentials.from_authorized_user_file('token.json')
#     if not creds or not creds.valid:
#         if creds and creds.expired and creds.refresh_token:
#             creds.refresh(Request())
#         else:
#             flow = InstalledAppFlow.from_client_secrets_file(CLIENT_SECRET_FILE, SCOPES)
#             creds = flow.run_local_server(port=0)
#         with open('token.json', 'w') as token:
#             token.write(creds.to_json())
#     return build(API_NAME, API_VERSION, credentials=creds)

# drive_service = get_drive_service()

# @app.route('/')
# def index():
#     return render_template('index.html')

# @app.route('/cifrar', methods=['POST'])
# def cifrar():
#     if 'file' not in request.files:
#         return "No se ha seleccionado ningún archivo"

#     file = request.files['file']
#     if file.filename == '':
#         return "No se ha seleccionado ningún archivo"

#     if file:
#         # Subir archivo a Google Drive
#         file_metadata = {'name': file.filename}
#         media = drive_service.files().create(body=file_metadata, media_body=file).execute()

#         return f"Archivo cifrado subido a Google Drive: {media['id']}"

#     return "Error al cifrar y subir el archivo a Google Drive"
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
#######################################################
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
    




@app.route("/hola/")
def hola():
    return render_template("hola.html")