from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
import os
# Utilizaremos el método "generate_private_key"
# para generar nuestra clave
# asignamos algunos parametros
private_key = rsa.generate_private_key(
     public_exponent=65537,
     key_size=2048,
     backend=default_backend()
)

# Ahora generaremos la clave pública
public_key = private_key.public_key()

# Solicitamos al usuario ingresar un nombre base para los archivos
file_base_name = input("Ingresa el nombre base para los archivos (sin extensión): ")

# Guardamos la clave privada en un archivo con el prefijo "priv"
private_key_filename = f"priv_{file_base_name}.pem"
with open(private_key_filename, "wb") as private_key_file:
    private_key_file.write(
        private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )
    )

# Guardamos la clave pública en un archivo con el prefijo "public"
public_key_filename = f"public_{file_base_name}.pem"
with open(public_key_filename, "wb") as public_key_file:
    public_key_file.write(
        public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )

print(f"Las claves se han guardado en {private_key_filename} y {public_key_filename}")

files_in_directory = os.listdir()
public_key_files = [filename for filename in files_in_directory if filename.startswith("public_")]

# Guardamos la lista de archivos en un archivo llamado "public_key_files.txt"
with open("public_key_files.txt", "w") as file_list:
    file_list.write("\n".join(public_key_files))
