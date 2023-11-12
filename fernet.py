from cryptography.fernet import Fernet

# Generamos una clave
clave = Fernet.generate_key()

# Creamos la instancia de Fernet
f = Fernet(clave)

# Especifica la ruta del archivo que deseas cifrar
archivo_a_cifrar = './hola.txt'

# Leemos el contenido del archivo
with open(archivo_a_cifrar, 'rb') as file:
    contenido_archivo = file.read()

# Encriptamos el contenido del archivo
archivo_encriptado = f.encrypt(contenido_archivo)

# Especifica la ruta donde deseas guardar el archivo cifrado
archivo_cifrado = './cifrado.txt'

# Guardamos el archivo cifrado
with open(archivo_cifrado, 'wb') as file:
    file.write(archivo_encriptado)

# Imprimimos la clave (guárdala en un lugar seguro para futura desencriptación)
print("Clave:", clave)
