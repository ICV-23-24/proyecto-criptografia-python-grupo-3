from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

def generate_key_pair():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key

def save_key_to_file(key, filename):
    with open(filename, 'wb') as f:
        f.write(key)

def load_key_from_file(filename):
    with open(filename, 'rb') as f:
        key_data = f.read()
    return key_data

def encrypt_file(public_key, input_file, output_file):
    with open(input_file, 'rb') as f:
        plaintext = f.read()

    ciphertext = public_key.encrypt(
        plaintext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as f:
        f.write(ciphertext)

def decrypt_file(private_key, input_file, output_file):
    with open(input_file, 'rb') as f:
        ciphertext = f.read()

    plaintext = private_key.decrypt(
        ciphertext,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    with open(output_file, 'wb') as f:
        f.write(plaintext)

# Generar un par de claves y guardarlas en archivos
private_key, public_key = generate_key_pair()
save_key_to_file(private_key.private_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PrivateFormat.PKCS8,
    encryption_algorithm=serialization.NoEncryption()
), 'private_key.pem')

save_key_to_file(public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
), 'public_key.pem')

# Cifrar un archivo
encrypt_file(public_key, 'input.txt', 'encrypted_file.bin')

# Descifrar el archivo cifrado
decrypt_file(private_key, 'encrypted_file.bin', 'decrypted_file.txt')