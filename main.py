#Criptografia Bcrypt
import hashlib
import bcrypt

def criptbcrypt(password):
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)

    print(f'Essa é a sua nova senha criptografada: {hash}')

#Criptografia 256

def criptsha256(password):
    hash = hashlib.sha256(password.encode()).hexdigest()
    print("Hash SHA256:", hash)