#Criptografia Bcrypt
import hashlib
import bcrypt
import secrets

#Criptografia Bcrypt feita por João

def criptbcrypt(password):
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)
    print(f'Essa é a sua nova senha criptografada: {hash}')

#Criptografia 256 feita por Leonardo

def criptsha256(password):
    hash = hashlib.sha256(password.encode()).hexdigest()
    print("Hash SHA256:", hash)

#Criptografia sha1
    
def criptsha1(password):
    salt = secrets.token_hex(16) 
    hash_object = hashlib.sha1((password + salt).encode())
    hash_hex = hash_object.hexdigest()
    print("Hash SHA1:", hash_hex)