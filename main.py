#Criptografia Bcrypt
import hashlib
import bcrypt

password = input('Digite a senha que deseja criptografar: ')
bytes = password.encode('utf-8')
salt = bcrypt.gensalt()
hash = bcrypt.hashpw(bytes, salt)

print(f'Essa é a sua nova senha criptografada: {hash}')

#Criptografia 256

texto = "Aprendendo a criar hash com SHA256"
hash = hashlib.sha256(texto.encode()).hexdigest()

print("Texto original:", texto)
print("Hash SHA256:", hash)