#Criptografia Bcrypt

import bcrypt
password = input('Digite a senha que deseja criptografar: ')
bytes = password.encode('utf-8')
salt = bcrypt.gensalt()
hash = bcrypt.hashpw(bytes, salt)

print(f'Essa é a sua nova senha criptografada: {hash}')
