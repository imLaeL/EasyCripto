#Hash Sha-1
import hashlib
import secrets

salt = secrets.token_hex(16)
senha = input("Digite sua senha:\n") 
hash_object = hashlib.sha1((senha + salt).encode())
hash_hex = hash_object.hexdigest()

print(hash_object.hexdigest())

