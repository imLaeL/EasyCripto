import hashlib


def criptografar_md5(password):
    hash_md5 = hashlib.md5()
    hash_md5.update(password.encode('utf-8'))
    return hash_md5.hexdigest()


password = "CriptoMd5-Camila.dev"
hash_md5 = criptografar_md5(password)
print('Senha:', password)
print("Hash MD5:", hash_md5)
