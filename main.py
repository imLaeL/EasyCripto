import tkinter as tk
import hashlib
import bcrypt
import secrets

#Criptografia Bcrypt feita por João

def criptbcrypt(password):
    bytes = password.encode('utf-8')
    salt = bcrypt.gensalt()
    hash = bcrypt.hashpw(bytes, salt)
    return hash

#Criptografia 256 feita por Leonardo

def criptsha256(password):
    hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hash

#Criptografia sha1 feita por Gabrielly
    
def criptsha1(password):
    salt = secrets.token_hex(16) 
    hash_object = hashlib.sha1((password + salt).encode('utf-8'))
    hash = hash_object.hexdigest()
    return hash

def generate_hash():
    input_text = entry.get()
    hash_type = hash_type_var.get()

    if not input_text:
        result_var.set("Por favor insira um hash.")
        return
    
    if hash_type == "SHA-256":
        result = criptsha256(input_text)
    elif hash_type == "SHA-1":
        result = criptsha1(input_text)
    elif hash_type == "bcrypt":
        result = criptbcrypt(input_text)
    else:
        result = "Tipo de hash inválido."

    result_var.set(result)

#Interface gráfica
    
root = tk.Tk()
root.title("EasyCripto")

root.geometry("600x300")

#Insere texto

tk.Label(root, text="Insira uma string:").pack(pady=5)
entry = tk.Entry(root, width=50)
entry.pack(pady=5)

#Selecioanr o tipo de hash

tk.Label(root, text="Selecione o tipo de hash:").pack(pady=5)
hash_type_var = tk.StringVar(value="SHA-256")
hash_type_menu = tk.OptionMenu(root, hash_type_var, "SHA-256", "SHA-1", "bcrypt")
hash_type_menu.pack(pady=5)

#Resultado

tk.Label(root, text="Resultado:").pack(pady=5)
result_var = tk.StringVar()
result_label = tk.Entry(root, textvariable=result_var, width=70, state="readonly")
result_label.pack(pady=7)

#Botão para gerar hash

generate_button = tk.Button(root, text="Gerar Hash", command=generate_hash)
generate_button.pack(pady=10)

root.mainloop()
