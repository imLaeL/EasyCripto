import tkinter as tk
import customtkinter
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
    
customtkinter.set_appearance_mode('dark')

root = customtkinter.CTk()
root.title("EasyCripto")

root.geometry("600x500")

#Insere texto

customtkinter.CTkLabel(root, text="Insira uma string:").pack(pady=10)
entry = customtkinter.CTkEntry(root, width=250)
entry.pack(pady=10)

#Selecioanr o tipo de hash

customtkinter.CTkLabel(root, text="Selecione o tipo de hash:").pack(pady=10)
hash_type_var = customtkinter.StringVar(value="SHA-256")
hash_type_menu = customtkinter.CTkOptionMenu(root, variable=hash_type_var, values=["SHA-256", "SHA-1", "bcrypt"])
hash_type_menu.pack(pady=10)

#Resultado

customtkinter.CTkLabel(root, text="Resultado:").pack(pady=5)
result_var = customtkinter.StringVar()
result_label = customtkinter.CTkEntry(root, textvariable=result_var, width=500, state="readonly")
result_label.pack(pady=10)

#Botão para gerar hash

generate_button = customtkinter.CTkButton(root, text="Gerar Hash", command=generate_hash)
generate_button.pack(pady=20)

root.mainloop()
