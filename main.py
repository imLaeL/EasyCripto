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
    #elif hash_type == "MD5":
        #result = criptmd5(input_text)
    else:
        result = "Tipo de hash inválido."

    result_var.set(result)

#Interface gráfica
    
customtkinter.set_appearance_mode('dark')

root = customtkinter.CTk()
root.title("EasyCripto")

root.geometry("600x500")

#Insere texto

customtkinter.CTkLabel(root, text="Bem-Vindo ao EasyCripto!").pack(pady=10)


customtkinter.CTkLabel(root, text="Insira sua senha:").pack(pady=10)
entry = customtkinter.CTkEntry(root, width=250)
entry.pack(pady=10)

#Selecioanr o tipo de hash

customtkinter.CTkLabel(root, text="Selecione o tipo de hash:").pack(pady=10)
hash_type_var = customtkinter.StringVar(value="SHA-256")
hash_type_menu = customtkinter.CTkOptionMenu(root, variable=hash_type_var, values=["SHA-256", "SHA-1", "bcrypt", "MD5"])
hash_type_menu.pack(pady=10)

#Resultado

customtkinter.CTkLabel(root, text="Resultado:").pack(pady=5)
result_var = customtkinter.StringVar()
result_label = customtkinter.CTkEntry(root, textvariable=result_var, width=500, state="readonly")
result_label.pack(pady=10)

#Botão para gerar hash

generate_button = customtkinter.CTkButton(root, text="Gerar Hash", command=generate_hash)
generate_button.pack(pady=20)


#PARTE 2 - SEGUNDA TELA
#Descriptografia 

def open_decrypt_window():
    decrypt_window = customtkinter.CTkToplevel(root)
    decrypt_window.title("EasyCripto")
    decrypt_window.geometry("600x500")

    customtkinter.CTkLabel(decrypt_window, text="Insira sua senha hash:").pack(pady=10)
    decrypt_entry = customtkinter.CTkEntry(decrypt_window, width=500)
    decrypt_entry.pack(pady=10)

    customtkinter.CTkLabel(decrypt_window, text="Selecione o tipo de hash:").pack(pady=10)
    decrypt_hash_type_var = customtkinter.StringVar(value="SHA-256")
    decrypt_hash_type_menu = customtkinter.CTkOptionMenu(decrypt_window, variable=decrypt_hash_type_var, values=["SHA-256", "SHA-1", "bcrypt", "MD5"])
    decrypt_hash_type_menu.pack(pady=10)

    customtkinter.CTkLabel(decrypt_window, text="Sua Senha:").pack(pady=5)
    decrypt_resultado_var = customtkinter.StringVar()
    decrypt_resultado_label = customtkinter.CTkEntry(decrypt_window, textvariable=decrypt_resultado_var, width=250, state="readonly")
    decrypt_resultado_label.pack(pady=10)

    def decrypt(descriptografia):
        decrypt_resultado_var.set("ADICIONAR O QUE FALTA")

    generate_button2 = customtkinter.CTkButton(decrypt_window, text="Desfazer hash", command=decrypt_hash_type_var)
    generate_button2.pack(pady=20)

decrypt_button = customtkinter.CTkButton(root, text="Desfazer hash", fg_color="#FF2655", hover_color="#FF073D", command=open_decrypt_window)
decrypt_button.pack(pady=20)



root.mainloop()
