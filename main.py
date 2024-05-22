import tkinter as tk
from tkinter import filedialog
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

#Criptografia sha256 feita por Leonardo

def criptsha256(password):
    hash = hashlib.sha256(password.encode('utf-8')).hexdigest()
    return hash

#Criptografia sha1 feita por Gabrielly
    
def criptsha1(password):
    salt = secrets.token_hex(16) 
    hash_object = hashlib.sha1((password + salt).encode('utf-8'))
    hash = hash_object.hexdigest()
    return hash

#Função para gerar hashes

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

#Carrega a wordlist

def load_wordlist():
    file_path = filedialog.askopenfilename()
    if file_path:
        with open(file_path, 'r', encoding='utf-8') as file:
            wordlist = file.read().splitlines()
            return wordlist
    else:
        return []
    
#Função decripta hashes


#Interface gráfica
    
customtkinter.set_appearance_mode('dark')

root = customtkinter.CTk()
root.title("EasyCripto")

root.geometry("600x500")


#Página de codificação


#----------------- Codificaçaõ -----------------#
#Insere texto

customtkinter.CTkLabel(root, text="Bem-Vindo ao EasyCripto!").pack(pady=10)


customtkinter.CTkLabel(root, text="Insira sua senha:").pack(pady=10)
entry = customtkinter.CTkEntry(root, width=250)
entry.pack(pady=10)

#Selecionar o tipo de hash

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


#PARTE 2 - SEGUNDA TELA
#Descriptografia 

def open_decrypt_window():

    def decrypt_hash():
        target_hash = decrypt_entry.get().strip()
        if not target_hash:
            result_var.set("Por favor, insira um hash para descriptografar.")
            return
    
        wordlist = load_wordlist()
        if not wordlist:
            result_var.set("Selecione uma wordlist para descriptografar.")
            return

        #for word in wordlist:
            #Descriptografia sha256

            #Descriptografia sha1

            #Descriptografia md5

        decrypt_resultado_var.set("Nenhuma correspondência encontrada na wordlist.")


    decrypt_window = customtkinter.CTkToplevel(root)
    decrypt_window.title("EasyCripto")
    decrypt_window.geometry("600x500")

    customtkinter.CTkLabel(decrypt_window, text="Insira o hash:").pack(pady=10)
    decrypt_entry = customtkinter.CTkEntry(decrypt_window, width=500)
    decrypt_entry.pack(pady=10)

    customtkinter.CTkLabel(decrypt_window, text="Selecione o tipo de hash:").pack(pady=10)
    decrypt_hash_type_var = customtkinter.StringVar(value="SHA-256")
    decrypt_hash_type_menu = customtkinter.CTkOptionMenu(decrypt_window, variable=decrypt_hash_type_var, values=["SHA-256", "SHA-1", "bcrypt"])
    decrypt_hash_type_menu.pack(pady=10)

    load_button = customtkinter.CTkButton(decrypt_window, text="Carregar wordlist", command=load_wordlist)
    load_button.pack(pady=10)

    customtkinter.CTkLabel(decrypt_window, text="Sua Senha:").pack(pady=5)
    decrypt_resultado_var = customtkinter.StringVar()
    decrypt_resultado_label = customtkinter.CTkEntry(decrypt_window, textvariable=decrypt_resultado_var, width=250, state="readonly")
    decrypt_resultado_label.pack(pady=10)

    generate_button2 = customtkinter.CTkButton(decrypt_window, text="Desfazer hash", command=decrypt_hash)
    generate_button2.pack(pady=20)

decrypt_button = customtkinter.CTkButton(root, text="Desfazer hash", fg_color="#FF2655", hover_color="#FF073D", command=open_decrypt_window)
decrypt_button.pack(pady=20)



root.mainloop()
