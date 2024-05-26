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
    hash_object = hashlib.sha1((password).encode('utf-8'))
    hash = hash_object.hexdigest()
    return hash

#Criptografia md5 feita por Camila

def criptmd5(password):
    hash_md5 = hashlib.md5()
    hash_md5.update(password.encode('utf-8'))
    hash = hash_md5.hexdigest()
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
    elif hash_type == "MD5":
        result = criptmd5(input_text)
    else:
        result = "Tipo de hash inválido."

    result_var.set(result)
    

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

    #Carrega a wordlist

    def load_wordlist():
        file_path = filedialog.askopenfilename()
        if file_path:
            with open(file_path, 'r', encoding='utf-8') as file:
                wordlist = file.read().splitlines()
                return wordlist
        else:
            return []

    def decrypt_hash():
        target_hash = decrypt_entry.get().strip()
        if not target_hash:
            decrypt_resultado_var.set("Por favor, insira um hash para descriptografar.")
            return
    
        wordlist = load_wordlist()

        if not wordlist:
            decrypt_resultado_var.set("Selecione uma wordlist para descriptografar.")
            return

        for word in wordlist:

            #Descriptografia sha256

            sha256_hash = criptsha256(word)
            if sha256_hash == target_hash:
                decrypt_resultado_var.set(word)
                return

            #Descriptografia sha1
            
            sha_1_hash = criptsha1(word)
            if sha_1_hash == target_hash:
                decrypt_resultado_var.set(word)
                return

            #Descriptografia md5

            md5_hash = criptmd5(word)
            if md5_hash == target_hash:
                decrypt_resultado_var.set(word)
                return

        decrypt_resultado_var.set("Nenhuma correspondência encontrada na wordlist.")


    decrypt_window = customtkinter.CTkToplevel(root)
    decrypt_window.title("EasyCripto")
    decrypt_window.geometry("600x500")

    #Insere o hash

    customtkinter.CTkLabel(decrypt_window, text="Insira o hash:").pack(pady=10)
    decrypt_entry = customtkinter.CTkEntry(decrypt_window, width=500)
    decrypt_entry.pack(pady=10)

    #Selcionar o tipo de hash

    customtkinter.CTkLabel(decrypt_window, text="Selecione o tipo de hash:").pack(pady=10)
    decrypt_hash_type_var = customtkinter.StringVar(value="SHA-256")
    decrypt_hash_type_menu = customtkinter.CTkOptionMenu(decrypt_window, variable=decrypt_hash_type_var, values=["SHA-256", "SHA-1", "bcrypt", "MD5"])
    decrypt_hash_type_menu.pack(pady=10)

    #Resultado da decodificação

    customtkinter.CTkLabel(decrypt_window, text="Sua Senha:").pack(pady=5)
    decrypt_resultado_var = customtkinter.StringVar()
    decrypt_resultado_label = customtkinter.CTkEntry(decrypt_window, textvariable=decrypt_resultado_var, width=250, state="readonly")
    decrypt_resultado_label.pack(pady=10)

    #Botão para descriptografar

    generate_button2 = customtkinter.CTkButton(decrypt_window, text="Desfazer hash", command=decrypt_hash)
    generate_button2.pack(pady=20)

decrypt_button = customtkinter.CTkButton(root, text="Desfazer hash", fg_color="#FF2655", hover_color="#FF073D", command=open_decrypt_window)
decrypt_button.pack(pady=20)



root.mainloop()
