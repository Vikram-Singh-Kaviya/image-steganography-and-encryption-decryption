import os
from tkinter import*
from tkinter import ttk
import tkinter as tk
from tkinter.filedialog import*
import tkinter.messagebox
import PIL 
from PIL import Image,ImageTk 
import hashlib

from cryptography.hazmat.primitives.ciphers.algorithms import AES


import file_Encryption

from file_Encryption import encrypt_file, decrypt_file


def pass_alert():
    tkinter.messagebox.showinfo("Password Alert","Please enter a password.")



def encrypt():
    
    global file_path_e
    enc_pass = pass_alert()
    if enc_pass == "":
        pass_alert()
    else:
        
        #LOAD THE IMAGE
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        
        #GENERATE KEY & INITIALIZATION VECTOR
        hash=hashlib.sha256(enc_pass.encode())
        p = hash.digest()
        key = p
        iv = p.ljust(16)[:16]
        print("Encoding key is: ",key)
        
        input_file = open(filename,'rb' )
        input_data = input_file.read()
        input_file.close()
        file_Encryption.enc_image(input_data,key,iv,file_path_e)
        tkinter.messagebox.showinfo("Encryption Alert","Encryption ended successfully.File stored as: encrypted .enc")
        
        
def decrypt(Crypto=None):
    
    global file_path_e
    enc_pass = pass_alert()
    if enc_pass =="":
        pass_alert()
    else:
        filename = tkinter.filedialog.askopenfilename()
        file_path_e = os.path.dirname(filename)
        
        hash=hashlib.sha256(enc_pass.encode())
        p = hash.digest()
        key = p
        iv = p.ljust(16)[:16]
        input_file = open(filename,'rb' )
        input_data = input_file.read()
        input_file.close()
        file_Encryption.enc_image(input_data,key,iv,file_path_e)
        
        tkinter.messsagebox.showinfo("Decryption Alert","Decryption ended successfully File Stored as: output.png")
        
        
        #GUI STUFF
        top=tk.Tk()
        top.geometry("500x150")
        top.resizable(0,0)
        top.title("Image Encryption")
        
        
        title = "Image Encryption Using AES"
        msgtitle = Message(top,text=title)
        msgtitle.config(font=('helvetica',17,'bold'),width=300)
        msgtitle.pack()
        
        
        sp="-------------------------------------------------"
        sp_title=Message(top,text=sp)
        sp_title.config(font=('arial',12),width=650)
        sp_title.pack()
        
        
        passlabel = Label(top,text="Enter Encryption/Decryption Key:")
        passlabel.pack()
        passg = Entry(top,show="*",width=20)
        passg.config(highlightthickness=1,highlightbaground="blue")
        passg.pack()
        
        
        encrypt=Button(top,text="Encrypt",width=28,height=3,command=encrypt_file)
        encrypt.pack(side=LEFT)
        
        decrypt=Button(top,text="Decrypt",width=28,height=3,command=decrypt_file)
        decrypt.pack(side=RIGHT)
        
        
        top.mainloop()
        
        #from Crypto.Cipher import AES
        
def enc_image(input_data,key,iv,filepath):
    cfb_cipher = AES.new(key,AES.MODE_CFB,iv)
    enc_data = cfb_cipher.encrpt(input_data)
    
    enc_file = open(filepath+"/encrypted.enc","web")
    enc_file.write(enc_data)
    enc_file.close()
    
    
def dec_image(input_data,key,iv,filepath):
    
    cfb_decipher = AES.new(key,AES.MODE_CFB,iv)
    plain_data = cfb_decipher.decrypt(input_data)
    
    
    output_file = open(filepath+"/output.png","web")
    output_file.write(plain_data)
    output_file.close()
    
    
        
        
        
        
        
    
        
      