#Cryptography is the process practice or study of techniques for
#secure communication

#Encryption is the process of translating image into something that
#appears to be random and meaningless(ciphertext)

#Decryption is the process of converting ciphertext back to image

#filedialog -> use filedialog where user have to browse a file
#or a directory from the system.

#The fernet module of the cryptography package has inbuilt functions for the generation of the key,
#Fernet guarantees that a message encrypted using it cannot be manipulated or read without the key.

#The tkinter package (“Tk interface”) is the standard Python interface to the Tcl/Tk GUI toolkit.
#Both Tk and tkinter are available on most Unix platforms, including macOS, as well as on Windows systems.
#(Tool Command Language) Tk(toolkit)

#partial func allow us to fix a certain number of args of a func and generate
#a new func
#It can be used to derive specialized functions from general funcnd therefore help
# us to reuse our code
#making a new fun by prior func with one param const.



                         ############################################## PACKAGES & MODULES ###########################################


from cryptography.fernet import Fernet
from tkinter import *
from tkinter import messagebox
from tkinter import filedialog
from functools import partial

                        ############################################## GLOBAL VARIABLES #############################################

global filename
button_height = 2
button_width = 25


                       ############################################# BROWSE FILES ##################################################


def browseFiles():
    browseFiles.filename = filedialog.askopenfilename(initialdir="/", title="Select a File",)
    file_explorer.configure(text="File Opened: " + browseFiles.filename)

    passwd_label.pack()
    password_entry.pack()
    temp_label.pack()
    button_encrypt.pack()
    button_decrypt.pack()
    
#open() -> Allocates some resources and memory
#close() -> Release "-----------------------"
#with keyword -> Release memory/resource automatically
#file saves instance of open func

                    ############################################# ENCRYPTION ######################################################

'''

1.Generate a secret key using the Fernet module
2.Save the secret key to a file for later use
3.Load the secret key from the file
4.Create a Fernet object using the secret key
5.Read the contents of the file to be encrypted
6.Encrypt the contents of the file using the Fernet object
7.Save the encrypted contents to a file
8.To decrypt the file, load the secret key from the file, create a Fernet object using the key,
  read the contents of the encrypted file, and decrypt the contents using the Fernet object:

'''
    
def encrypt_file(pass_word):
    secret_key = pass_word.get()
    if secret_key == "":
        messagebox.showerror("Alert", "Please enter secret key")
    else:     
        secret_key = ''.join(p for p in secret_key if p.isalnum())
        key = secret_key + ("s" * (43 - len(secret_key)) + "=")

        fernet = Fernet(key)

        with open(browseFiles.filename, 'rb') as file:  original = file.read()
        encrypted = fernet.encrypt(original)

        with open(browseFiles.filename, 'wb') as encrypted_file:    encrypted_file.write(encrypted)

        status_label.configure(text="Encrypted")
        status_label.pack()

#the "wb" mode opens the file in binary format for writing while the "rb" opens the file in binary format for reading.
#Binary files are not readable by humans, in contrast to text files. Any text editor can be used to open the data, but it is unusable.


                  ############################################## DECRYPTION ####################################################


def decrypt_file(pass_word):
    secret_key = pass_word.get()
    if secret_key == "":
        messagebox.showerror("Alert", "Please enter secret key")
    else:    
        secret_key = ''.join(p for p in secret_key if p.isalnum())
        key = secret_key + ("s" * (43 - len(secret_key)) + "=")

        fernet = Fernet(key)
        

        with open(browseFiles.filename, 'rb') as encrypt_file:  encrypted = encrypt_file.read()
        decrypted = fernet.decrypt(encrypted)

        with open(browseFiles.filename, 'wb') as decrypt_file:  decrypt_file.write(decrypted)

        status_label.configure(text="Decrypted")
        status_label.pack()


    ################################################################  USER INTERFACE ############################################################################

    ################################################################     Tkinter     ############################################################################    

root = Tk()

root.title('File Encryptor and Decryptor')
root.geometry("1460x740")
root.config(background="black")

main_title = Label(root, text = "File Encrypter and Decrypter", width=100, height=2, fg="white", bg="black", font=("",30))
password = StringVar()

#A variable defined using StringVar() holds a string data where we can set text value and can retrieve it.
#Also, we can pass this variable to textvariable parameter for a widget like Entry.
#The widget will automatically get updated with the new value whenever the value of the StringVar() variable changes.

encrypt_fun = partial(encrypt_file,password)
decrypt_fun = partial(decrypt_file,password)

credit = Label(root, text="Developed By CSE Department Group-19, Major Project-I", bg="black", height=2, fg="white", font=("",15))
file_explorer = Label(root, text="File Name: ", width=100, height=2, fg="white", bg="black",font=("",20))
passwd_label = Label(root, text="Enter the Secret key: ", width=100, height=2, fg="white", bg="black",font =("",20)) 
temp_label = Label(root, text="",height=3,bg="black")

button_explore = Button(root, text="Browse File", command=browseFiles, width=button_width, height=button_height, font =("",15))

password_entry = Entry(root, textvariable=password,show="*")                     


button_encrypt = Button(root, text="Encrypt", command=encrypt_fun, width=button_width, height=button_height, font =("",15))
button_decrypt = Button(root, text="Decrypt", command=decrypt_fun, width=button_width, height=button_height, font =("",15))


status_label = Label(root, text="", width=100, height=4, fg="white", bg="black",font =("",17))

credit.pack()
main_title.pack()
file_explorer.pack()
button_explore.pack()
root.mainloop()

'''
pack is a layout manager that aumotically placeas the widget in window based upon the space available in the window.
pack organizes widgets in blocks in vertical oprder before placing them in the parent widget.
'''

                     ################################################################     END     ############################################################################
