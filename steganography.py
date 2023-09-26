from tkinter import *
import tkinter as tk
from tkinter import filedialog
from PIL import Image, ImageTk
import os
from stegano import lsb

root=Tk()
root.title("Image Steganography")
#root.geometry("700x500+150+180")
root.geometry("1024x620")
#root.resizable(False,False)
root.configure(bg="#254155")

def showImage():
    global fileName
    fileName = filedialog.askopenfilename(initialdir=os.getcwd(), title='Select Image File',
                                          filetype=(("PNG file","*.png"),("JPG file","*.jpg"),("All file","*.txt")))
    img=Image.open(fileName)        #open the image
    img=ImageTk.PhotoImage(img)     #load the image
    lbl.configure(image=img, width=250,height=250)
    lbl.image=img


#filedialog -> use filedialog where user have to browse a file
#or a directory from the system.

#askOpenFileName -> return value as a path of file (as string)
#askOpenFile-> Here file is a obj

#initialDir -> Default directory that you want to set when user
#browse foe a file.

#cwd -> current working dir
    
#fileTypes -> mention file type that we want to accept.

#Python OS module provides the facility to establish the
#interaction between the user and the operating system.
#It offers many useful OS functions that are used to perform
#OS-based tasks and get related information about operating system.
#Ex: os.getCWD(), dir(os), os.chdir("C://") etc
    
def Hide():
    global secret
    message = text1.get(1.0,END)
    #Tkinter Text box widget is used to insert multi-line text. This widget can be
    #used for messaging, displaying information
    secret = lsb.hide(str(fileName),message)

def Show():
    clr_msg = lsb.reveal(fileName)
    text1.delete(1.0, END)
    text1.insert(END, clr_msg)

def save():
    secret.save("secret.png")

    
#icon

img_icon = PhotoImage(file="icon.png")

#to change the icon of title bar img should be obj. of PhotoImage class
root.iconphoto(False,img_icon)  #iconphoto-> to set the icon


#Tkinter Label is a widget that is used to implement
#display boxes where you can place text or images.

#Widgets are standard GUI elements, like buttons 

#logo
logo = PhotoImage(file="logoo.png")
Label(root,image=logo,bg="#2f4155").place(x=10,y=0)
Label(root,text="Secret Message", bg="#2d4155", fg="white", font="arial 25 bold").place(x=100,y=20) 

#frame-1
f=Frame(root,bd=3,bg="black",width=340,height=280,relief=GROOVE) #relief->border type #bd->border width#f.place(x=10,y=80)
f.place(x=10,y=80)

lbl=Label(f,bg="black")     #Label is a widget that is used to implement display boxes where you can place text or images.
lbl.place(x=40,y=10)

#frame-2
f2=Frame(root,bd=3,bg="white",width=340,height=280,relief=GROOVE)
f2.place(x=350,y=80)

#HiddenText in frame2
text1=Text(f2,font="Robote 15", bg="white",fg="black",relief=GROOVE)
text1.place(x=0,y=0,width=320,height=290)

#Scrollbar on f2
scrollbar1 = Scrollbar(f2)
scrollbar1.place(x=320, y=0, height=300)

scrollbar1.configure(command=text1.yview)
text1.configure(yscrollcommand=scrollbar1.set)

#fram-3
f3=Frame(root,bd=3,bg="#2f4155",width=330,height=100,relief=GROOVE)
f3.place(x=10,y=370)

Button(f3,text="Choose Image",width=11,height=1,font="arial 14 bold",command=showImage).place(x=20,y=30)
Button(f3,text="Save Image",width=11,height=1,font="arial 14 bold",command=save).place(x=180,y=30)
Label(f3,text=" Photo File",bg="#2f4155",fg="yellow").place(x=20,y=5)

#fram-4
f4=Frame(root,bd=3,bg="#2f4155",width=330,height=100,relief=GROOVE)
f4.place(x=360,y=370)

Button(f4,text="Hide Data",width=11,height=1,font="arial 14 bold",command=Hide).place(x=20,y=30)
Button(f4,text="Show Data",width=11,height=1,font="arial 14 bold",command=Show).place(x=180,y=30)
Label(f4,text=" Photo File",bg="#2f4155",fg="yellow").place(x=20,y=5)

##Add "command" attr to frame 3-4 and make func.

root.mainloop()
