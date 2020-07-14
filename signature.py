#-*-coding: utf-8 -*-
from tkinter import *
#from Tkinter import *

window = Tk()
window.title("An Toàn Bảo Mật Thông Tin")
lb0 = Label(window, text = "                ", font=("Arial Bold", 10) )
lb0.grid(column=0,row=0)

lb2=Label(window,text="DEMO: CHỮ KÝ SỐ",font=("Arial Bold" ,15))
lb2.grid(column=2,row=0)

plainlb3=Label(window,text="Sign message",font=("Arial",13))
plainlb3.grid(column=0,row=4)

plaintxt=Entry(window,width=20)
plaintxt.grid(column=1, row=4)

resulttxt2=Entry(window,width=20)
resulttxt2.grid(column=1, row=5)

KEYlb4=Label(window,text="PUBLIC KEY",font=("Arial",13))
KEYlb4.grid(column=3,row=4)
KEYA1=Entry(window,width=20)
KEYA1.grid(column=4,row=4)

KEYlb4=Label(window,text="PRIVATE KEY",font=("Arial",13))
KEYlb4.grid(column=3,row=5)
KEYB1=Entry(window, width=20)
KEYB1.grid(column=4,row=5)

lb5=Label(window,text="Verify message",font=("Arial",13))
lb5.grid(column=1,row=7)


ciphertxt3=Entry(window,width=20)
ciphertxt3.grid(column=2, row=7)

dentxt3=Entry(window, width=20)
dentxt3.grid(column=2,row=8)

from Crypto.PublicKey import RSA
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA256
import binascii

# Generate 1024-bit RSA key pair (private + public key)
keyPair = RSA.generate(bits=1024)
pubKey = keyPair.publickey()


def keyCourse():
    KEYB1.insert(INSERT, keyPair)

    KEYA1.insert(INSERT, pubKey)

# Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
def sigInput():
    global signature
    msg = plaintxt.get()
    msg1 = str.encode(msg)
    hash = SHA256.new(msg1)
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash)
    resulttxt2.insert(INSERT, binascii.hexlify(signature))

# Verify valid PKCS#1 v1.5 signature (RSAVP1)
def sigOutput():
    msg = ciphertxt3.get()
    msg1 = str.encode(msg)
    hash = SHA256.new(msg1)
    verifier = PKCS115_SigScheme(pubKey)
    dentxt3.delete(0, END)
    try:
        verifier.verify(hash, signature)
       # print("Signature is valid.")
        dentxt3.insert(INSERT, "Chữ ký hợp lệ!")
    except:
       # print("Signature is invalid.")
        dentxt3.insert(INSERT, "Chữ ký không hợp lệ!")

DESbtn = Button(window,text="Sinh khóa", command=keyCourse)
DESbtn.grid(column=2,row=4)
DESbtn = Button(window,text="Tạo chữ ký", command=sigInput)
DESbtn.grid(column=0,row=5)
DE_DESbtn = Button(window,text="Kết quả", command=sigOutput)
DE_DESbtn.grid(column=1, row=8)	


window.geometry('800x600')
window.mainloop()