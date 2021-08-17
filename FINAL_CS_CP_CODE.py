import tkinter as tk
import string
import itertools
from tkinter import *
import tkinter.font as tkfont
import numpy as np
#from sympy import Matrix

text=""
s=0

def createNewWindow1():
    newWindow1 = tk.Toplevel(app)
    newWindow1.configure(bg='#87CEFA')
    newWindow1.geometry("800x800")
    ceaserCipher1=tk.Label(newWindow1, text="Input Text", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    CipherInfo = Label(newWindow1, text= "(Single Alphabetic Substitution Cipher)", fg="#000066", bg="#87CEFA", font=tkfont.Font(family="Helvetica",size=14))
    e1 = tk.Entry(newWindow1,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    ceaserCipher2=tk.Label(newWindow1, text="key",bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e2 = tk.Entry(newWindow1,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e3=tk.Entry(newWindow1,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e4=tk.Entry(newWindow1,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    ceaserCipher3= tk.Label(newWindow1, text = "Ceaser Cipher Text", fg = "#000066", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=25,weight="bold"))
    ceaserCipher4= tk.Label(newWindow1, text = "Cipher Text", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    ceaserCipher5= tk.Label(newWindow1, text = "Key", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    
    ceaserCipher5.pack()
    ceaserCipher4.pack()
    ceaserCipher3.pack()
    ceaserCipher2.pack()
    ceaserCipher1.pack()
    CipherInfo.pack()
    
    e1.pack()
    e2.pack()
    e3.pack()
    e4.pack()
    e1.place(x=400, y=100)
    e2.place(x=400, y=160)
    e3.place(x=400, y=260)
    e4.place(x=400, y=320)
    ceaserCipher1.place(x=300, y=100)
    ceaserCipher2.place(x=300, y=160)
    
    ceaserCipher4.place(x=300, y=260)
    ceaserCipher5.place(x=300, y=320)
    
    label_result=tk.Label(newWindow1,bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    label1=tk.Label(newWindow1,bg ='#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    def encrypt():
        
        text = e1.get()
        s = e2.get()
        p=int(s)
        print(text)
        print(p)
    
        result = ""
        
        for i in range(len(text)):
            char = text[i]

                # Encrypt uppercase characters
            if (char.isupper()):
                result += chr((ord(char) + p-65) % 26 + 65)

                # Encrypt lowercase characters
            else:
                result += chr((ord(char) + p - 97) % 26 + 97)
        
    
    
        def pro():
            print(result)
        label_result.config(text=result) 
        label_result.pack()
        label_result.place(x=650,y=200)     
    btnceaserCipher1 = tk.Button(newWindow1, text = "Encryption",command=(encrypt), height = 2, width = 20,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnceaserCipher1.pack()
    btnceaserCipher1.place(x=350, y=200)
    
    def decrypt():
        alphabet = string.ascii_lowercase # "abcdefghijklmnopqrstuvwxyz"
        encrypted_message=e3.get()
        k=e4.get()
        key=int(k)
        print(encrypted_message)
        print(key)
        
        decrypted_message = ""

        for c in encrypted_message:

            if c in alphabet:
                position = alphabet.find(c)
                new_position = (position - key) % 26
                new_character = alphabet[new_position]
                decrypted_message += new_character
            else:
                decrypted_message += c

        def pro1():
            print(decrypted_message)
        label1.config(text=decrypted_message)
        label1.pack()
        label1.place(x=650,y=360)
    btnceaserCipher2 = tk.Button(newWindow1, text = "Decryption",command=decrypt, height = 2, width = 20, fg = "white", bg = "#000066",font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnceaserCipher2.pack()
    btnceaserCipher2.place(x=350, y=360)
   

    
    


def createNewWindow2():
    newWindow2 = tk.Toplevel(app)
    newWindow2.geometry("800x800")
    newWindow2.configure(bg='#87CEFA')
    playfairCipher1= tk.Label(newWindow2, text = "Playfair Cipher Text", fg = "#000066", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=25,weight="bold"))
    CipherInfo = Label(newWindow2, text= "(Polyalphabetic Substitution Cipher)", fg="#000066", bg="#87CEFA", font=tkfont.Font(family="Helvetica",size=14))
    playfairCipher2=tk.Label(newWindow2,text = "Input Text",bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    playfairCipher3=tk.Label(newWindow2,text = "Key", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    playfairCipher4=tk.Label(newWindow2,text = "Cipher Text",bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    playfairCipher5=tk.Label(newWindow2,text = "Key",bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    
    f1=tk.Entry(newWindow2,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    f2=tk.Entry(newWindow2,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    f3=tk.Entry(newWindow2,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    f4=tk.Entry(newWindow2,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    playfairCipher5.pack()
    playfairCipher4.pack()
    playfairCipher3.pack()
    playfairCipher2.pack()
    playfairCipher1.pack()
    CipherInfo.pack()
    f1.pack()
    f2.pack()
    f3.pack()
    f4.pack()
    playfairCipher2.place(x=300,y=100)
    playfairCipher3.place(x=300,y=160)
    playfairCipher4.place(x=300,y=260)
    playfairCipher5.place(x=300,y=320)
    f1.place(x=400,y=100)
    f2.place(x=400,y=160)
    f3.place(x=400,y=260)
    f4.place(x=400,y=320)
    
    
    def encryption():
        plaintext = f1.get()
        key1=f2.get()
        def chunker(seq, size):
            it = iter(seq)
            while True:
                chunk = tuple(itertools.islice(it, size))
                if not chunk:
                    return
                yield chunk



        def prepare_input(dirty):
            """
            Prepare the plaintext by up-casing it
            and separating repeated letters with X's
            """
            
            dirty = ''.join([c.upper() for c in dirty if c in string.ascii_letters])
            clean = ""

            if len(dirty) < 2:
                return dirty

            for i in range(len(dirty)-1):
                clean += dirty[i]

                if dirty[i] == dirty[i+1]:
                    clean += 'X'

            clean += dirty[-1]

            if len(clean) & 1:
                clean += 'X'

            return clean

        def generate_table(key1):

            # I and J are used interchangeably to allow
            # us to use a 5x5 table (25 letters)
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            # we're using a list instead of a '2d' array because it makes the math 
            # for setting up the table and doing the actual encoding/decoding simpler
            table = []

            # copy key1 chars into the table if they are in `alphabet` ignoring duplicates
            for char in key1.upper():
                if char not in table and char in alphabet:
                    table.append(char)

            # fill the rest of the table in with the remaining alphabet chars
            for char in alphabet:
                if char not in table:
                    table.append(char)

            return table
        def encode(plaintext, key1):
            table = generate_table(key1)
            
            ciphertext = ""


            for char1, char2 in chunker(plaintext, 2):
                row1, col1 = divmod(table.index(char1), 5)
                row2, col2 = divmod(table.index(char2), 5)

                if row1 == row2:
                    ciphertext += table[row1*5+(col1+1)%5]
                    ciphertext += table[row2*5+(col2+1)%5]
                elif col1 == col2:
                    ciphertext += table[((row1+1)%5)*5+col1]
                    ciphertext += table[((row2+1)%5)*5+col2]
                else: # rectangle
                    ciphertext += table[row1*5+col2]
                    ciphertext += table[row2*5+col1]

            return ciphertext
        a=encode(plaintext,key1)
        print(a)
        labelPlay=tk.Label(newWindow2,bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
        labelPlay.config(text=a)
        labelPlay.pack()
        labelPlay.place(x=650,y=200)
    btnplayfairCipher1= tk.Button(newWindow2, text = "Encryption",height =2, width=20, command=encryption,fg='white',bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnplayfairCipher1.pack()
    btnplayfairCipher1.place(x=350,y=200)
    
    
    def decryption():
        ciphertext=f3.get()
        key=f4.get()
        def chunker(seq, size):
            it = iter(seq)
            while True:
                chunk = tuple(itertools.islice(it, size))
                if not chunk:
                    return
                yield chunk



        def prepare_input(dirty):
            """
            Prepare the plaintext by up-casing it
            and separating repeated letters with X's
            """

            dirty = ''.join([c.upper() for c in dirty if c in string.ascii_letters])
            clean = ""

            if len(dirty) < 2:
                return dirty

            for i in range(len(dirty)-1):
                clean += dirty[i]

                if dirty[i] == dirty[i+1]:
                    clean += 'X'

            clean += dirty[-1]

            if len(clean) & 1:
                clean += 'X'

            return clean

        def generate_table(key):

            # I and J are used interchangeably to allow
            # us to use a 5x5 table (25 letters)
            alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
            # we're using a list instead of a '2d' array because it makes the math 
            # for setting up the table and doing the actual encoding/decoding simpler
            table = []

            # copy key chars into the table if they are in `alphabet` ignoring duplicates
            for char in key.upper():
                if char not in table and char in alphabet:
                    table.append(char)

            # fill the rest of the table in with the remaining alphabet chars
            for char in alphabet:
                if char not in table:
                    table.append(char)
            return table
        
        def decode(ciphertext, key):
            table = generate_table(key)
            plaintext = ""


            for char1, char2 in chunker(ciphertext, 2):
                row1, col1 = divmod(table.index(char1), 5)
                row2, col2 = divmod(table.index(char2), 5)

                if row1 == row2:
                    plaintext += table[row1*5+(col1-1)%5]
                    plaintext += table[row2*5+(col2-1)%5]
                elif col1 == col2:
                    plaintext += table[((row1-1)%5)*5+col1]
                    plaintext += table[((row2-1)%5)*5+col2]
                else: # rectangle
                    plaintext += table[row1*5+col2]
                    plaintext += table[row2*5+col1]

            return plaintext
        b=decode(ciphertext,key)
        print(b)
        labelPlay1=tk.Label(newWindow2,bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
        labelPlay1.config(text=b)
        labelPlay1.pack()
        labelPlay1.place(x=650,y=360)

    
    btnplayfairCipher2= tk.Button(newWindow2, text = "Decryption",height =2, width=20, command=decryption,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnplayfairCipher2.pack()
    btnplayfairCipher2.place(x=350,y=360)
    
def createNewWindow3():
    newWindow3 = tk.Toplevel(app)
    newWindow3.geometry("800x800")
    newWindow3.configure(bg='#87CEFA')
    m = StringVar()
    k = StringVar()
    c = StringVar()
    kd = StringVar()

    vernamCipher3= Label(newWindow3, text = "Vernam Cipher", fg = "#000066", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=25,weight="bold"))
    vernamCipherInfo = Label(newWindow3, text= "(Polyalphabetic Substitution Cipher)", fg="#000066", bg="#87CEFA", font=tkfont.Font(family="Helvetica",size=14))

    vernamCipher1 = Label(newWindow3, text="Plain Text", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e1 = Entry(newWindow3,textvariable=m, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    vernamCipher2=Label(newWindow3, text="key", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e2 = Entry(newWindow3,textvariable=k, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    vernamCipher4= Label(newWindow3, text = "Cipher Text",  bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e3=Entry(newWindow3,textvariable=c, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    vernamCipher5= Label(newWindow3, text = "Key",  bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e4=Entry(newWindow3,textvariable=kd, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    
    vernamCipher1.pack()
    vernamCipher2.pack()
    vernamCipher3.pack()
    vernamCipherInfo.pack()
    vernamCipher4.pack()
    vernamCipher5.pack()
    vernamCipher1.place(x=300, y=100)
    vernamCipher2.place(x=300, y=160)
    vernamCipher4.place(x=300, y=360)
    vernamCipher5.place(x=300, y=420)
    
    e1.pack()
    e2.pack()
    e3.pack()
    e4.pack()
    e1.place(x=400, y=100)
    e2.place(x=400, y=160)
    e3.place(x=400, y=360)
    e4.place(x=400, y=420)
    
    label_vernamCipher = Label(newWindow3,bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    label_Plain = Label(newWindow3,bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    cipherEntry = Entry(newWindow3, width = 60,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    cipherEntry.pack()
    cipherEntry.place(x=200, y=270)
   
    btnvernamCipher1 = Button(newWindow3, text = "Encrypt", command = lambda: vernamEncryption(m.get(),k.get(),cipherEntry), height = 2, width = 20,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnvernamCipher1.pack()
    btnvernamCipher1.place(x=350, y=200)
    
    plainEntry = Entry(newWindow3, width = 60,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    plainEntry.pack()
    plainEntry.place(x=200, y=530)

    btnvernamCipher2 = Button(newWindow3, text = "Decrypt", command = lambda: vernamDecryption(c.get(),kd.get(),plainEntry), height = 2, width = 20,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnvernamCipher2.pack()
    btnvernamCipher2.place(x=350, y=460)
    btnclearvencrypt = Button(newWindow3, text = "CLEAR", command = lambda: vernameclear(e1, e2, cipherEntry), height=1, width=6,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnclearvencrypt.pack()
    btnclearvencrypt.place(x=60, y=270)

    btnclearvdecrypt = Button(newWindow3, text = "CLEAR", command = lambda: vernamdclear(e3, e4, plainEntry), height=1, width=6,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnclearvdecrypt.pack()
    btnclearvdecrypt.place(x=60, y=530)

def vernameclear(e1, e2, cipherEntry):
    e1.delete(0, END)
    e2.delete(0, END)
    cipherEntry.delete(0, END)

def vernamdclear(e3, e4, plainEntry):
    e3.delete(0, END)
    e4.delete(0, END)
    plainEntry.delete(0, END)

def vernamEncryption(plaintext,key,cipherEntry):
    # plaintext = m.get()
    # key = k.get()
    ptlist = list()
    keylist = list()
    updatedPlaintext = plaintext.upper()
    updatedKey = key.upper()

    for c in updatedPlaintext:
        temp = ord(c) - 65
        ptlist.append(temp)

    for c in updatedKey:
        temp = ord(c) - 65
        keylist.append(temp)
        
    tempList = [i + j for i, j in zip(ptlist, keylist)]
    ciphertextList = []
    for item in tempList:
        if(item > 25):
            item -= 26
            ciphertextList.append(item)
        else:
            ciphertextList.append(item)
            
    ct = ""
    for number in ciphertextList:
        number += 65
        temp = chr(number)
        tempstr = str(temp)
        ct = ct + tempstr

    cipherEntry.insert(0,ct)

def vernamDecryption(ct, key, plainEntry):
    ct = ct.upper()

    keylist = list()
    updatedKey = key.upper()

    for c in updatedKey:
        temp = ord(c) - 65
        keylist.append(temp)

    ctlist = list()
    for i in ct:
        n = ord(i) - 65
        ctlist.append(n)

    tempctlist = [i - j for i,j in zip(ctlist, keylist)]
    tempctlistnew = list()
    for i in tempctlist:
        if i<0:
            i += 26
        tempctlistnew.append(i)

    pt = ""
    for i in tempctlistnew:
        pt += str(chr(i + 65))

    decrypt = pt.replace(":"," ")

    plainEntry.insert(0,decrypt)


def createNewWindow4():
    newWindow4 = tk.Toplevel(app)
    newWindow4.geometry("800x800")
    newWindow4.configure(bg='#87CEFA')
    reverseCipher1 = tk.Label(newWindow4, text = "Reverse Cipher Text",fg = "#000066", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=25,weight="bold"))
    CipherInfo = Label(newWindow4, text= "(Pattern of Reversing String Cipher)", fg="#000066", bg="#87CEFA", font=tkfont.Font(family="Helvetica",size=14))
    reverseCipher2=tk.Label(newWindow4, text = "Plain Text",bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    g2=tk.Label(newWindow4, text = "Cipher Text",bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    g1=tk.Entry(newWindow4, font=(40))
    
    
    g1.pack()
   
    reverseCipher1.pack()
    reverseCipher2.pack()
    CipherInfo.pack()
    
    g1.place(x=400,y=100)

    
    reverseCipher2.place(x=300,y=100)
    
    def reverse():
        
        message = g1.get()
        translated = '' 
        i = len(message) - 1

        while i >= 0:
            translated = translated + message[i]
            i = i - 1
        print('The cipher text is : ', translated)
    
        
        g2.config(text=translated)
        g2.pack()
        g2.place(x=400,y=300)
    
    
    
    btnreverseCipher1 = tk.Button(newWindow4, text = "Encryption", height = 3, width = 20, command=reverse,fg='white',bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnreverseCipher1.pack()
    btnreverseCipher1.place(x=350, y=150)

    
    
    
def createNewWindow5():
    root= tk.Toplevel(app)
    root.geometry("600x600")
    root.configure(bg='#87CEFA')
    # For changing the icon of the title bar
    #pic = PhotoImage(file = "Image File")
    #root.iconphoto(False,pic)
    # For changing the title of the title bar 
    root.title("Hill Cipher (Polygraphic Substitution Cipher)")
    
    # To set whether we can resize the window or not.The below line doesn't allow the resizing of the window.
    root.resizable(width=FALSE, height=FALSE)
    # Creating a canvas 
    canvas = tk.Canvas(root,height = 800, width=400, bg="#87CEFA")
    
    # Attaching the canvas
    canvas.pack()

    # Set the family,size and style of the font
    bold_font = tkfont.Font(family="Helvetica",size=12,weight="bold")

    # Input label for plain text
    label1 = tk.Label(root,text= "Enter the Text (3 letters)",width=20,bg="#000066",fg='white')
    # adding the font features to the label
    label1.config(font=bold_font)
    # placing the label in the canvas
    canvas.create_window(200,25,window=label1)

    # Input field for plain text
    user_text = tk.Entry(root)
    canvas.create_window(200,50,window=user_text)

    # Input label for key
    labelKey = tk.Label(root,text= "Enter the Key (9 letters)",width=20,bg="#000066",fg='white')
    # adding the font features to the label
    labelKey.config(font=bold_font)
    # placing the label in the canvas
    canvas.create_window(200,100,window=labelKey)

    # Input field for lay
    user_key = tk.Entry(root)
    canvas.create_window(200,125,window=user_key)

    # Creating a label with a text and attaching it to the root
    label2=tk.Label(root,text="Choose an Operation",width=25,bg="#000066",fg='white')
    # adding the font features to the label
    label2.config(font=bold_font)
    # placing the label in the canvas
    canvas.create_window(200,200,window=label2)

    # Tkinter Variable 
    v = tk.IntVar()

    keyMatrix = [[0] * 3 for i in range(3)]

    # Generate vector for the message
    messageVector = [[0] for i in range(3)]

    # Generate vector for the cipher
    cipherMatrix = [[0] for i in range(3)]

    # Following function generates the
    # key matrix for the key string
    def getKeyMatrix(key):
        k = 0
        for i in range(3):
            for j in range(3):
                keyMatrix[i][j] = ord(key[k]) % 65
                k += 1

    # Following function encrypts the message
    def encrypt(messageVector):
        for i in range(3):
            for j in range(1):
                cipherMatrix[i][j] = 0
                for x in range(3):
                    cipherMatrix[i][j] += (keyMatrix[i][x] * messageVector[x][j])
                cipherMatrix[i][j] = cipherMatrix[i][j] % 26

    # Defined a function choice
    def choice():
      # Retrieve the value of the radio button
        x = v.get()
      # Performs Encryption if the value is 1 else performs Decryption.
        if(x==1):
            encryption()
        elif(x==2):
            decryption()

    # Defined a function Encryption
    def encryption():
      # Storing input text
        message = user_text.get()
      # To store the result   
        cipher_text = ""
      # Storing input key
        key = user_key.get()

        # Get key matrix from the key string
        getKeyMatrix(key)

        # Generate vector for the message
        for i in range(3):
            messageVector[i][0] = ord(message[i]) % 65

        # Following function generates
        # the encrypted vector
        encrypt(messageVector)

        # Generate the encrypted text 
        # from the encrypted vector
        CipherText = []
        for i in range(3):
            CipherText.append(chr(cipherMatrix[i][0] + 65))

        # Finally print the ciphertext
        cipher_text ="".join(CipherText)

      #############################################

      # Creating a label with a text and attaching it to the root       
        label3 =tk.Label(root,text=cipher_text,width=20,bg="light yellow")
        displayKeyMatrix =tk.Label(root,text=keyMatrix,width=30,bg="light yellow")
      # adding the font features to the label
        label3.config(font=bold_font)
        displayKeyMatrix.config(font=bold_font)
      # placing the label in the canvas
        canvas.create_window(200,325,window=label3)
        canvas.create_window(200,400,window=displayKeyMatrix)
    
    # Defined a function Decryption
    def decryption():
      # Storing input text
        cipherMessage = user_text.get()
      # To store the result   
        decrypt_text = ""
      # Storing input key
        key = user_key.get()

        # declaring matrix for key
        keyMatrix = [[0] * 3 for i in range(3)]

        # Generate vector for the message
        cipherMessageVector = [[0] for i in range(3)]

        # Generate vector for the cipher and decrypt
        decryptMatrix = [[0] for i in range(3)]

        # Following function generates the
        # key matrix for the key string
        def getKeyMatrix(key):
            k = 0
            for i in range(3):
                for j in range(3):
                    keyMatrix[i][j] = ord(key[k]) % 65
                    k += 1

        # Get key matrix from the key string
        getKeyMatrix(key)

        # Generate vector for the message
        for i in range(3):
            cipherMessageVector[i][0] = ord(cipherMessage[i]) % 65
        
        # converting the key matrix to np.array
        keyNP = np.array(keyMatrix)

        # inverse matrix of key matrix
        keyInverse = Matrix(keyNP).inv_mod(26)

        # multiplication: (inverse matrix of key) x (vector of cipher text)
        decryptMatrix = np.matmul(keyInverse, cipherMessageVector) % 26

        # generating decrypted text
        DecryptText = []
        for i in range(3):
            DecryptText.append(chr(decryptMatrix[i][0] + 65))

        # Finally print the decrypted text
        decrypt_text ="".join(DecryptText)
     
      # Creating a label with a text and attaching it to the root
        label4 =tk.Label(root,text=decrypt_text,width=20,bg="light yellow")
        DisplaykeyInverse =tk.Label(root,text=keyInverse,width=30,bg="light yellow")
      # Adding the font features to the label
        label4.config(font=bold_font)
        DisplaykeyInverse.config(font=bold_font)
      # Placing the label in the canvas
        canvas.create_window(200,325,window=label4)
        canvas.create_window(200,400,window=DisplaykeyInverse)
    
    # Radio Button for Encryption 
    label5=tk.Radiobutton(root, text="Encryption",padx = 20, variable=v, value=1,command=choice,bg="light yellow")
    label5.config(font=bold_font)
    canvas.create_window(100,230,window=label5)
    # Radio Button for Decryption
    label6=tk.Radiobutton(root, text="Decryption",padx = 20, variable=v, value=2,command=choice,bg="light yellow")
    label6.config(font=bold_font)
    canvas.create_window(300,230,window=label6)

    # Creating a label with a text and attaching it to the root
    label7 =tk.Label(root,text="Converted Text is ",width=20,bg="#000066",fg='white')
    labelKeyMatrix =tk.Label(root,text="Key Matrix is ",width=20,bg="#000066",fg='white')
    # adding the font features to the label
    label7.config(font=bold_font)
    labelKeyMatrix.config(font=bold_font)
    # placing the label in the canvas
    canvas.create_window(200,300,window=label7)
    canvas.create_window(200,375,window=labelKeyMatrix)
    

def createNewWindow6():
    newWindow6 = Toplevel(app)
    newWindow6.geometry("800x800")
    newWindow6.configure(bg='#87CEFA')
    m = StringVar()
    k = StringVar()
    c = StringVar()
    kd = StringVar()

    Rail_FenceCipher3= Label(newWindow6, text = "Rail_Fence Cipher", fg = "#000066", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=25,weight="bold"))
    CipherInfo = Label(newWindow6, text= "(Classical Transposition Cipher)", fg="#000066", bg="#87CEFA", font=tkfont.Font(family="Helvetica",size=14))
    Rail_FenceCipher1 = Label(newWindow6, text="Plain Text",bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e1 = Entry(newWindow6,textvariable=m, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    Rail_FenceCipher2=Label(newWindow6, text="key", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e2 = Entry(newWindow6,textvariable=k, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    Rail_FenceCipher4= Label(newWindow6, text = "Cipher Text", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e3=Entry(newWindow6,textvariable=c, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    Rail_FenceCipher5= Label(newWindow6, text = "Key", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    e4=Entry(newWindow6,textvariable=kd, width = 40,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    
    
    
    Rail_FenceCipher1.pack()
    Rail_FenceCipher2.pack()
    Rail_FenceCipher3.pack()
    Rail_FenceCipher4.pack()
    Rail_FenceCipher5.pack()
    CipherInfo.pack()
    Rail_FenceCipher1.place(x=300, y=100)
    Rail_FenceCipher2.place(x=300, y=160)
    Rail_FenceCipher4.place(x=300, y=360)
    Rail_FenceCipher5.place(x=300, y=420)
    
    e1.pack()
    e2.pack()
    e3.pack()
    e4.pack()
    e1.place(x=400, y=100)
    e2.place(x=400, y=160)
    e3.place(x=400, y=360)
    e4.place(x=400, y=420)
    
    label_Rail_FenceCipher = Label(newWindow6,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    label_Plain = Label(newWindow6,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

    cipherEntry = Entry(newWindow6, width = 50,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    cipherEntry.pack()
    cipherEntry.place(x=200, y=270)
   
    btnRail_FenceCipher1 = Button(newWindow6, text = "Encrypt", command = lambda: Rail_FenceEncryption(m.get(),k.get(),cipherEntry), height = 2, width = 20,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnRail_FenceCipher1.pack()
    btnRail_FenceCipher1.place(x=350, y=200)
    
    plainEntry = Entry(newWindow6, width = 50,font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    plainEntry.pack()
    plainEntry.place(x=200, y=530)

    btnRail_FenceCipher2 = Button(newWindow6, text = "Decrypt", command = lambda: Rail_FenceDecryption(c.get(),kd.get(),plainEntry), height = 2, width = 20,fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
    btnRail_FenceCipher2.pack()
    btnRail_FenceCipher2.place(x=350, y=460)

def Rail_FenceEncryption(plaintext,key,cipherEntry):
    # plaintext = m.get()
    # key = k.get()
    plaintext
    key
    key = int(key)
    ciphertext = ""

    cycle = key * 2 - 2
    int(cycle)

    for row in range(key):
        index = 0


        #for the first row
        if row == 0:
              while index < len(plaintext):
                    ciphertext += plaintext[index]
                    index +=cycle

        #for last row
        elif row == key -1:
            index = row
            while index < len(plaintext):
                    ciphertext += plaintext[index]
                    index +=cycle

        #for the rows in middle
        else:
            left_index = row
            right_index = cycle - row
            while left_index < len(plaintext):
                ciphertext += plaintext[left_index]

                if right_index < len(plaintext):
                    ciphertext += plaintext[right_index]

                left_index += cycle
                right_index += cycle
    print(ciphertext)




    cipherEntry.insert(0,ciphertext)

def Rail_FenceDecryption(ciphertext, key, plainEntry):
    ciphertext = ciphertext.upper()
    key
    key = int(key)
    
    length = len(ciphertext)

    plaintext = "." * length
    print(plaintext)
    cycle = 2 * key - 2
    units = length // cycle

    rail_lengths = [0]* key

    # Top Rail Length
    rail_lengths[0] = units

    # Intermediate Rail length
    for i in range(1,key -1):
         rail_lengths[i] = 2* units

    #Bottom rail Length
    rail_lengths[key-1] = units


    for i in range(length % cycle):
         if( i < key):
              rail_lengths[i] += 1
         else:
              rail_lengths[cycle-i] += 1

    print(rail_lengths)

    print(plaintext)

    #replace char. in the top rail fence

    index = 0
    rail_offset = 0
    for c in ciphertext[:rail_lengths[0]]:
         plaintext = plaintext[:index] + c + plaintext[index+1:]
         index += cycle

    rail_offset += rail_lengths[0]
    print(plaintext)
    print(rail_lengths)

    #Replace characters in the intermediate rails

    for row in range(1, key-1):
         left_index = row
         right_index = cycle - row
         left_char = True
         for c in ciphertext[rail_offset:rail_offset + rail_lengths[row]]:
              if left_char:
                   plaintext = plaintext[:left_index] + c + plaintext[left_index+1:]
                   left_index += cycle
                   left_char = not left_char
              else:
                   plaintext = plaintext[:right_index] + c + plaintext[right_index + 1:]
                   right_index += cycle
                   left_char = not left_char
         rail_offset += rail_lengths[row]
         print(plaintext)
    #Replace charcheter int the bottom rail fence

    index = key - 1

    for c in ciphertext[rail_offset:]:
         plaintext = plaintext[:index] + c + plaintext[index+1:]
         index += cycle

    print(plaintext)
    print(rail_lengths)
 
    plainEntry.insert(0,plaintext)
    
app = tk.Tk()
app.geometry("820x820")
app.configure(bg='#87CEFA')
labelExample2 = tk.Label(app, text = "Cipher Text Conversion Algorithms",fg = "#000066", bg = '#87CEFA',font=tkfont.Font(family="Helvetica",size=25,weight="bold"))
buttonExample2 = tk.Button(app, 
              text="Ceaser Cipher",
              command=createNewWindow1, height = 3, width = 20, fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
buttonExample3 = tk.Button(app, 
              text="Playfair Cipher",
              command=createNewWindow2, height = 3, width = 20, fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
buttonExample4 = tk.Button(app, 
              text="Vernam Cipher",
              command=createNewWindow3, height = 3, width = 20, fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
buttonExample5 = tk.Button(app, 
              text="Reverse Cipher",
              command=createNewWindow4, height = 3, width = 20, fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
buttonExample6 = tk.Button(app, 
              text="Hill Cipher",
              command=createNewWindow5, height = 3, width = 20, fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))
buttonExample7 = tk.Button(app, 
              text="Rail Fence Cipher",
              command=createNewWindow6, height = 3, width = 20, fg='white', bg = '#000066',font=tkfont.Font(family="Helvetica",size=12,weight="bold"))

labelExample2.pack()
buttonExample2.pack()
buttonExample2.place(x=20, y=200)
buttonExample3.pack()
buttonExample3.place(x=300, y=200)
buttonExample4.pack()
buttonExample4.place(x=580, y=200)
buttonExample5.pack()
buttonExample5.place(x=20, y=400)
buttonExample6.pack()
buttonExample6.place(x=300, y=400)
buttonExample7.pack()
buttonExample7.place(x=580, y=400)


app.mainloop()

