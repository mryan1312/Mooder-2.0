import tkinter
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import base64
import os
import csv
import datetime
from tkinter.tix import PopupMenu
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC



def password_to_key(password):                                      # Takes password to generate key
    salt = os.urandom(16)
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt(key, data):
    f = Fernet(key)
    token = f.encrypt(data.encode('utf-8'))
    return token

def decrypt(key, data):
    f = Fernet(key)
    token = f.decrypt(data)
    decode = token.decode('utf-8')
    return decode

def get_password():
    def exit_btn_password():
        global key 
        key = password_to_key(password.get())
        t_password.destroy()
        t_password.update()
        if key != "":
            messagebox.showinfo("Success", "Key was successfully generated.")
        else:
            messagebox.showinfo("Error", "Key generation failed.")
    t_password = Toplevel(master)
    password = tkinter.StringVar(t_password)
    lay.append(t_password)
    Label(t_password, text = "All data is encrypted for privacy. Enter your password:").grid(row = 0)
    pass_enter = Entry(t_password, textvariable = password).grid(row = 1)
    ttk.Button(t_password, text = "OK", command = exit_btn_password).grid(row = 2)
    


def popup_reader():
    t_read = Toplevel(master)
    txt_box = Text(t_read)
    txt_box.grid(row = 0, column = 0)
    decoded = []
    if os.path.isfile("moodhistory.csv") == True:
        with open("moodhistory.csv", newline = '') as file:
            reader = csv.reader(file)
            for row in reader:
                for each in row:
                    decoded.append(decrypt(each))
                txt_box.insert(INSERT, decoded)
                decoded = []
    else:
        txt_box.insert(INSERT, "Data not available yet.")

def clear_data():
    def exit_btn():
        tclear.destroy()
        tclear.update()
    def confirm_btn():
        os.remove("moodhistory.csv")
        exit_btn()
    if os.path.isfile("moodhistory.csv") == True:
        tclear = Toplevel(master)
        tclear.title("Confirmation")
        Label(tclear, text = "Are you sure you want to delete all data?").grid(row = 0, column = 1)
        ttk.button(tclear, text = "Confirm").grid(row = 1, column = 0)
        ttk.button(tclear, text = "Cancel", command =exit_btn).grid(row = 1, column = 2)
    else:
        messagebox.showinfo("Error", "Data file is missing or already deleted.")

def save_data():
    global key
    rating = sb.get()
    notes = notes_ent.get()
    tstamp = datetime.datetime.now()
    enc_rating = encrypt(key, rating.encode('utf-8'))
    enc_notes = encrypt(key, notes.encode('utf-8'))
    enc_timestamp = encrypt(key, tstamp.encode('utf-8'))
    entry = [enc_rating, enc_notes, enc_timestamp]
    if os.path.isfile("moodhistory.csv") == False:
        with open("moodhistory.csv", newline = '') as file:
            writer = csv.writer(file)
            file.writeline("Date", "Rating", "Notes")
    else:
        with open("moodhistory.csv", newline = '') as file:
            writer = csv.writer(file)
            file.writeline(entry)
            messagebox.showinfo("Success", "Entry Saved")

password = ""
key = ""
lay=[]
master = tkinter.Tk(className='Mooder')
Label(master, text ='Mood Rating').grid(row = 0, column = 0)
Label(master, text ='Any notes for this entry?').grid(row=1, column = 0)
sb = Spinbox(master, from_ = 1, to = 5)
sb.grid(row = 0, column = 1)
notes_ent = Entry(master)
notes_ent.grid(row = 1, column = 1)
save_button = Button(master, text = "Save")
save_button.grid(row = 2, column = 1)
Label(master, text ='Data Managment:').grid(row=0, column = 2)
ttk.Button(master, text = "View Data", command = popup_reader).grid(row = 0, column = 3)
ttk.Button(master, text = "Chart Data").grid(row = 1, column = 3)
ttk.Button(master, text = "Clear Data", command = clear_data).grid(row = 2, column = 3)
get_password()
while key != "":
    Label(master, text ='Data file unlocked!').grid(row = 3, column = 0)
master.mainloop()


#working = True
#password = input("whats the password?\n")
#while working == True: 
#    choice = input("Do you want to 1. Encrypt or 2. Decrypt or 3. Exit\n")
#    if choice == "1":
#        message = input("Whats the message?\n")
#        key = password_to_key(password)
#        enc_message = encrypt(key, message)
#        print (enc_message)
#    elif choice == "2":
#        dec_message = decrypt(key, enc_message)
#        print(dec_message)
#    elif choice == "3":
#        working = False
#    else:
#        print("Not a valid choice.\n")
