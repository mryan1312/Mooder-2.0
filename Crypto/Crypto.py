import tkinter
import bytes
from tkinter import *
from tkinter import ttk
from tkinter import messagebox
import base64
import os
import csv
import datetime
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pandas as pd
import plotly.express as px

def password_to_key(password):                                      # Takes password to generate key
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=b'',
        iterations=390000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password.encode('utf-8')))
    return key

def encrypt(key, data):
    f = Fernet(key)
    token = f.encrypt(data)
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
    t_password.attributes('-topmost', 'true')
    password = tkinter.StringVar(t_password)
    Label(t_password, text = "All data is encrypted for privacy. Enter your password:").grid(row = 0)
    pass_enter = Entry(t_password, textvariable = password).grid(row = 1)
    ttk.Button(t_password, text = "OK", command = exit_btn_password).grid(row = 2)
    
def popup_reader():
    global key
    t_read = Toplevel(master)
    txt_box = Text(t_read)
    txt_box.grid(row = 0, column = 0)
    if os.path.isfile(".\moodhistory.csv") == True:
        with open(".\moodhistory.csv", 'r', newline = '') as file:
            reader = csv.reader(file)
            row1 = next(reader, None)
            header1 = row1[0]
            header2 = row1[1]
            header3 = row1[2]
            txt_box.insert(INSERT, header1 + "                        " + header2 + "   " + header3+"\n")
            for line in reader:
                tstamp_enc = line[0][2:-1]
                rate_enc = line[1][2:-1]
                note_enc = line[2][2:-1]
                try:
                    tstamp = decrypt(key, tstamp_enc.encode('utf-8'))
                    rate = decrypt(key, rate_enc.encode('utf-8'))
                    note = decrypt(key, note_enc.encode('utf-8'))
                    txt_box.insert(INSERT, tstamp + "     " + rate + "     " + note + "\n")
                except:
                    messagebox.showinfo("Error", "Key mismatch.")
    else:
        txt_box.insert(INSERT, "Data not available yet.")

def clear_data():
    def exit_btn():
        tclear.destroy()
        tclear.update()
    def confirm_btn():
        os.remove(".\moodhistory.csv")
        exit_btn()
    if os.path.isfile(".\moodhistory.csv") == True:
        tclear = Toplevel(master)
        tclear.title("Confirmation")
        Label(tclear, text = "Are you sure you want to delete all data?").grid(row = 0, column = 1)
        ttk.Button(tclear, text = "Confirm", command=confirm_btn).grid(row = 1, column = 0)
        ttk.Button(tclear, text = "Cancel", command =exit_btn).grid(row = 1, column = 2)
    else:
        messagebox.showinfo("Error", "Data file is missing or already deleted.")

def save_data():
    global key
    rating = sb.get()
    notes = notes_ent.get()
    tstamp = str(datetime.datetime.now())
    enc_rating = encrypt(key, rating.encode('utf-8'))
    enc_notes = encrypt(key, notes.encode('utf-8'))
    enc_timestamp = encrypt(key, tstamp.encode('utf-8'))
    entry = [enc_timestamp, enc_rating, enc_notes]
    if os.path.isfile(".\moodhistory.csv") == False:
        with open(".\moodhistory.csv",'w', newline = '') as file:
            writer = csv.writer(file)
            writer.writerow(["Date", "Rating", "Notes"])
    with open(".\moodhistory.csv",'a', newline = '') as file:
            writer = csv.writer(file)
            writer.writerow(entry)
            messagebox.showinfo("Success", "Entry Saved")

def plot_data():
    tstamps = []
    rates = []
    notes = []
    if os.path.isfile(".\moodhistory.csv") == True:
        with open(".\moodhistory.csv", 'r', newline = '') as file:
            reader = csv.reader(file)
            row1 = next(reader, None)
            for line in reader:
                tstamp_enc = line[0][2:-1]
                rate_enc = line[1][2:-1]
                note_enc = line[2][2:-1]
                try:
                    tstamp = decrypt(key, tstamp_enc.encode('utf-8'))
                    tstamps.append(tstamp)
                    rate = decrypt(key, rate_enc.encode('utf-8'))
                    rates.append(rate)
                    note = decrypt(key, note_enc.encode('utf-8'))
                    notes.append(note)
                except:
                    messagebox.showinfo("Error", "Key mismatch.")
    else:
        txt_box.insert(INSERT, "Data not available yet.")
    fig = px.line(x = tstamps, y = rates, text = notes, title ="Mood Change over Time")
    fig.update_layout(xaxis_title="Date-Time", yaxis_title="Mood Rating")
    fig.show()

password = ""
key = ""
master = tkinter.Tk(className='Mooder')
Label(master, text ='Mood Rating').grid(row = 0, column = 0)
Label(master, text ='Any notes for this entry?').grid(row=1, column = 0)
sb = Spinbox(master, from_ = 1, to = 5)
sb.grid(row = 0, column = 1)
notes_ent = Entry(master)
notes_ent.grid(row = 1, column = 1)
save_button = Button(master, text = "Save", command = save_data)
save_button.grid(row = 2, column = 1)
Label(master, text ='Data Managment:').grid(row=0, column = 2)
ttk.Button(master, text = "View Data", command = popup_reader).grid(row = 0, column = 3)
ttk.Button(master, text = "Chart Data", command = plot_data).grid(row = 1, column = 3)
ttk.Button(master, text = "Clear Data", command = clear_data).grid(row = 2, column = 3)
get_password()
master.mainloop()

