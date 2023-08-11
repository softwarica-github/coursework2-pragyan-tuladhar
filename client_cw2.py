import tkinter as tk
from tkinter import *
from tkinter import messagebox
from PIL import Image, ImageTk
import socket
import threading
import rsa
import hashlib
import sqlite3

#. Connecting to IP and Port
HOST = "localhost"
PORT = 8888

client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client_socket.connect((HOST, PORT))
PUBLIC_KEY_SIZE = 2048
public_key, private_key = rsa.newkeys(PUBLIC_KEY_SIZE)    #Generating Public key and Private Key of client
public_partner = rsa.PublicKey.load_pkcs1(client_socket.recv(1024))  #Receiving the public key of server
client_socket.send(public_key.save_pkcs1("PEM"))      #Sending the public key
help_counter = 0

def create_user(fullname, username, password):  #. Creating a function for creating a user
    # Error handling for userinput fullname and password
    if len(fullname) < 6:
        messagebox.showwarning("Requirement", "Full name must be at least 6 characters.")
        return
    elif len(password) <=9:
        messagebox.showwarning("Requirement", "Password must be at least 9 characters.")
        return
    elif fullname =="Fullname" or username=="Username" or password =="Password":
        messagebox.showerror("Invalid", "Fullname, Username, and Password cannot be empty.")
        return
    
    hashpass = hashlib.sha256(password.encode()).hexdigest()

    conn = sqlite3.connect('userdata.db')       #Connecting to database
    cursor = conn.cursor()              #. Making a Cursor for inputing sql quries

    # Check if the username is already taken
    cursor.execute("SELECT * FROM userdata WHERE username= ?", (username,)) 
    existing_user = cursor.fetchone()
    if existing_user:
        messagebox.showerror("Invalid", "Username already exists")
        conn.close()
        return

    else:
        cursor.execute("INSERT INTO userdata (fullname, username, password) VALUES (?, ?, ?)",(fullname, username, hashpass))
    conn.commit()
    conn.close()
    messagebox.showinfo("Success", "Account created successfully")


def signup():
    
    def clear_placeholder_full(event):
        if fullname_entry.get() == "FullName":
            fullname_entry.delete(0, tk.END)

    def restore_placeholder_full(event):
        if fullname_entry.get() == "":
            fullname_entry.insert(0, "FullName")

    def clear_placeholder_user(event):
        if username_entry1.get() == "Username":
            username_entry1.delete(0, tk.END)

    def restore_placeholder_user(event):
        if username_entry1.get() == "":
            username_entry1.insert(0, "Username")

    def clear_password_placeholder_pass(event):
        if password_entry1.get() == "Password":
            password_entry1.delete(0, tk.END)
            password_entry1.config(show="*")

    def restore_password_placeholder_pass(event):
        if password_entry1.get() == "":
            password_entry1.config(show="")
            password_entry1.insert(0, "Password")

    def create_user_callback():
        full_username = fullname_entry.get()
        username = username_entry1.get()
        new_password = password_entry1.get()
        create_user(full_username, username, new_password)

    windows = tk.Toplevel(root)
    windows.title("Sign Up")
    windows.geometry("925x500+300+200")
    windows.configure(bg="#fff")
    windows.resizable(False, False)
    pop = Image.open('community.webp')
    pop = ImageTk.PhotoImage(pop)

    label3 = tk.Label(windows, image=pop, bg="white")
    label3.place(x=50, y=50)

    hero = tk.Frame(windows, width=350, height=350, bg="#fff")
    hero.place(x=480, y=50)
    heading = tk.Label(hero, text='Sign Up', fg="#57a1f8", bg='white', font=("Microsoft YaHei UI Light", 23, 'bold')) #Defining Heading
    heading.place(x=100, y=5)

    # Entry fields for username and password during sign up
    fullname_entry = tk.Entry(hero, width=25, fg='black', border=0, bg='white', font=("Microsoft YaHei UI Light", 11))
    fullname_entry.insert(0, "FullName")
    fullname_entry.bind("<FocusIn>", clear_placeholder_full)
    fullname_entry.bind("<FocusOut>", restore_placeholder_full)
    fullname_entry.place(x=30, y=80)
    tk.Frame(hero, width=295, height=2, bg='black').place(x=25, y=107)

    username_entry1 = tk.Entry(hero, width=25, fg='black', border=0, bg='white', font=("Microsoft YaHei UI Light", 11))
    username_entry1.insert(0, "Username")
    username_entry1.bind("<FocusIn>", clear_placeholder_user)
    username_entry1.bind("<FocusOut>", restore_placeholder_user)
    username_entry1.place(x=30, y=150)
    tk.Frame(hero, width=295, height=2, bg='black').place(x=25, y=177)
    
    #Showing this '*' symbol in password entry 
    password_entry1 = tk.Entry(hero, width=25, fg='black', border=0, bg='white', font=("Microsoft YaHei UI Light", 11),show="*") 
    password_entry1.insert(0, "Password")
    password_entry1.bind("<FocusIn>", clear_password_placeholder_pass)
    password_entry1.bind("<FocusOut>", restore_password_placeholder_pass)
    password_entry1.place(x=30, y=209)
    tk.Frame(hero, width=295, height=2, bg='black').place(x=25, y=237)

    signup_button = tk.Button(hero, text="Sign Up", bg="#57a1f8", fg="white",font=('Microsoft YaHei UI Light', 11, 'bold'), command=create_user_callback)
    signup_button.place(x=25, y=250, width=80)


def clear_placeholder(event):
    if username_entry.get() == "Username":
        username_entry.delete(0, tk.END)


def restore_placeholder(event):
    if username_entry.get() == "":
        username_entry.insert(0, "Username")


def clear_password_placeholder(event):
    if password_entry.get() == "Password":
        password_entry.delete(0, tk.END)
        password_entry.config(show="*")


def restore_password_placeholder(event):
    if password_entry.get() == "":
        password_entry.config(show="")
        password_entry.insert(0, "Password")

message_gg = None


def receive_messages(client_socket, private_key, text_area_widget):
    try:
        while True:
            encrypted_message = client_socket.recv(1024)
            combine_msg_hash = rsa.decrypt(encrypted_message, private_key).decode("utf-8")
            a = combine_msg_hash.split('|')                         #

            if len(a) == 3:
                
                
                print(a[2])
                calculate_hash = hashlib.sha256(a[1].encode('utf-8')).hexdigest()
                print(calculate_hash)
                if calculate_hash == a[2]:
                    
                    text_area_widget.config(state="normal")
                    b = "*******************"
                    text_area_widget.insert("end", b + "\n")      
                    text_area_widget.insert("end",f"From {a[0]}: message: {a[1]}" + "\n")
                    text_area_widget.config(state="disabled")       #. Text area cannot be modified 
                    text_area_widget.tag_configure("bold", font=("Helvetica", 12, "bold"))
                    text_area_widget.tag_add("bold", "1.0", "end")
            else:
                print("Invalid message format")
    except Exception as e:
            print("Error:", e)
    finally:
        client_socket.close()




def login():
  
    while True:
        entry = username_entry.get()
        entry1 = password_entry.get()

        if entry == "Username" or entry1 == "Password":
            messagebox.showerror("Invalid", "Fill the username or password")
            break
        elif entry1 == "" and entry == "":
            messagebox.showerror("Invalid", "Dumbass fill up the username or password")
            break
        else:
            client_socket.send(rsa.encrypt(entry.encode('utf-8'), public_partner))
            client_socket.send(rsa.encrypt(entry1.encode('utf-8'), public_partner))

            result = rsa.decrypt(client_socket.recv(1024), private_key).decode('utf-8') 
        
            if result == "LOGIN":
                def send_message():
                    message_gg = message_entry.get()

                    if message_entry.get() == "":               #. If entry is blank
                        messagebox.showwarning("EMPTY", "Fill up the message box and send")

                    else:
                        try:
                            
                            if message_gg.lower() == "quit":
                                client_socket.send(rsa.encrypt(message_gg.encode('utf-8'), public_partner))
                                exit()
                        
                            else:
                                hash_message = hashlib.sha256(message_gg.encode('utf-8')).hexdigest()
                                combine_messg_hash = f"{message_gg}|{hash_message}"
                                client_socket.send(rsa.encrypt(f"{combine_messg_hash}".encode('utf-8'), public_partner))
                            message_entry.delete(0, tk.END)
                        except Exception as e:  
                            print(f"Error sending message: {str(e)}")
                    
                def help():
                    global help_counter
                    
                    if help_counter < 1:
                        help_window = tk.Toplevel()
                        help_window.title("Help")
                        help_window.geometry("500x300")
                        
                        help_label = tk.Label(help_window, text="Private message can be doneby specifying {username@your_message}", font=('Helvetica 10 underline'))
                        help_label.place(x=30, y=40)
                        help_counter += 1
                    else:
                        messagebox.showerror("Error", "Help window is already open")

                    


                root.destroy()      # Destroying the main windows if all credential are correct
                Window = tk.Tk()        # Creating a new main windows
                
                Window.geometry("900x555+200+200")
                Window.title("Open Community Chat")
                Window.resizable(0,0)                   #. Windows screen cannot be resizable
                left_frame = tk.Frame(Window, width=160, height=560, bg="DarkOliveGreen")
                left_frame.place(x=0, y=0)
                label_left = tk.Label(left_frame, text=entry,font= ('Helvetica 22 underline'), background="DarkOliveGreen")
                label_left.place(x=7,y=250)
                button = tk.Button(left_frame, text="Help", background="white",command=help) #Creating a button link with help function
                button.place(x=35,y=520)

                right_frame = tk.Frame(Window, width=900, height=100000, bg="lightgreen")   #Creating a Frame 
                right_frame.place(x=160, y=0)

                text_area = tk.Text(right_frame,width=800, height=200)
                text_area.config(state= "disabled",background="LightCyan2")
                text_area.place(x=0,y=95)

                top_frame = tk.Frame(right_frame, width=900, height=90, background="white")
                top_frame.place(x=0,y=0)

                top_label = tk.Label(top_frame, text="Open Community Chat", font=('Helvetica bold', 30), background="white")
                top_label.place(x=175,y=20)
                
                bottom_frame = tk.Frame(right_frame, width=9000, height=90,background="grey") 
                bottom_frame.place(x=0,y=465)
                label_left1 = tk.Label(bottom_frame, text="Note:For Guidance go to Help options",font= ('Helvetica 7 bold'), background="grey")
                label_left1.place(x=20,y=60)
                q = StringVar()
                
                message_entry = tk.Entry(bottom_frame,textvariable=q , width=100, background="white",foreground="black")
                message_entry.place(x=5,y=20)
                
                button = tk.Button(bottom_frame, text="SEND", background="white",command=send_message) #Creating a button links with send_messages function
                button.place(x=635,y=16)
                # Creating and starting threads for receving message
                receive_thread = threading.Thread(target=receive_messages, args=(client_socket,private_key,text_area)) 
                
                receive_thread.start()
                Window.mainloop()       

                
               
            elif result == "FAILED":
                messagebox.showerror("Invalid", "Invalid username or password")
                break
    



if __name__ == '__main__':
    root = tk.Tk()
    root.title('Login')
    root.geometry('925x500+300+200')
    root.configure(bg="#fff")
    root.resizable(False, False)

    img = Image.open('community.webp')
    img = ImageTk.PhotoImage(img)

    label = tk.Label(root, image=img, bg="white")
    label.place(x=50, y=50)

    frame = tk.Frame(root, width=350, height=350, bg="white")
    frame.place(x=480, y=70)

    heading = tk.Label(frame, text='Sign in', fg="#57a1f8", bg="white", font=('Microsoft YaHei UI Light', 23, 'bold'))
    heading.place(x=100, y=5)
    
    username_entry = tk.Entry(frame, width=25, fg='black', border=0, bg='white', font=("Microsoft YaHei UI Light", 11))
    username_entry.insert(0, 'Username')
    username_entry.bind("<FocusIn>", clear_placeholder)
    username_entry.bind("<FocusOut>", restore_placeholder)
    username_entry.place(x=30, y=80)

    tk.Frame(frame, width=295, height=2, bg='black').place(x=25, y=107)

    password_entry = tk.Entry(frame, width=25, fg='black', border=0, bg='white', font=("Microsoft YaHei UI Light", 11),show="*")
    password_entry.insert(0, "Password")
    password_entry.bind("<FocusIn>", clear_password_placeholder)
    password_entry.bind("<FocusOut>", restore_password_placeholder)
    password_entry.place(x=30, y=150)

    tk.Frame(frame, width=295, height=2, bg='black').place(x=25, y=177)
    
    login_button = tk.Button(frame, text="Login", bg="#57a1f8", fg="white",font=('Microsoft YaHei UI Light', 11, 'bold'), command=login)
    login_button.place(x=30, y=200, width=80)

    label = tk.Label(frame, text="Don't have an account?", fg='black', bg='white', font=('Microsoft YaHei UI Light', 9))
    label.place(x=30, y=250)

    sign_up = tk.Button(frame, width=6, text='Sign Up', border=0, bg='white', cursor='hand2', fg='#57a1f8', command=signup)
    sign_up.place(x=160, y=250, width=60)

    root.mainloop()

   
