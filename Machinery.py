import tkinter as tk
from customtkinter import *
import firebase_admin
from firebase_admin import credentials, auth, db
from PIL import Image, ImageTk
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import random
import re
import secrets
import sys
import base64
import time

def generate_cryptographically_secure_random_bytes(length):
    return secrets.token_bytes(length)

def generate_cryptographically_secure_random_integer(start, end):
    return secrets.randbelow(end - start) + start
    
def pad(data):
    block_size = 16
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length]) * padding_length

def unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]

def aes_encrypt(key, data):
    cipher = AES.new(key, AES.MODE_ECB) 
    encrypted_data = cipher.encrypt(pad(data))
    return encrypted_data

def aes_decrypt(key, encrypted_data):
    cipher = AES.new(key, AES.MODE_ECB)
    decrypted_data = unpad(cipher.decrypt(encrypted_data))
    return decrypted_data

def encrypt_number(key, number):
    encrypted_data = aes_encrypt(key, number)
    return encrypted_data

def decrypt_number(key, encrypted_data):
    decrypted_data = aes_decrypt(key, encrypted_data)
    number = int.from_bytes(decrypted_data, 'big')
    return number

key = generate_cryptographically_secure_random_bytes(16)
private_key = generate_cryptographically_secure_random_integer(10, 900000)

def find_representation(x, num):
    
def parse_string(s):
    
def replace_x(representations, replacement_bytes):
    
def adds(lst, n):
    
# Initialize Firebase Admin SDK with service account credentials
cred = credentials.Certificate(#"--JSON FILE--")
firebase_admin.initialize_app(cred, {
    'databaseURL': #Database URL
})

# Reference to the Firebase Realtime Database
ref = db.reference()

# Global variable to store the logged-in user UID
logged_in_uid = None

parties = {
    "BJP": "/home/lucifer/Downloads/bjp.ppm",
    "Congress": "/home/lucifer/Downloads/Congress.ppm",
    "AAP": "/home/lucifer/Downloads/Aap.ppm",
}

party_images = {}
# Function to sign up a new user

def sign_up():
    username = username_entry.get()
    password = password_entry.get()
    
    try:
        # Check if the username is a valid email address
        if not username.endswith("@gov.in"):  # Replace with your domain
            raise ValueError("Please enter a valid email address.")
        
        user = auth.create_user(email=username, password=password)
        print(f"User '{username}' signed up successfully!")
    except ValueError as ve:
        print("Error:", ve)
    except Exception as e:
        print("Error:", e)

import requests

# Function to log in an existing user
def log_in():
    global logged_in_uid
    username = username_entry.get()
    password = password_entry.get()
    
    # Authenticate user using Firebase Authentication REST API
    url = "API Key"
    payload = {
        "email": username,
        "password": password,
        "returnSecureToken": True
    }
    response = requests.post(url, json=payload)
    data = response.json()
    
    if "error" in data:
        error_message = data["error"]["message"]
        print("Error:", error_message)
    else:
        logged_in_uid = data["localId"]
        print(f"User '{username}' logged in successfully!")
        show_voting_page()

key = b'\xb8\xba<\x80@\xe7w\xc3\xb3\xcb\xec\xf2n\x9a\xcc\x19'
print()
print("Key used for encryption and decryption: (Should be kept secret, only to be known by Election Commission)", key)
print()
plaintext = "74891"
print()
print("Example Unique Party Number(UPN): (Should be kept secret, only to be known by Election Commission)", plaintext)
print()

def extract_integers(representations):

def generate_output_representation(representations, x):

def replace_x(representations, replacement_integer):

def add(lst):

import ast


def vote(party):
    global logged_in_uid
    private_key = generate_cryptographically_secure_random_integer(10, 900000)
    print()
    print("The Random integer being used for representation:", private_key)
    print()
    number_bytes = private_key.to_bytes((private_key.bit_length() + 7) // 8, 'big')
    encrypted_number = encrypt_number(key, number_bytes)
    # Generate key and private key for encryption
    party_ref = ref.child('parties').child(party)
    party_data = party_ref.get() or {}
    recieved = party_data.get('encrpyted_supporter', None)
    recieved2 = party_data.get('supporter2', 0)
    if recieved:
    	current_votes = int(recieved)%(10**recieved2)
    else:
    	current_votes = int(plaintext)
    print()
    
    
    print("Reference Number before vote: (UPN+current votes)", current_votes)
    print()
    
    print("Current votes: ", current_votes-int(plaintext))
    print()
    
    lst1 = parse_string(find_representation(private_key, current_votes))
    print("Representation of Reference Number using the random integer:", lst1)
    print()

    replaced_list = replace_x(lst1, encrypted_number)
    print("Representation of Reference Number using the random integer encryption:", replaced_list)
    print()

    add_result = adds(replaced_list, 1)
    print("Representation of Reference Number after a vote and the value stored in the database:", add_result)
    print()
    
    party_ref.update({'ciphertext': add_result})
    
    output_representation = generate_output_representation(add_result, private_key)
    gui = replace_x(output_representation, private_key)
    final_resultop = add(gui)
    
    print("After votes, of a round:", final_resultop - int(plaintext))
    print()
    
    support = generate_cryptographically_secure_random_integer(10, 900000)
    party_ref.update({'encrpyted_supporter': str(support)+str(final_resultop), 'supporter2': len(str(final_resultop))})
    
    print(f"Successfully voted for {party}!")
    for button in vote_buttons:
        button.configure(state="disabled")
    
    CTkLabel(root, text=f"Successfully voted for {party}. Returning to Login Page").pack(pady=10)  # Display the message
    root.update() 
    
    time.sleep(2)
    
    show_login_page()

def show_voting_page(): 
    for widget in root.winfo_children():
        widget.destroy()
    
    global vote_buttons
    vote_buttons = []
    for party, icon_path in parties.items():
        image = tk.PhotoImage(file=icon_path)
        image = image.subsample(max(1, image.width() // 50), max(1, image.height() // 50))
        party_images[party] = image
        button = CTkButton(root, image=image, command=lambda p=party: vote(p), corner_radius=32, fg_color="transparent", border_width=0, text=party)
        button.pack(pady=5)
        vote_buttons.append(button)

def show_login_page():
    for widget in root.winfo_children():
        widget.destroy()
    
    username_label = CTkLabel(root, text="Username:")
    username_label.pack(pady=10)
    global username_entry
    username_entry = CTkEntry(root, placeholder_text="Enter a valid @gov.in ID", width=300)
    username_entry.pack(pady=10)

    password_label = CTkLabel(root, text="Password:")
    password_label.pack(pady=10)
    global password_entry
    password_entry = CTkEntry(root, show="*", placeholder_text="Enter a valid Password", width=300)
    password_entry.pack(pady=10)

    sign_up_button = CTkButton(root, text="Sign Up", command=sign_up, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
    sign_up_button.pack(pady=10)

    log_in_button = CTkButton(root, text="Log In", command=log_in, corner_radius=32, fg_color="transparent", hover_color="#4158D0", border_color="#FFCC70", border_width=2)
    log_in_button.pack(pady=10)

root = CTk()
root.title("Secure Voting Machine")

root.geometry("600x350") 
root.configure()

original_image = Image.open("/home/lucifer/Downloads/image_2024-06-04_002825380.ppm")
resized_image = original_image.resize((600, 350), Image.LANCZOS)
bg_image = ImageTk.PhotoImage(resized_image)
bg_label = tk.Label(root, image=bg_image)
bg_label.place(x=0, y=0, relwidth=1, relheight=1)

show_login_page()

root.mainloop()

