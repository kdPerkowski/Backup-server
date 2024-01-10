#BACKUP SERVER INITAILIZATION FILE 
import socket
import threading
import sqlite3
import os
from Crypto.Cipher import AES
import hashlib

ADDR = '127.0.0.1' #server address
PORT = 44000 #server listening port
HEADER = 64 #received message bufer size
FORMAT = 'utf-8' #encoding format

#create socket
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#bind server
server_socket.bind((ADDR,PORT))

#func for encrypting message
def do_encrypt(message):
    obj = AES.new(b'Encrypt$key/728!', AES.MODE_EAX, b'Initialization@vEctor997*')
    ciphertext = obj.encrypt(message)
    return ciphertext

#func for decrypting message
def do_decrypt(ciphertext):
    obj = AES.new(b'Encrypt$key/728!', AES.MODE_EAX, b'Initialization@vEctor997*')
    message = obj.decrypt(ciphertext)
    return message


#func for receiving message from host
def recv_message(conn):
    message_length = int(conn.recv(HEADER).decode(FORMAT))
    message = do_decrypt(conn.recv(message_length))
    decrypted_message = message.decode(FORMAT)
    return decrypted_message

#func for receiving file in bytes
def recv_message_in_bytes(conn):
    message_length = int(conn.recv(HEADER).decode(FORMAT))
    message = do_decrypt(conn.recv(message_length))
    return message

#func for sending message to host
def send_message(conn,message):
    encode_message = do_encrypt(message.encode(FORMAT))
    conn.send(encode_message)

#func initialize connection with database
def db_connection(query):
    #connect with data base
    db_conn = sqlite3.connect("users.db")
    #initialize cursor for executing querys
    cur = db_conn.cursor()

    #creating table with user data if not exists
    cur.execute("""CREATE TABLE if not exists users(
                username TEXT UNIQUE,
                password TEXT,
                directory TEXT
    )""")

    #execute and read query
    res = cur.execute(query)
    response = res.fetchall()

    #close data base connection
    db_conn.close()

    #return query result in tuple in directory format
    return response

#func for hashing passwords
def hash_password(password):
    hashed = hashlib.md5(password.encode())
    return hashed.hexdigest()

#func for receiving files
def recv_files(conn,username):
    #path of the server file
    server_path = os.path.normpath(os.path.join(os.path.dirname(__file__)))
    #path to users directories main directory
    users_path = os.path.join(server_path, "users")
    #path to current logged in user directory
    current_user_path = os.path.join(users_path, username)

    if os.path.exists(users_path) is False:
        os.mkdir(users_path)

    if os.path.exists(current_user_path) is False:
        os.mkdir(current_user_path)

    #list users files
    user_dir_files = os.listdir(current_user_path)

    #format list of files to send with delimiter ';'
    files = ";".join(user_dir_files)
    if files == '':
        send_message(conn,"empty")
    else:
        send_message(conn,files)

    modification_list = []

    #reading modification dates of files
    for i in user_dir_files:
        file_mod = os.path.getmtime(os.path.join(current_user_path,i))
        modification_list.append(str(file_mod))
    mod_dates = ";".join(modification_list)

    if mod_dates == '':
        send_message(conn,'empty')
    else:
        send_message(conn,mod_dates)

    #read local host directory from data base
    db_directory = db_connection(f"SELECT directory FROM users WHERE username='{username}'")
    user_client_directory = str(db_directory[0][0])

    send_message(conn,user_client_directory)

    #receive files to update from host 
    files_to_update_recv = recv_message(conn)

    if files_to_update_recv == "empty":
        files_to_update = []
    else:
        files_to_update = files_to_update_recv.split(';')
    

    updated = []

    #updating files in users directory
    for file_name in files_to_update:
        file_content = recv_message_in_bytes(conn)
        with open(os.path.join(current_user_path,file_name),'wb') as file_write:
            file_write.write(file_content)
            updated.append(file_name)
    
    #receiving files from hosts local directory
    all_files_local_recv = recv_message(conn)
    all_files_local = all_files_local_recv.split(';')

    users_files_updated = os.listdir(current_user_path)

    removed = []
    
    #checking if file is in local host directory and if its in server directory if not delete file from server dir
    for file_check in users_files_updated:
        if file_check not in all_files_local:
            os.remove(os.path.join(current_user_path,file_check))
            removed.append(file_check)    

    #alert with numbers of files updated/removed send to host
    fin_response = f"{len(updated)};{len(removed)}"

    send_message(conn,fin_response)
    
#func for handling host connection
def handle_client(conn, addr):
    print(f"[NEW CONNECTION] {addr[0]}:{addr[1]} connected")

    login = True

    #login process
    while login:
        send_message(conn,'Enter username: ')
        username = recv_message(conn)
        #get usernames from data base
        users_db = [i[0] for i in db_connection(f"SELECT username FROM users")]
        if username in users_db:
            login = False
            send_message(conn,'Correct user')
            passwd = True
            #checking if user knows password
            while passwd:
                user_password_db = db_connection(f"SELECT password FROM users WHERE username='{username}'")[0][0]
                send_message(conn,'Enter your password: ')
                password = hash_password(recv_message(conn))
                if password == user_password_db:
                    #if password is correct start updating files procedure
                    passwd = False
                    send_message(conn,f'Hello {username}')
                    recv_files(conn,username)
                else:
                    #if passowrd is not correct try again
                    send_message(conn,'Invalid password. Try again.')

        else:
            #if username is not correct try again
            send_message(conn,'Invalid username. Try again.')

    #close connection with user
    conn.close()


#func for starting the server
def server_start():
    #server starts listening on port for connections
    server_socket.listen()
    print(f"[LISTENING] Server is listening on {ADDR}")
    while True:
        #accepting connection with host
        conn, addr = server_socket.accept()
        #making new thread to handle host
        thread = threading.Thread(target=handle_client, args=(conn,addr))
        thread.start()
        print(f"[ACTIVE CONNECTIONS] {threading.active_count()-1}")


print("[STARTING] server is starting...")
server_start()
