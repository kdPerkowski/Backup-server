#CLIENT SIDE INITIALIZATION FILE
import socket
import os
from Crypto.Cipher import AES

ADDR = '127.0.0.1' #server address
PORT = 44000 #server listening port
HEADER = 64 #received message bufer size
FORMAT = 'utf-8' #encoding format

#create client side socket
client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#connect with server
client_socket.connect((ADDR,PORT))

#func to encrypt message
def do_encrypt(message):
    obj = AES.new(b'Encrypt$key/728!', AES.MODE_EAX, b'Initialization@vEctor997*')
    ciphertext = obj.encrypt(message)
    return ciphertext

#func to decrypt message
def do_decrypt(ciphertext):
    obj = AES.new(b'Encrypt$key/728!', AES.MODE_EAX, b'Initialization@vEctor997*')
    message = obj.decrypt(ciphertext)
    return message 

#func for sending messages to server with custom bufer
def send(msg):
    message = do_encrypt(msg.encode(FORMAT))
    msg_length = len(message) 
    send_length = str(msg_length).encode(FORMAT) 
    send_length += b' ' * (HEADER - len(send_length))
    client_socket.send(send_length)
    client_socket.send(message)

#func for sending files to server with custom bufer
def send_in_bytes(msg):
    message = do_encrypt(msg) 
    msg_length = len(message) 
    send_length = str(msg_length).encode(FORMAT) 
    send_length += b' ' * (HEADER - len(send_length))
    client_socket.send(send_length)
    client_socket.send(message)  

#func for receiving messages from server
def recv_message(conn):
    message = do_decrypt(conn.recv(1024)).decode(FORMAT)
    return message


login = True

#interaction with server
while login:
    #entering username
    print(recv_message(client_socket))
    username = str(input())
    send(username)
    response = recv_message(client_socket)
    if response == 'Correct user':
        login = False
        while True:
            #enetering password
            print(recv_message(client_socket))

            password = str(input())
            send(password)
            password_response = recv_message(client_socket)
            if password_response == f'Hello {username}':
                #if password is correct start interaction with server
                print(password_response)
                #get files from server side directory
                files_res = recv_message(client_socket)
                if files_res=="empty":
                    server_files = []
                else:
                    server_files = files_res.split(';')

                #get modification dates from server side directory files
                mod_res = recv_message(client_socket)
                if mod_res=="empty":
                    mod_dates = []
                else:
                    mod_dates = mod_res.split(';')

                #get local directory path
                directory_res = recv_message(client_socket)
                client_directory = os.path.abspath(directory_res)
                #get list of local directory files
                files_local_directory = os.listdir(client_directory)

                #get local files modification dates
                mod_local = []
                for i in files_local_directory:
                    file_mod = os.path.getmtime(os.path.join(client_directory,i))
                    mod_local.append(str(file_mod))

                #create local files dictionary with format file:modification date
                files_mod_local = {}
                for i in range(len(files_local_directory)):
                    files_mod_local[files_local_directory[i]] = mod_local[i]

                #create server files dictionary with format file:modification date
                files_mod_server = {}
                for i in range(len(server_files)):
                    files_mod_server[server_files[i]] = mod_dates[i]

                #lsit of files needs to be send to server
                server_send_files = []
                for i in files_local_directory:
                    if i not in files_mod_server.keys():
                        server_send_files.append(i)
                    else:
                        if float(files_mod_local[i]) > float(files_mod_server[i]):
                            server_send_files.append(i)

                #format files names to send
                format_name_files_to_server = ";".join(server_send_files)

                if format_name_files_to_server == '':
                    send('empty')
                else:
                    send(format_name_files_to_server)

                #send files content
                for file_name in server_send_files:
                    with open(os.path.join(client_directory,file_name),"rb") as file:
                        file_content = file.read()
                        send_in_bytes(file_content)
                        
                all_files_send = ';'.join(files_local_directory)
                send(all_files_send)

                #finish updating files procedure with server feedback
                fin_response_recv = recv_message(client_socket)
                fin_response = fin_response_recv.split(';')
                print(f"Added/Updated: {fin_response[0]} Removed: {fin_response[1]}")
                break
            else:
                print(password_response)
    else:    
        print(response)
