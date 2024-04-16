# Backup Server App
## Main Goal

I wanted to create something that will perform its main abillity through the network using Python. I found out about sockets and first though was about creating some system that enables moving files around networks and PCs. Finally,  Project contains three main files:
1. server.py - contains server side functionalities of the app
2. client.py - enables connecting with server side app and sending files to server
3. add_user.py - admin interface for users management

## How does this work?
The comunication beetwen server and client side app rely on the python socket module. The comunication will be possible only if you enter the correct informations about ip addres and the port number where the server will be listening for connections. Ofcourse you need to place add_user.py and server.py on the server machine and the client.py on the PC which you want send data from. I recomemend to create separate folders for server side apps, because during the configuration server app will create files and directiories.

## Users Management App
The database of users are create by sqlite3 module and it's placed in the file called users.db in the same directory as add_users.py. One record of table in database contains username, user's password and directory where user will be place files wanted to send to the server. To launch the users management app type in your console `python add_users.py`. That's what you should get:

<img src="https://github.com/kdPerkowski/Backup-server/assets/82761466/4c6b4247-c2df-4318-a8aa-890819176c31" alt="drawing" width="300"/>

This app enables to add users, display users that exist in the databas and delete users from database. If there is no database in directory it will be created during creation of user. There will appear also a folder with folder of every user that exist in database. In this folder will be all files that user send to server.

## Server Side App
To launch server type `python server.py` in your console. This you should see (the ip address depends what address did you enter in configurations in code):

<img src="https://github.com/kdPerkowski/Backup-server/assets/82761466/2f7b6ba1-b5b2-4048-aa93-a6747c00b692" alt="drawing" width="400"/>

## Client Side App
To launch the app enter `python client.py` in your console. You should see a prompt with login and next with password. Enter username and password of user that admin put into database. After correct user authentication files in users directory (directory eneterd into user reocord in database) will be sent to server. You should see overall statistics how many files were send, modfied or removed from the server.

## Security
Passwords placed in the database are hashed with md5. The server app provides end-to-end encryption with AES algorithm.
