#SERVER ADMINISTRATION PANEL USE TO CREATE USERS 
import sqlite3, os, re, getpass
from time import sleep
from pathlib import Path
import hashlib

CLEAR_SCREEN = ''

#directory validation regex
regexDir = re.compile(r"^[A-Za-z]:[a-zA-Z0-9/_-]*$")

#check which syatem is beeing used by user
if os.name == 'nt':
    CLEAR_SCREEN = 'cls'
else:
    CLEAR_SCREEN = 'clear'

#func for hashing passwords
def hash_password(password):
    hashed = hashlib.md5(password.encode())
    return hashed.hexdigest()

#start connection with data base
conn = sqlite3.connect("users.db")
cur = conn.cursor()

#create table if not exists
cur.execute("""CREATE TABLE if not exists users(
            username TEXT UNIQUE,
            password TEXT,
            directory TEXT
)""")

manage = True

#managing data base procedure 
while manage:
    os.system(CLEAR_SCREEN)
    #start panel
    choice = input("Add new user(1)\nDelete user(2)\nShow users(3)\nExit(4)\nEnter value: ")
    if choice == '1':
        #adding new user to data base
        os.system(CLEAR_SCREEN)
        add_username = True
        while add_username:
            users_db = [i[0] for i in cur.execute(f"SELECT username FROM users")]
            username = str(input("Enter username: "))
            if username in users_db:
                print('User already exists! Try again.')
            else:
                add_username = False

        add_password = True
        while add_password:
            password = str(getpass.getpass("Enter password: "))
            re_password = str(getpass.getpass("Enter password again: "))
            if password == re_password:
                add_password = False
            else:
                print('Wrong password! Try again.')
            
        add_directory = True
        while add_directory:
            directory = str(input("Enter absolute user directory (with '/' as a separator): "))
            if os.path.isdir(directory) and Path(directory).is_absolute() and re.fullmatch(regexDir,directory):
                add_directory = False
            else:
                print('Wrong directory! Try again')
            
        cur.execute(f"INSERT INTO users VALUES('{username}','{hash_password(password)}','{directory}')")
        conn.commit()
        print('User added!')
        sleep(2)

    elif choice == '2':
        #deleting user from data base
        os.system(CLEAR_SCREEN)
        delete = True
        while delete:
            users_db = [i[0] for i in cur.execute(f"SELECT username FROM users")]
            del_username = str(input("Which user do you want to delete?(!exit) "))
            if del_username == '!exit':
                print('Delete aborted.')
                delete = False
            elif del_username in users_db:
                dec = str(input("Are you sure?(y/n)"))
                if dec.lower() == 'yes' or dec.lower() == 'y':
                    cur.execute(f"DELETE FROM users WHERE username='{del_username}'")
                    conn.commit()
                    print("User deleted!")
                    sleep(2)
                    delete = False
                else:
                    print('Delete aborted.')
                    delete = False
            else:
                print("Username doesn't exist! Try again.")
    elif choice == '3':
        #get all users with their local directory paths
        os.system(CLEAR_SCREEN)
        res = cur.execute("SELECT username,directory FROM users")
        print("Username : Directory path")
        for i in res.fetchall():
            print(f"{i[0]} : {i[1]}")
        pause = input("Press enter to continue.")
    elif choice == '4':
        #exit administration panel
        os.system(CLEAR_SCREEN)
        manage = False
    else:
        os.system(CLEAR_SCREEN)
        print('Wrong data. Try again')
        sleep(2)

conn.close()
