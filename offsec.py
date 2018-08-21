#Offensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help
import interface
import itertools
import math
import hashlib
import sys

arr = ["Social Engineering  A collection of Social Engineering tools, including Phishing email producer, email spoofer, and many more","",
 "Dictionary Creation You can enter an array of words and/or numbers and the algorithm will create a list of all possible passwords created with those words and save it into your specified file path","",
 "Bruteforcing tool   A bruteforcing tool that's designed to both bruteforce local files, such as password protected ZIP files, it can also bruteforce supported email services","",
 "Reverse Shell       Allows you to create a reverse tcp shell in order to keep a connection to the infected computer","",
 "Hash Cracking       This takes a different approach to cracking passwords. If you have a password hash from somewhere, and you'd like to know what the password is, but it may be in a one-way algorithm, you can use this with an attached wordlist to bruteforce the hash",
]

arr = ["a"]
def dictExec(list,idx):
    arr.remove("a")
    x = 0
    with open(list) as f:
        lines = [line.rstrip('\n') for line in open(list)]
    for i in lines:
        print(str(x)+": "+i)
        arr.append(i)
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

    OffsecMenu()





def crackExec(list,hash,algorithm):
    arr.remove("a")
    sentinel = hash
    with open(list) as f:
        lines = [line.rstrip('\n') for line in open(list)]
    for i in lines:
        arr.append(i)
    if(algorithm == 1):
        found = False
        for i in range(len(arr)):
            m = hashlib.md5(arr[i].encode())
            print(m.hexdigest())
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
            print(m.hexdigest())
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
            print(m.hexdigest())
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
            print(m.hexdigest())
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
            print(m.hexdigest())
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
            print(m.hexdigest())
            if(m.hexdigest() == hash):
                print("The hash was found.The password is: "+arr[i])
                found = True
                break
        if(not found):
            print("No passwords matched")
    else:
        print("Not a valid option")
        HashCrack()





def SocialEngineering():
    print("asd")

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

def Brute():
    print("das")

def Reverse_Shell():
    print("dasdg")

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

def OffsecHelpmenu():
    print("welcome to the help menu")
    print()
    for i in range(0,len(arr)):
        print(arr[i])

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
        print("SE")
        SocialEngineering()
    elif(x == 2):
        Dictionary()
    elif(x == 3):
        print("BF")
        Brute()
    elif(x == 4):
        print("Reverse shell NOTE:PLEASE RESEARCH")
        Reverse_Shell()
    elif(x == 5):
        print("basically paste hashcat here")
        HashCrack()
    elif(x == 88):
        OffsecHelpmenu()
        OffsecMenu()
    elif(x == 99):
        exit()

OffsecMenu()
