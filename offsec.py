#Offensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help
import interface

arr = ["Social Engineering  A collection of Social Engineering tools, including Phishing email producer, email spoofer, and many more","",
 "Dictionary Creation You can enter an array of words and/or numbers and the algorithm will create a list of all possible passwords created with those words and save it into your specified file path","",
 "Bruteforcing tool   A bruteforcing tool that's designed to both bruteforce local files, such as password protected ZIP files, it can also bruteforce supported email services","",
 "Reverse Shell       Allows you to create a reverse tcp shell in order to keep a connection to the infected computer","",
 "Hash Cracking       This takes a different approach to cracking passwords. If you have a password hash from somewhere, and you'd like to know what the password is, but it may be in a one-way algorithm, you can use this with an attached wordlist to bruteforce the hash",
]

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
    elif(x == 2):
        print("Dictionary")
    elif(x == 3):
        print("BF")
    elif(x == 4):
        print("Reverse shell NOTE:PLEASE RESEARCH")
    elif(x == 5):
        print("basically paste hashcat here")
    elif(x == 88):
        OffsecHelpmenu()
        OffsecMenu()
    elif(x == 99):
        exit()

OffsecMenu()

        
