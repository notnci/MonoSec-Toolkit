#Defensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help
import hashlib
import json
import requests
import cv2
import time
from bs4 import BeautifulSoup as bs
import time
import os

#Steganography: So you can add hidden files into an image
def Steg():
    print("1. Encode")
    print("2. Decode")
    x = int(input("Enter your option: "))
    if x == 1:
        steg_encode()
    elif x == 2:
        steg_decode()
    else:
        print("Bad input")
        Steg()

def steg_encode():
    def to_bit_generator(msg):
    #Converts a message into a generator which returns 1 bit of the message
    #each time
        for c in (msg):
            o = ord(c)
            for i in range(8):
                yield (o & (1 << i)) >> i

    def encode_main():
        #Message generator
        message = to_bit_generator(open("steg_message.txt", "r").read() * 10)
        # OG image reading
        image = cv2.imread('original.png', cv2.IMREAD_GRAYSCALE)
        for h in range(len(image)):
            for w in range(len(image[0])):
                # Writing to the least significant bit
                image[h][w] = (image[h][w] & ~1) | next(message)
        # Image + message
        cv2.imwrite("output.png", image)
    encode_main()

def steg_decode():
    # Try to restore image with message
    image = cv2.imread('output.png', cv2.IMREAD_GRAYSCALE)
    i = 0
    bits = ""
    chars = []
    for row in image:
        for pixel in row:
            bits = str(pixel & 0x01) + bits
            i += 1
            if(i == 8):
                chars.append(chr(int(bits, 2)))
                i = 0
                bits = ""
    print(" ".join(chars))



#Antivirus v1 will have a threat detection algorithm aka idk what I'm doing, and will use the VirusTotal API to scan files and parse results
def AV():
    print("YEET")


#Creates a listener for opens, and records mac address, IP address, geolocation, time, etc and sends it to an email, hopefully
def FAC():
    def log(epoch_elapsed):
        if not os.path.exists("C:/Monosec"):
            os.makedirs("C:/Monosec")
        f = open("C:/Monosec/accesslogs.txt","a")
        time.gmtime(epoch_elapsed)
        print(time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(epoch_elapsed)))
        f.write("Accessed at: "+ time.strftime('%m/%d/%Y %H:%M:%S',  time.gmtime(epoch_elapsed))+" GMT"+"\n")

    f = input("Enter the name of the file you want to add the listener to: ")
    epoch_elapsed = os.path.getmtime(f)
    log(epoch_elapsed)


#basic haveibeenpwned API usage to check for password/account deprecation
def pwned():
    print("1. Email checker")
    print("2. Password Checker")
    x  = int(input("Enter your choice: "))
    if x == 1:
        location = input("Enter the list name of all the emails you would like to check: ")
        email = [line.rstrip('\n') for line in open(location)]
        for e in email:
            check(e)
    elif x == 2:
        location = input("Enter the list name for the passwords you would like to check: ")
        passw = [line.rstrip('\n') for line in open(location)]
        for p in passw:
            checkPass(p)
    else:
        print("Bad input")
        pwned()


def checkPass(p):
    sentinel = p
    p = hashlib.sha1(p.encode()).hexdigest()
    temp = p
    p = p[0:5]
    response = requests.get("https://api.pwnedpasswords.com/range/"+p)
    if str(response.status_code) == "200":
        print("All good")
        for lines in response.text.split('\n'):
            if temp[5:].upper() == lines[:35]:
                print("The hash is: "+temp+" and the password is: "+sentinel)
        time.sleep(1.3)
    else:
        print("Fuck")


def check(email):
    rate = 1.5
    response = requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/", verify = True)
    print(str(response.status_code))
    if str(response.status_code) == "404":
        print("Your account doesn't seem to be breached")
    elif str(response.status_code) == "200":
        print("Your account has been compromised.")
    elif str(response.status_code) == "404":
        print("There was an error")
    elif str(response.status_code) == "429":
        print("Too many requests too quickly")
        rate = rate + .3
    elif str(response.status_code) == "503":
        print("Cloudflare is gay")
    time.sleep(rate)
    DefsecMenu()


#various cryptographic tools, like hashers, password generators, file encryptors (algorithm used: not determined)
def crypto():
    print("Welcome to the Crypto Suite")
    print()
    print("1. Password Hashing")
    print("2. Cesar Ciphering")
    print("3. Substitution Cipher Cracking")
    print("4. Cesar Cipher Cracking")
    print("5. AES Decyphering")
    print("6. RSA Decyphering")


def DefsecMenu():
    print()
    print("Welcome to the world of Defensive Security:")
    print("1. Steganography") #fix
    print("2. Anti Virus")#TODO
    print("3. File access listeners")#TODO
    print("4. Password deprecation check (uses API)")#cloudflare messes stuff up
    print("5. Crypto Suite")#TODO
    print("88. Help")
    print("99. Exit")
    x = int(input("What option would you like to choose? "))
    if(x == 1):
        Steg()
    elif(x == 2):
        print("AV")
        AV()
    elif(x==3):
        print("FAL")
        FAC()
    elif(x==4):
        pwned()
    elif(x==5):
        crypto()
    elif(x == 88):
        DefsecHelpmenu()
        DefsecMenu()
    elif(x==99):
        exit()

DefsecMenu()

if __name__ == "__DefsecMenu__":
    DefsecMenu()
