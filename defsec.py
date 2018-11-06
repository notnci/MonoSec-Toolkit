#Defensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help
import hashlib
import json
import requests
import cv2
import time
import time
import os
import webbrowser
import subprocess
import sys
import shutil
from os import path
from stegano import lsb
from ngram_score import ngram_score
from pycipher import SimpleSubstitution
import random
import re
fitness = ngram_score("./english_quadgrams.txt")
#import Crypto
#from Crypto.PublicKey import RSA
#from Crypto import Random

#Steganography: So you can add hidden files into an image
def Steg():
    try:
        print("1. Encode")
        print("2. Decode")
        print("99. Back")
        x = int(input("Enter your option: "))
        if x == 1:
            steg_encode()
        elif x == 2:
            steg_decode()
        elif x == 99:
            DefsecMenu()
        else:
            print("Bad input")
            Steg()
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def steg_encode():
    try:
        original_file = input("Enter the name of the file you want to hide the message in: ")
        secret_message = input("Enter the message you want to hide: ")
        output_file = input("Enter the name of the file to be saved: ")
        try:
            new_image = lsb.hide(original_file, secret_message)
            new_image.save(output_file)
        except IOError:
            print("File cannot be opened")
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def steg_decode():
    try:
        file_to_decode = input("Enter the file you want checked for Steganography: ")
        try:
            cleartext = lsb.reveal(file_to_decode)
            print(cleartext)
        except IOError:
            print("File cannot be opened")
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

#Antivirus v2 will have a threat detection algorithm(don't have time) aka idk what I'm doing, and v1 will use the VirusTotal API to scan files and parse results maybe
def AV():
    try:
        apiKey = "" #Enter your API key here

        url = 'https://www.virustotal.com/vtapi/v2/file/scan'
        file = input("Enter the name of the file you want scanned: ")
        params = {'apikey': apiKey}
        files = {'file': (file, open(file, 'rb'))}
        response = requests.post(url, files=files, params=params)
        print(response.text)
        js = json.loads(response.text)
        webbrowser.open(js["permalink"])
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)


    #TODO: Heuristic analysis when I have some more time

#Creates a listener for opens, and  TODO records mac address, IP address, geolocation, time, etc and sends it to an email, hopefully.
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
    try:
        print("1. Email checker")
        print("2. Password Checker")
        print("99. Back")
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
        elif x == 99:
            print()
            DefsecMenu()
        else:
            print("Bad input")
            print()
            pwned()
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

#Password check
def checkPass(p):
    try:
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
            print("Nope")
    except KeyboardInterrupt:
        print("Fored exit...")
        sys.exit(1)

def check(email):
    try:
        rate = 1.5
        response = requests.get("https://haveibeenpwned.com/api/v2/breachedaccount/"+email, verify = True)
        print(str(response.status_code))
        if str(response.status_code) == "404":
            print("Your account: "+email+" doesn't seem to be breached")
        elif str(response.status_code) == "200":
            print("Your account: "+email+" has been compromised.")
        elif str(response.status_code) == "429":
            print("Too many requests too quickly")
            rate = rate + .3
        elif str(response.status_code) == "503":
            print("Cloudflare....")
        time.sleep(rate)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

#various cryptographic tools, like hashers, password generators, file encryptors (algorithm used: not determined)
def cryptoExec(hash,word):
    try:
        if hash == 1:
            m = hashlib.md5(word.encode())
            print("Your hash is: "+m.hexdigest())
        elif hash == 2:
            m = hashlib.sha1(word.encode())
            print("Your hash is: "+m.hexdigest())
        elif hash == 3:
            m = hashlib.sha224(word.encode())
            print("Your hash is: "+m.hexdigest())
        elif hash == 4:
            m = hashlib.sha256(word.encode())
            print("Your hash is: "+m.hexdigest())
        elif hash == 5:
            m = hashlib.sha384(word.encode())
            print("Your hash is: "+m.hexdigest())
        elif hash == 6:
            m = hashlib.sha512(word.encode())
            print("Your hash is: "+m.hexdigest())

        else:
            print("Not a valid option")
            print()
            crypto()
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def cipher(offset,text):
    try:
        newText = ""
        for symbol in text:
            if symbol.isalpha():
                num = ord(symbol)
                num += offset

                if symbol.isupper():
                    if num > ord("Z"):
                        num -= 26
                    elif num < ord("A"):
                        num += 26
                elif symbol.islower():
                    if num > ord("z"):
                        num -= 26
                    elif num < ord("a"):
                        num += 26
                newText += chr(num)
            else:
                newText += symbol
        print("Your cipher is: "+newText)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def cipherCrack(offset,text):
    try:
        newText = ""
        for symbol in text:
            if symbol.isalpha():
                num = ord(symbol)
                num -= offset

                if symbol.isupper():
                    if num > ord("Z"):
                        num -= 26
                    elif num < ord("A"):
                        num += 26
                elif symbol.islower():
                    if num > ord("z"):
                        num -= 26
                    elif num < ord("a"):
                        num += 26
                newText += chr(num)
            else:
                newText += symbol
        print("Your deciphered text is: "+newText)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def cipherCrackBF(text):
    try:
        for i in range(1,26):
            newText = ""
            for symbol in text:
                if symbol.isalpha():
                    num = ord(symbol)
                    num -= i

                    if symbol.isupper():
                        if num > ord("Z"):
                            num -= 26
                        elif num < ord("A"):
                            num += 26
                    elif symbol.islower():
                        if num > ord("z"):
                            num -= 26
                        elif num < ord("a"):
                            num += 26
                    newText += chr(num)
                else:
                    newText += symbol
            print("One deciphered text is: "+newText)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def subEncode(text):
    try:
        nt = text
        old = []
        new = []
        idx = int(input("How many letters do you want substituded?: "))
        for i in range(idx):
            ol = input("Enter the letter you want replaced: ")
            old.append(ol)
            nl = input("Enter the letter you want to replace it with: ")
            new.append(nl)
        for i in range(len(old)):
            nt = nt.replace(old[i],new[i])
        print("The original text was: "+text)
        print("The ciphered text is: "+nt)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

#Baseline information https://en.wikipedia.org/wiki/Frequency_analysis
def subDecode(text):
    maxscore = -99999999999
    ctext = text
    ctext = ctext.replace(" ","").upper()
    print("Adjusted Text: " + ctext)
    maxkey = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ'
    pText, pKey = ctext,maxkey
    decipher = SimpleSubstitution(pKey).decipher(pText)
    pscore = fitness.score(decipher)
    print("Deciphered: " + decipher)
    print("Score: " + str(pscore))
    i = 0
    while 1:
        i = i + 1
        pKeyL = list(pKey)
        random.shuffle(pKeyL)
        pKey = ''.join(pKeyL)
        decipher = SimpleSubstitution(pKey).decipher(ctext)
        pscore = fitness.score(decipher)
        count = 0
        while count  < 1000:

            cKey = pKey
            x = random.randint(0,25)
            y = random.randint(0,25)
            cKeyL = list(cKey)
            cKeyL[x] = pKey[y]
            cKeyL[y] = pKey[x]
            cKey = ''.join(cKeyL)
            #print("Key swapped")
            decipher = SimpleSubstitution(cKey).decipher(pText)
            score = fitness.score(decipher)
            #print("Attempt: " + decipher)
            #print("Score: " + str(score))
            if score > pscore:
                pscore = score
                pKey = cKey
                count = 0
            count = count + 1
    if(pScore > maxscore):
        maxscore = pScore
        maxkey = pKey
        ss = SimpleSubstitution(maxkey).decipher(ctext)
        print("Best Key: "+maxkey)
        print("plaintext: "+ss)




def crypto():
    try:
        print()
        print("Welcome to the Crypto Suite")
        print()
        print("1. Password Hashing")
        print("2. Cesar Ciphering")
        print("3. Substitution Ciphering")
        print("4. Substitution Cipher Cracking")
        print("5. Cesar Cipher Cracking")
        print("99. Back")
        crypt = int(input("Enter your choice: "))
        if crypt == 1:
            print("Here are the available hashing algorithms:")
            print()
            print("1. MD5")
            print("2. SHA1")
            print("3. SHA224")
            print("4. SHA256")
            print("5. SHA384")
            print("6. SHA512")
            hash = int(input("Enter the hashing algorithm you want to use: "))
            if(hash < 1 or hash > 6):
                print("Not a valid option")
                print()
                crypto
            word = input("Enter the word you want hashed: ")
            cryptoExec(hash,word)
        elif crypt == 2:
            offset = 0
            while(offset >= 26 or offset < 1):
                offset = int(input("Enter the offset you want to use for the cipher: "))
            text = input("Enter the text you want ciphered: ")
            cipher(offset, text)
        elif crypt == 3:
            print("[!!!] Make sure the text is lowercase")
            text = input("Enter the text you want to cipher: ")
            subEncode(text.lower())
        elif  crypt == 4:
            text = input("Enter the string you want decoded: ")
            subDecode(text)
        elif crypt == 5:
            var = input("Do you know the key used to encrypt the message? [y/n] ")
            if var.lower() == "y":
                offset = int(input("WHat key vaule was used to encrypt the message?: "))
                text = input("Enter the ciphered text: ")
                cipherCrack(offset, text)
            elif var.lower() == "n":
                text = input("Enter the ciphered text: ")
                cipherCrackBF(text)
            else:
                print("Not a valid option")
                print()
                crypto()
        elif crypt == 99:
            DefsecMenu()
        else:
            print("Bad input")
            print()
            crypto()
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def clearChrome():
    data_dir = os.path.expandvars (r'C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data\Default')
    data_minus_one = os.path.expandvars (r'C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data')
    print(data_dir)
    shutil.rmtree(data_dir)
    subprocess.run(["cipher","/w:C:"], shell=True)



def antiForensic():
    try:
        print("Welcome to some rudimentary anti forensic tools.")
        print("1. Clear Chrome Data")
        print("99. Back")
        x = int(input("What option would you like to choose? "))
        if(x == 1):
            clearChrome()
        elif(x==99):
            DefsecMenu()
        else:
            print("Not a valid option")
            print()
            antiForensic()
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(0)


def DefsecMenu():
    try:
        print()
        print("Welcome to the world of Defensive Security:")
        print("1. Steganography") #fixed and Done
        print("2. Anti Virus")#TODO add actual analysis but Done for now
        print("3. File access listeners")#TODO create a callback bait file
        print("4. Password and Account deprecation")#seems to be fixed now with the verify = True flag and Done
        print("5. Crypto Suite")#TODO Finish calculations
        print("6. Anti Forensics")
        print("88. Help")
        print("99. Exit")
        x = int(input("What option would you like to choose? "))
        if(x == 1):
            Steg()
        elif(x == 2):
            AV()
        elif(x==3):
            FAC()
        elif(x==4):
            pwned()
        elif(x==5):
            crypto()
        elif(x==6):
            antiForensic()
        elif(x == 88):
            DefsecHelpmenu()
            DefsecMenu()
        elif(x==99):
            sys.exit(0)
        else:
            print("Not a valid option")
            print()
            DefsecMenu()
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

DefsecMenu()
