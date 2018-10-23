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
    double_letters =["aa","bb","cc","dd","ee","ff","gg","hh","ii","jj","kk","ll",
    "mm","nn","oo","pp","qq","rr","ss","tt","uu","vv","ww","xx","yy","zz"]

    double_letter_freq = {}
    #Found at https://www3.nd.edu/~busiforc/handouts/cryptography/Letter%20Frequencies.html
    last_letter_freq = {
    "e":19.17,
    "s":14.35,
    "d":9.23,
    "t":8.64,
    "n":7.86,
    "y":7.30,
    "r":6.93,
    "o":4.67,
    "l":4.56,
    "f":4.08
    }


    #Found at https://en.wikipedia.org/wiki/Letter_frequency
    first_letter_frequency = {
    "a":11.682,
    "b":4.34,
    "c":2.78,
    "d":4.25,
    "e":12.7,
    "f":2.22,
    "g":2.015,
    "h":6.094,
    "i":6.966,
    "j":0.153,
    "k":0.772,
    "l":4.025,
    "m":2.406,
    "n":6.749,
    "o":7.507,
    "p":1.929,
    "q":0.095,
    "r":5.987,
    "s":6.327,
    "t":9.056,
    "u":2.758,
    "v":0.978,
    "w":2.360,
    "x":0.150,
    "y":1.974,
    "z":0.074
    }

    #Found at https://en.wikipedia.org/wiki/Bigram
    bigram_frequency = {
    "th":1.52,
    "he":1.28,
    "in":0.94,
    "er":0.94,
    "an":0.82,
    "re":0.68,
    "nd":0.63,
    "at":0.59,
    "on":0.57,
    "nt":0.56,
    "ha":0.56,
    "es":0.56,
    "st":0.55,
    "en":0.55,
    "ed":0.53,
    "to":0.52,
    "it":0.50,
    "ou":0.50,
    "ea":0.47,
    "hi":0.46,
    "is":0.46,
    "or":0.46,
    "ti":0.34,
    "as":0.33,
    "te":0.27,
    "et":0.19,
    "ng":0.18,
    "of":0.16,
    "al":0.09,
    "de":0.09,
    "se":0.08,
    "le":0.08,
    "sa":0.06,
    "si":0.05,
    "ar":0.04,
    "ve":0.04,
    "ra":0.04,
    "ld":0.02,
    "ur":0.02
    }

    #Found at http://pi.math.cornell.edu/~mec/2003-2004/cryptography/subs/frequencies.html

    frequencies={
    "e":12.02,
    "t":9.10,
    "a":8.12,
    "o":7.68,
    "i":7.31,
    "n":6.95,
    "s":6.28,
    "r":6.02,
    "h":5.92,
    "d":4.32,
    "l":3.98,
    "u":2.88,
    "c":2.71,
    "m":2.61,
    "f":2.30,
    "y":2.11,
    "w":2.09,
    "g":2.03,
    "p":1.82,
    "b":1.49,
    "v":1.11,
    "k":0.69,
    "x":0.17,
    "q":0.11,
    "j":0.10,
    "z":0.07
    }
    #Outline:
    #Calculate letter frequencies in input text
    #Compare letter frequency to frequency Dictionary
    #Check for double letter combos
    #Compare to double letter frequencies
    #Compare to common 3 letter combos
    #Substitute letters through frequency comparison
    #hopefully have something readable at the end?
    div = len(text)
    dyn_num = {}
    dyn_freq = {}
    dyn_double_letter = {}
    for key, value in frequencies.items():
        letter = key
        count = 0
        for i in range(len(text)):
            if text[i] == letter:
                count += 1
        dyn_num[letter] = count

    print()
    print("Letter counts:")
    print(dyn_num)
    for key, value in dyn_num.items():
        dyn_freq[key] = (value/div)*100
    print()
    print("Letter frequencies:")
    print(dyn_freq)
    for i in range(len(double_letters)):
        dyn_double_letter[double_letters[i]] = text.count(double_letters[i])
    print()
    print("Double Letter Counts:")
    print(dyn_double_letter)

    print("These are the possible words with first letter adjustments:")
    new_t = text.split(" ")
    for i in new_t:
        temp_first_adj = []
        for j in first_letter_frequency.keys():
            temp_string = i
            temp_first_adj.append(temp_string.replace(temp_string[0],j))
        print(temp_first_adj)



    print("These are the possible words with last letter adjustments:")
    new_t = text.split(" ")
    for i in new_t:
        temp_last_adj = []
        for j in last_letter_freq.keys():
            temp_string = i
            temp_last_adj.append(temp_string.replace(temp_string[-1],j))
        print(temp_last_adj)

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
    data_minus_one = os.path.expandvars (r'C:\Users\%USERNAME%\AppData\Local\Google\Chrome\User Data'
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
