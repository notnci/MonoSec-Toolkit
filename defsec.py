#Defensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help


def Steg():
    print("Yeet")


#Antivirus v1 will have a threat detection algorithm aka idk what I'm doing, and will use the VirusTotal API to scan files and parse results
def AV():
    print("YEET")


#Creates a listener for opens, and records mac address, IP address, geolocation, time, etc and sends it to an email, hopefully
def FAC():
    print("yEeT")


#basic haveibeenpwned API usage to check for password/account deprecation
def pwned():
    print("pwned")


#various cryptographic tools, like hashers, password generators, file encryptors (algorithm used: not determined)
def crypto():
    print("memes")


def DefsecMenu():
    print()
    print("Welcome to the world of Defensive Security:")
    print("1. Steganography")
    print("2. Anti Virus")
    print("3. File access listeners")
    print("4. Password deprecation check (uses API)")
    print("5. Crypto Suite")
    print("88. Help")
    print("99. Exit")
    x = int(input("What option would you like to choose? "))
    if(x == 1):
        print("Steganography")
        Steg()
    elif(x == 2):
        print("AV")
        AV()
    elif(x==3):
        print("FAL")
        FAC()
    elif(x==4):
        print("pwned api")
        pwned()
    elif(x==5):
        print("cryptographic suite")
        crypto()
    elif(x == 88):
        DefsecHelpmenu()
        DefsecMenu()
    elif(x==99):
        exit()