#Defensive Security Framework
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help


def DefsecMenu():
    print()
    print("Welcome to the world of Defensive Security:")
    print("1. Steganography")
    print("2. Anti Virus")
    print("3. File access listeners")
    print("4. Password deprecation check (uses API)")
    print("5. File Encryptions")
    print("99. Exit")
    x = int(input("What option would you like to choose? "))
    if(x == 1):
        print("one")
    elif(x == 2):
        print("two")