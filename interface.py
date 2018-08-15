#Menu Framework for MSF
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help

import offsec
import defsec
import sys
import time
args = ["-O \tOffensive Framework only","-D \tDefensive Framework only","-A \tAll Frameworks"]

#For arugment Debugging
#print("Arguments:",str(sys.argv))

def update_progress(job_title, progress):
    length = 20 # modify this to change the length
    block = int(round(length*progress))
    msg = "\r{0}: [{1}] {2}%".format(job_title, "#"*block + "-"*(length-block), round(progress*100, 2))
    if progress >= 1: msg += " DONE\r\n"
    sys.stdout.write(msg)
    sys.stdout.flush()

# Test


def fullFramework():
    print("Welcome to the MonoSec Full Framework")
    print()
    for i in range(50):
        time.sleep(0.1)
        update_progress("Loading", i/50.0)
    update_progress("Loading", 1)

def main():
    if(sys.argv[1] == ("-A")):
        fullFramework()
    elif(sys.argv[1] == ("-help")):
        print("This is the MSF help page...")
        print("All command line arguments will be listed below:")
        #for loop since I'm too lazy to rewrite print
        for i in range(0,len(args)):
            print(args[i])
    elif(sys.argv[1] == ("-O")):
        offsec.main2()
        for i in range(50):
            time.sleep(0.1)
            update_progress("Loading", i/50.0)
        update_progress("Loading", 1)
        offsec.menu()
    elif(sys.argv[1] == ("-D")):
        defsec.main1()
        for i in range(50):
            time.sleep(0.1)
            update_progress("Loading", i/50.0)
        update_progress("Loading", 1)
        defsec.menu()
    else:
        print("No applicable arguments")


main()