#Menu Framework for MSF
#Made by Christian Krenzlin, Co-Founder of MonoSec
#Special Thanks to Albert Slepak for his help

import offsec
import defsec
import sys
import time
args = ["-O \tOffensive Framework only","-D \tDefensive Framework only","-A \tAll Frameworks"]

#For arugment Debugging

def update_progress(job_title, progress):
    length = 20 # modify this to change the length
    block = int(round(length*progress))
    msg = "\r{0}: [{1}] {2}%".format(job_title, "#"*block + "-"*(length-block), round(progress*100, 2))
    if progress >= 1: msg += " DONE\r\n"
    sys.stdout.write(msg)
    sys.stdout.flush()

# Test

def null():
    if(sys.argv[1] == "-O"):
        exec("offsec")
    elif(sys.argv[1] == "-D"):
        exec("defsec")
    else:
        print("No applicable arguments")

null()