import base64
import pyDes

key = b"AKaPdSgV"
iv = b"QeThWmYq"

def decryptSessionData(ctext):
    data = base64.b64decode(ctext)

    des = pyDes.des(key, pyDes.CBC, iv, padmode=pyDes.PAD_PKCS5)
    pt = des.decrypt(data)
    print(pt)

path = input("Nhập đường dẫn tới sessions: ").strip()

import os

for file in os.listdir(path):
    with open(os.path.join(path, file), 'r') as f:
        for line in f:
            decryptSessionData(line.strip())
