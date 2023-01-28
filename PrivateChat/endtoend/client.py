import socket
import threading

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding

import rsa as rr

# Choosing Nickname
nickname = "b"

public, private = rr.newkeys(1024)
with open("key1.txt", "w") as f:
    f.write(public.save_pkcs1().decode())

input("Press enter:")

aa = open("key2.txt", "rb").read()
print(aa)

public_partner = rr.PublicKey.load_pkcs1(aa)

# Connecting To Server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect(('127.0.0.1', 55555))


# Listening to Server and Sending Nickname
def receive():
    while True:
        try:
            # Receive Message From Server
            # If 'NICK' Send Nickname
            message = client.recv(1024)
            message = rr.decrypt(message, private).decode()
            print(message)

        except Exception as e:
            print(e)
            # Close Connection When Error
            print("An error occured!")
            # client.close()


# Sending Messages To Server
def write():
    while True:
        mess = input("")
        message = rr.encrypt(mess.encode(), public_partner)
        client.send(message)


# Starting Threads For Listening And Writing
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
