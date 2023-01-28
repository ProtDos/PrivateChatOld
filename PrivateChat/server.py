import socket
import threading
from datetime import datetime
import time
import csv
import pandas as pd

import base64  # For encrypting messages
from cryptography.fernet import Fernet  # For encrypting messages
from cryptography.hazmat.backends import default_backend  # For encrypting messages
from cryptography.hazmat.primitives import hashes  # For encrypting messages
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For encrypting messages


host = "localhost"
port = 5000

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((host, port))

server.listen()

clients = []
nicknames = []

dataset = []
form = []

private_chats = []

clients__pr = {}
buffer = []


class Decrypt:
    def __init__(self, message_, key, verbose=True):
        self.message = message_
        self.key = key
        self.verbose = verbose

    def decrypt(self):
        try:
            self.key = self.key.encode()
            salt = b'salt_'
            kdf = PBKDF2HMAC(
                algorithm=hashes.SHA256(),
                length=32,
                salt=salt,
                iterations=100000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.key))
            self.message = self.message.encode()
            f = Fernet(key)
            decoded = str(f.decrypt(self.message).decode())
            return decoded
        except:
            pass


def replace_value(old_value, new_value, column_name):
    df = pd.read_csv('database.csv')
    df.loc[df[column_name] == old_value, column_name] = new_value
    df.to_csv('database.csv', index=False)


def check_username_exist(value):
    with open('database.csv', 'r') as f:
        reader = csv.DictReader(f)
        data = [row for row in reader]
        for row in data:
            if row['username'] == value:
                return True
        return False


def check_id_exist(value):
    with open('database.csv', 'r') as f:
        reader = csv.DictReader(f)
        data = [row for row in reader]
        for row in data:
            if row['id'] == value:
                return True
        return False


def get_id(username):
    with open('database.csv', 'r') as f:
        reader = csv.DictReader(f)
        data = [row for row in reader]
        for row in data:
            if row['username'] == username:
                return row['id']
    return None


def get_username(idd):
    with open('database.csv', 'r') as f:
        reader = csv.DictReader(f)
        data = [row for row in reader]
        for row in data:
            if row['id'] == idd:
                return row['username']
    return None


def get_password(username):
    with open('database.csv', 'r') as f:
        reader = csv.DictReader(f)
        data = [row for row in reader]
        for row in data:
            if row['username'] == username:
                return row['password']
    return None


def get_public(idd):
    try:
        with open(f"public_{idd}.txt", "rb") as file:
            return file.read()
    except:
        return None


class Encrypt:
    def __init__(self, message_, key):
        self.message = message_
        self.key = key

    def encrypt(self):
        password_provided = self.key
        password = password_provided.encode()
        salt = b'salt_'
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=100000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        msg = self.message.encode()
        f = Fernet(key)
        msg = f.encrypt(msg)
        return msg


def broadcast(message, client):
    try:
        group_id = None
        for item in dataset:
            if item["client"] == client:
                group_id = item["group"]
        if group_id is None:
            print("User not in list")
            pass
        else:
            members = []
            for item in dataset:
                if item["group"] == group_id:
                    members.append(item["client"])
            print(message)
            for person in members:
                if person != client:
                    person.send(message)

        """
        for client in clients:
            client.send(message)
        """

    except KeyboardInterrupt:
        exit("ctrl+c detected")


def broadcast_file(name, client, data, sender):
    try:
        print("okay")
        group_id = None
        for item in dataset:
            if item["client"] == client:
                group_id = item["group"]
        if group_id is None:
            print("User not in list")
            pass
        else:
            members = []
            for item in dataset:
                if item["group"] == group_id:
                    members.append(item["client"])
            print("sending file")
            for person in members:
                if person != client:
                    person.send("FILE_INCOMING".encode())
                    time.sleep(.5)
                    person.send(f"{name}".encode())
                    time.sleep(.5)
                    person.send(sender.encode())
                    person.send(data.encode())
                    person.send("DONE:::".encode())
                    # person.send(name)
                    # person.send(content)

        """
        for client in clients:
            client.send(message)
        """

    except KeyboardInterrupt:
        exit("ctrl+c detected")


def handle(client, d1, g_id):
    dataset.append({"client": client, "group": g_id})
    while True:
        try:
            pp = False
            message = client.recv(1024)

            if message == b'':
                pp = True
                pass
            elif message.decode() == "FILE:::::":
                # TODO: add try-except everywhere
                pp = True
                print("File received")
                filename = client.recv(1024).decode()

                print("Encrypted-Filename", filename)

                sender = client.recv(1024).decode()

                al = []

                while True:
                    more_data = client.recv(1024).decode()
                    if more_data.endswith(":"):
                        more_data = more_data[:-5]
                        al.append(more_data)
                        break
                    else:
                        al.append(more_data)
                    # print(more_data)
                complete_data = "".join(al)
                print("Data received.")

                broadcast_file(name=filename, client=client, data=complete_data, sender=sender)
            if not pp:
                if message.decode() == "PRIV:":
                    print("okay")
                    a = "True"
                    b = None
                print(f"{d1} Message: ", message)
                if ": " in message.decode():
                    broadcast(message, client)
        except ConnectionResetError:
            try:
                s = False
                for item in form:
                    if item["client"] == client:
                        print(f"{d1} {item['name']} disconnected.")
                        s = True
                if not s:
                    print(f"{d1} Unknown client disconnected.")
                clients.remove(client)
                for item in dataset:
                    if item["client"] == client:
                        dataset.remove(item)
            except Exception as e:
                print(e)
                clients.remove(client)
                print("Client disconnected x2")
            break
        except KeyboardInterrupt:
            print("Ctrl+C detected")
            break
        except OSError:
            pass
    exit("ok")


def handle_client(client, _, oho):
    if oho == "True":
        p = client.recv(1024).decode()
        print(p)
        clients__pr[p] = client
        dd = p
    else:
        clients__pr[oho] = client
        dd = oho
    p = dd
    for item in buffer:
        if item["from"] == p:
            print("yws")
            send_message(item["from"], item["mess"], p, buf=True)
            buffer.remove(item)
    while True:
        try:
            request = client.recv(1024).decode()
            print(request)
            if request.startswith("/pm"):
                _, idd, *mess = request.split(" ")
                send_message(idd, mess, p, buf=False)
            else:
                print("Invalid.")
            clients__pr[p] = client
        except:
            print("client disconnected.")
            break


def send_message(idd, message, p, buf=True):
    print(idd, message, p)
    idd = get_username(idd) + "#" + idd
    if buf:
        try:
            recipient_socket = clients__pr[idd]
            message = " ".join(message)
            recipient_socket.send(f"INCOMING:{p}|||{message}".encode())
        except:
            buffer.append({"from": idd, "to": p, "mess": message})
            print("Sender not available.")
    else:
        try:
            recipient_socket = clients__pr[idd]
            print(idd)
            message = " ".join(message)
            recipient_socket.send(f"{p}---{message}".encode())
        except Exception as e:
            print(e)
            buffer.append({"from": idd, "to": p, "mess": message})
            print("Sender not available.")


def receive():
    print(f"{datetime.now().strftime('[%d-%m-%Y %H:%M:%S]')} Server started...")
    while True:
        try:
            now = datetime.now()
            d1 = now.strftime("[%d-%m-%Y %H:%M:%S]")

            client, address = server.accept()
            print("Connected with {}".format(str(address)))

            xxx = client.recv(1024).decode()

            print("X", xxx)

            if xxx == "PRIV:":
                print("private")
                oho = "True"
                client_thread = threading.Thread(target=handle_client, args=(client, address, oho,))
                client_thread.start()
            elif xxx.startswith("SIGNUP:::"):
                print("ye")
                _, username, pas, idd = xxx.split(":::")
                public_key = client.recv(1024).decode()

                print(username, pas, idd)
                if check_username_exist(username):
                    client.send("error".encode())
                else:

                    if check_id_exist(idd):
                        client.send("errorv2".encode())
                    else:
                        with open("database.csv", "a") as data_file_:
                            data_file_.write(f"{username},{pas},{idd}\n")
                        with open(f"public_{idd}.txt", "w") as file:
                            file.write(public_key)
                        client.send("success".encode())
            elif xxx.startswith("LOGIN:::"):
                _, username, password = xxx.split(":::")
                print(username, password)
                if not check_username_exist(username):
                    client.send("error".encode())
                else:
                    pas = get_password(username)
                    if Decrypt(message_=pas, key=password).decrypt() is not None:
                        client.send(f"success:{get_id(username)}".encode())
                    else:
                        client.send("errorv2".encode())
            elif xxx.startswith("CHANGE_USERNAME:"):
                _, username, password, new_username = xxx.split(":")
                if check_username_exist(username):
                    if Decrypt(message_=get_password(username), key=password).decrypt() is not None:
                        replace_value(username, new_username, "username")
                        client.send(b"success")
                    else:
                        client.send(b"error")
                else:
                    client.send(b"error")
            elif xxx.startswith("CHANGE_PASSWORD:"):
                _, old, new, username = xxx.split(":")
                if check_username_exist(username):
                    if Decrypt(message_=get_password(username), key=old).decrypt() is not None:
                        replace_value(get_password(username), Encrypt(message_=new, key=new).encrypt().decode(), "password")
                        client.send(b"success")
                    else:
                        client.send(b"error")
                else:
                    client.send(b"error")
            elif xxx.startswith("DELETE_ALL:"):
                _, username, password = xxx.split(":")
                if check_username_exist(username):
                    if Decrypt(message_=get_password(username), key=password).decrypt() is not None:
                        df = pd.read_csv('database.csv')
                        fieldname = 'username'
                        value_to_delete = username
                        df = df[df[fieldname] != value_to_delete]
                        df.to_csv('database.csv', index=False)
                        client.send(b"success")
                    else:
                        client.send(b"error")
                else:
                    client.send(b"error")
            elif xxx.startswith("PRIV:"):
                try:
                    _, idd = xxx.split(":")
                    print("private")
                    client_thread = threading.Thread(target=handle_client, args=(client, address, idd,))
                    client_thread.start()
                except Exception:
                    print("da fuck")
                    pass
            elif xxx.startswith("GET_PUBLIC:"):
                idd = xxx.split(":")[1]
                if check_id_exist(idd):
                    print("Ok")
                    aa = get_public(idd)
                    if aa:
                        client.send(aa)
                    else:
                        client.send(b"error")
                else:
                    print("nah")
                    client.send(b"error")
            else:
                if xxx.startswith("ID:::::"):
                    _, nickname, group_id = xxx.split("|||")
                    nicknames.append(nickname)

                    clients.append(client)
                    form.append({"client": client, "name": nickname})

                    print(f"{d1} {nickname} joined.")

                    thread = threading.Thread(target=handle, args=(client, d1, group_id,))
                    thread.start()

        except KeyboardInterrupt:
            exit()
        except Exception as e:
            print(e)
            print("Client disconnected.")


receive()
