import socket
import threading
from datetime import datetime
import time

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
            elif xxx.startswith("PRIV:"):
                try:
                    _, idd = xxx.split(":")
                    print("private")
                    client_thread = threading.Thread(target=handle_client, args=(client, address, idd,))
                    client_thread.start()
                except Exception:
                    print("da fuck")
                    pass
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
        except:
            print("Client disconnected.")


receive()
