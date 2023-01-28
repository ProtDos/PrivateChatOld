# KivyMD
from kivymd.app import MDApp
from kivymd.uix.label import MDLabel
from kivymd.toast import toast  # for sending toast messages

# Kivy
from kivy.uix.screenmanager import ScreenManager, Screen
from kivy.lang import Builder
from kivy.clock import mainthread
from kivy.core.text import LabelBase
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.properties import StringProperty, NumericProperty  # for chat screen, displaying speech bubbles

# Cryptography
import base64  # For encrypting messages
from cryptography.fernet import Fernet  # For encrypting messages
from cryptography.hazmat.backends import default_backend  # For encrypting messages
from cryptography.hazmat.primitives import hashes  # For encrypting messages
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC  # For encrypting messages
import rsa as rr

# Other
import threading  # Threaded tasks
import socket  # To connect to the server
import string  # Generating strong keys
import os  # Clearing the terminal window
import uuid  # Generating unique IDs
from password_strength import PasswordPolicy  # Checking security of password
import secrets  # creating strong keys (real randomness)
import time  # sleep function
from plyer import filechooser, notification  # File Choosing to send them to others, sending notifications
import qrcode  # creating QR-Codes (for the keys)
import colorama  # Terminal coloring
import socks  # TOR-Proxy
import pyperclip as pc  # For copying text

# Unused
import random  # Generating strong keys
from kivy.graphics import Color, RoundedRectangle
from kivy.uix.label import Label
from kivy.properties import ObjectProperty
from kivy.uix.scrollview import ScrollView
from kivymd.uix.list import TwoLineListItem
import pyfiglet  # Printing the banner
from colorama import Fore, Style, init  # Coloring
from io import BytesIO
from kivymd.uix.card import MDCard
import requests
import platform
from os import walk
from kivymd.uix.relativelayout import MDRelativeLayout

# TODO
"""
- Encrypt Private Messaging
    - https://www.youtube.com/watch?v=U_Q1vqaJi34&t=1070s
    - use private and public key, maybe store in database (public key)
- Check if messages come when being offline
"""

Window.size = (310, 580)

colorama.init()

HOST = "localhost"
PORT = 5000  # The port used by the server
"""
# 7.tcp.eu.ngrok.io:11961
HOST = "7.tcp.eu.ngrok.io"
PORT = 11961
"""

group_key = ""
user = ""

current_private_key = b""
current_chat_with = ""

is_it_my_turn = False


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


class Encrypt_File:
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
            iterations=1000,
            backend=default_backend()
        )
        key = base64.urlsafe_b64encode(kdf.derive(password))
        msg = self.message.encode()
        f = Fernet(key)
        msg = f.encrypt(msg)
        return msg


class Decrypt_File:
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
                iterations=1000,
                backend=default_backend()
            )
            key = base64.urlsafe_b64encode(kdf.derive(self.key))
            self.message = self.message.encode()
            f = Fernet(key)
            decoded = str(f.decrypt(self.message).decode())
            return decoded
        except:
            pass


def start_tor():
    os.system("torpy_socks -p 9050 --hops 3")


def connect(use_tor=False):
    global sock
    if use_tor:
        threading.Thread(target=start_tor).start()
        socks.set_default_proxy(socks.SOCKS5, "127.0.0.1", 9050)
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
    else:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))


connect(use_tor=False)


class ChatScreen(Screen):
    def __init__(self, **kwargs):
        super().__init__(**kwargs)

        try:
            sock.connect((HOST, PORT))
        except OSError:
            pass

        thread = threading.Thread(target=self.receive_message)
        thread.start()

    def send_message(self, message):
        self.usr = user
        self.key = group_key
        global size, halign, value
        if message != "":
            value = message
            if len(value) < 6:
                size = .22
                halign = "center"
            elif len(value) < 6:
                size = .22
                halign = "center"
            elif len(value) < 11:
                size = .32
                halign = "center"
            elif len(value) < 16:
                size = .45
                halign = "center"
            elif len(value) < 21:
                size = .58
                halign = "center"
            elif len(value) < 26:
                size = .71
                halign = "center"
            else:
                size = .7
                halign = "left"
            self.change2(value, size, halign)

            print(self.key)
            # sock.send("{}: {}".format(self.usr, value).encode())
            sock.send('{}: {}'.format(self.usr, Encrypt(message_=value, key=self.key).encrypt().decode()).encode())

            self.ids.text_input.text = ""

    def receive_message(self):
        print("started")
        """Receive messages from the server and update the chat screen"""
        while True:
            if is_it_my_turn:
                try:
                    message = sock.recv(1024).decode()
                    try:
                        sender = message.split(": ")[0]
                        message = Decrypt(message_=message.split(": ")[1], key=self.key).decrypt()
                    except:
                        pass
                    if message is not None:
                        if message:
                            if message == "NICK":
                                sock.send(self.usr.encode())
                            elif message == "FILE_INCOMING":
                                filename = Decrypt(message_=sock.recv(1024).decode(), key=group_key).decrypt()
                                # print(filename)

                                sender = sock.recv(1024).decode()
                                print(sender)

                                al = []

                                while True:
                                    more_data = sock.recv(1024).decode()
                                    if more_data.endswith(":"):
                                        more_data = more_data[:-7]
                                        al.append(more_data)
                                        break
                                    else:
                                        al.append(more_data)

                                data = "".join(al)
                                more3_data = Decrypt_File(message_=data, key=group_key).decrypt()
                                # print(more3_data)
                                k = f"{uuid.uuid4()}-{filename}"

                                kk = os.path.join(os.path.dirname(os.path.abspath(__file__)), k)

                                with open(kk, "w") as file:
                                    file.write(more3_data)

                                os.startfile(kk)

                                value = more3_data

                                if len(value) < 6:
                                    size = .22
                                    halign = "center"
                                elif len(value) < 6:
                                    size = .22
                                    halign = "center"
                                elif len(value) < 11:
                                    size = .32
                                    halign = "center"
                                elif len(value) < 16:
                                    size = .45
                                    halign = "center"
                                elif len(value) < 21:
                                    size = .58
                                    halign = "center"
                                elif len(value) < 26:
                                    size = .71
                                    halign = "center"
                                else:
                                    size = .7
                                    halign = "left"
                                self.change(filename, sender, size, halign)

                            else:
                                if len(value) < 6:
                                    size = .22
                                    halign = "center"
                                elif len(value) < 6:
                                    size = .22
                                    halign = "center"
                                elif len(value) < 11:
                                    size = .32
                                    halign = "center"
                                elif len(value) < 16:
                                    size = .45
                                    halign = "center"
                                elif len(value) < 21:
                                    size = .58
                                    halign = "center"
                                elif len(value) < 26:
                                    size = .71
                                    halign = "center"
                                else:
                                    size = .7
                                    halign = "left"
                                self.change(message, sender, size, halign)
                                print(message)
                        else:
                            break
                except Exception as e:
                    print(e)
                    continue
            time.sleep(5)

    @mainthread
    def change(self, message, fro, size, halign):
        self.ids.chat_list.add_widget(Response(text=message, size_hint_x=size, halign=halign, fro=fro))

    @mainthread
    def change2(self, message, size, halign):
        self.ids.chat_list.add_widget(
            Command(text=message, size_hint_x=size, halign=halign))  # size


def strength_test(p):
    try:
        policy = PasswordPolicy.from_names(
            strength=0.5  # need a password that scores at least 0.5 with its strength
        )
        out = policy.test(p)
        return [True if out == [] else False]  # returning if password is good or not
    except Exception:
        exit()


def gen(length):
    al = string.ascii_uppercase + string.ascii_lowercase + string.digits + "^!§$%&/()=?*+#'-_.:;{[]}"  # creating a list of nearly every char
    """
    This code is outdated, because generating a random key isn't truly possible with the random module:
    - https://python.readthedocs.io/en/stable/library/random.html
    - https://www.youtube.com/watch?v=Nm8NF9i9vsQ
    bb = []  # init list
    for i in range(length):  # creating a random password based on var length
        bb.append(random.choice(al))
    return "".join(bb)
    """
    # A better solution is this:
    key_sequences = []
    for _ in range(length):
        key_sequences.append(secrets.choice(al))
    return "".join(key_sequences)


class Command(MDLabel):
    text = StringProperty()
    size_hint_x = NumericProperty()
    halign = StringProperty()
    font_name = "BPoppins"
    font_size = 12


class Response(BoxLayout):
    text = StringProperty()
    fro = StringProperty()
    size_hint_x = NumericProperty()
    halign = StringProperty()
    font_name = "BPoppins"
    font_size = 12


class Command2(MDLabel):
    text = StringProperty()
    size_hint_x = NumericProperty()
    halign = StringProperty()
    font_name = "BPoppins"
    font_size = 12


class Response2(MDLabel):
    text = StringProperty()
    size_hint_x = NumericProperty()
    halign = StringProperty()
    font_name = "BPoppins"
    font_size = 12


class FAQScreen(Screen):
    def unfold_question(self, question_num):
        question = self.ids.faq_list.children[question_num-1]
        if question.is_selected:
            question.secondary_text = ""
            question.is_selected = False
        else:
            question.secondary_text = "Answer " + str(question_num)
            question.is_selected = True


class ChatApp(MDApp):
    def change_screen(self, name):
        self.screen_manager.current = name

    def build(self):
        self.username = ""
        self.password = ""
        self.id = ""
        self.rooms = []
        self.mf_key_group_bla = ""
        self.super_dubba_key = ""
        self.public_key = ""
        self.private_key = ""

        self.screen_manager = ScreenManager()
        self.screen_manager.add_widget(Builder.load_file("login.kv"))
        self.screen_manager.add_widget(Builder.load_file("home.kv"))
        self.screen_manager.add_widget(Builder.load_file("chat_private.kv"))
        self.screen_manager.add_widget(Builder.load_file("chat_sec.kv"))
        self.screen_manager.add_widget(Builder.load_file("main.kv"))
        self.screen_manager.add_widget(Builder.load_file("group_create.kv"))
        self.screen_manager.add_widget(Builder.load_file("group_join.kv"))
        self.screen_manager.add_widget(Builder.load_file("group.kv"))
        self.screen_manager.add_widget(Builder.load_file("group.kv"))
        self.screen_manager.add_widget(Builder.load_file("password_reset.kv"))
        self.screen_manager.add_widget(Builder.load_file("chat_new_private.kv"))
        self.screen_manager.add_widget(Builder.load_file("signup.kv"))
        self.screen_manager.add_widget(Builder.load_file("help.kv"))
        self.screen_manager.add_widget(Builder.load_file("chat_load.kv"))
        self.screen_manager.add_widget(Builder.load_file("personal.kv"))
        self.screen_manager.add_widget(Builder.load_file("bad.kv"))
        self.screen_manager.add_widget(Builder.load_file("new_group_join.kv"))
        self.screen_manager.add_widget(Builder.load_file("show_qr.kv"))
        self.screen_manager.add_widget(Builder.load_file("show_qr2.kv"))
        self.screen_manager.add_widget(Builder.load_file("show_id.kv"))
        self.asd = ChatScreen(name='chat')
        self.screen_manager.add_widget(self.asd)

        return self.screen_manager

    def sign_up(self, username, password, password2):
        connect()
        global user
        self.screen_manager.get_screen("home").welcome_name.text = f"Welcome {self.username}"
        self.screen_manager.get_screen("signup").username.text = ""
        self.screen_manager.get_screen("signup").password.text = ""
        self.screen_manager.get_screen("signup").password2.text = ""
        # TODO: add checking
        if password != password2:
            self.screen_manager.current = "bad"
            return
        uid = str(uuid.uuid4())
        public, private = rr.newkeys(1024)
        sock.send(f"SIGNUP:::{username}:::{Encrypt(message_=password, key=password).encrypt().decode()}:::{uid}".encode())
        sock.send(public.save_pkcs1())
        r = sock.recv(1024).decode()
        if r == "error":
            self.show_toaster("Username taken. Try again.")
            return
        elif r == "errorv2":
            self.show_toaster("ID already used - internal error. Try again later.")
            return
        else:
            pass
        with open("private_key2.txt", "w") as file:
            file.write(private.save_pkcs1().decode())
        with open("public_key.txt", "w") as file:
            file.write(public.save_pkcs1().decode())
        """
        with open("data/username.txt", "w") as file:
            file.w rite(username)
        with open("data/auth.txt", "w") as file:
            file.write(Encrypt(message_=password, key=password).encrypt().decode())
        with open("data/id.txt", "w") as file:
            uid = str(uuid.uuid4())
            file.write(uid)
        """
        self.id = uid
        self.username = username
        user = username
        self.password = password
        self.super_dubba_key = self.password
        self.screen_manager.current = "home"

        self.show_toaster("Account created!")

    def login(self, username, password):
        connect()
        global user
        self.screen_manager.get_screen("login").username.text = ""
        self.screen_manager.get_screen("login").password.text = ""
        self.screen_manager.get_screen("home").welcome_name.text = f"Welcome {self.username}"
        try:
            """
            with open("data/username.txt", "r") as file:
                usr = file.read()
            with open("data/auth.txt", "r") as file:
                pp = file.read()
            with open("data/id.txt", "r") as file:
                ii = file.read()
            if usr != username:
                self.screen_manager.current = "bad"
                return
            pp2 = Decrypt(message_=pp, key=password).decrypt()
            if pp2 == password:
                self.username = username
                user = usr
                self.password = password
                self.id = ii
                self.super_dubba_key = self.password
                self.screen_manager.current = "home"
                self.show_toaster("Logged in!")
            else:
                self.screen_manager.current = "bad"
            """
            sock.send(f"LOGIN:::{username}:::{password}".encode())
            r = sock.recv(1024).decode()
            print(r)
            if r == "error":
                self.show_toaster("Invalid username")
            elif r == "errorv2":
                self.show_toaster("Invalid password")
            else:
                self.username = username
                self.password = password
                self.screen_manager.current = "home"
                self.show_toaster("Logged in!")
                _, idd = r.split(":")
                self.id = idd
        except Exception as e:
            print(e)
            self.screen_manager.current = "bad"

    def show_qr_code(self, key):
        qr = qrcode.make(key)
        qr.save("assets/qr_code.png")

        self.screen_manager.get_screen("show_qr").img.reload()

        self.screen_manager.current = "show_qr"

    def show_qr_code2(self, key):
        qr = qrcode.make(key)
        qr.save("assets/qr_code.png")

        self.screen_manager.get_screen("show_qr2").img.reload()

        self.screen_manager.current = "show_qr2"

    def change_username(self, username):
        self.screen_manager.get_screen("home").text_input2.text = ""
        self.screen_manager.get_screen("home").welcome_name.text = f"Welcome {self.username}"
        if username != "":
            self.screen_manager.get_screen("home").username_icon.icon = "check"
            time.sleep(.5)
            self.screen_manager.get_screen("home").username_icon.icon = "account-cog"

            connect()
            sock.send(f"CHANGE_USERNAME:{self.username}:{self.password}:{username}".encode())
            r = sock.recv(1024).decode()
            if r == "success":
                self.screen_manager.current = "login"
                self.show_toaster("Username has been changed")
            else:
                self.show_toaster("Error changing username.")
        else:
            self.show_toaster("Please enter an username.")

    def change_password(self, new):
        self.screen_manager.get_screen("home").text_input3.text = ""

        """
        with open("data/auth.txt", "w") as file:
            file.write(Encrypt(message_=new, key=new).encrypt().decode())
        """
        connect()
        sock.send(f"CHANGE_PASSWORD:{self.password}:{new}:{self.username}".encode())
        r = sock.recv(1024).decode()
        if r == "success":

            with open("data/groups.csv", "r") as file:
                encrypted_keys = file.read().split("\n")

            for item in encrypted_keys:
                if item == "key" or item == "" or item == '':
                    encrypted_keys.remove(item)

            print(f"Found {len(encrypted_keys)} key(s) in groups.csv")
            print(encrypted_keys)

            with open("data/groups.csv", "w") as f:
                f.write("key\n")
                for enc_key in encrypted_keys:
                    print(enc_key)
                    dec_key = Decrypt(message_=enc_key, key=self.super_dubba_key).decrypt()
                    print(dec_key)
                    enc_key2 = Encrypt(message_=dec_key, key=new).encrypt().decode()
                    print(enc_key2)
                    f.write(enc_key2 + "\n")


            self.password = new
            self.super_dubba_key = new

            self.screen_manager.get_screen("home").password_icon.icon = "check"
            time.sleep(.5)
            self.screen_manager.get_screen("home").password_icon.icon = "account-cog"

            self.screen_manager.current_screen = "login"

            self.show_toaster("Password has been changed.")
        else:
            self.show_toaster("Error changing password.")

    def create_chat(self, rec):
        global current_private_key, current_chat_with, is_it_my_turn
        is_it_my_turn = False
        personal = self.username + "#" + self.id

        connect()
        sock.send(f"GET_PUBLIC:{rec}".encode())
        public_key = sock.recv(1024)
        print(public_key)
        if public_key != "error":
            public = rr.PublicKey.load_pkcs1(public_key)
            print(public)

            connect()

            sock.send("PRIV:".encode())
            sock.send(personal.encode())
            name = "b"
            """
            open(f"2\\{rec}.txt", 'w').close()
            key = gen(100)
            current_private_key = key
            current_chat_with = rec
            """
            current_private_key = public_key
            current_chat_with = rec

            # name = rec.split("#")[0]

            self.screen_manager.get_screen("chat_sec").chat_list.clear_widgets()
            self.screen_manager.get_screen("chat_sec").bot_name.text = name
            # self.screen_manager.get_screen("chat_sec").kkk.text = key

            threading.Thread(target=self.receive_messages_private, args=(public,)).start()

            self.screen_manager.current = "chat_sec"

            # self.show_toaster("Created!")
        else:
            self.show_toaster("Invalid recipient.")

    def join_chat(self, rec, key):
        global current_private_key, current_chat_with, is_it_my_turn
        is_it_my_turn = False
        personal = self.username + "#" + self.id

        connect()
        sock.send(f"GET_PUBLIC:{rec}".encode())
        public_key = sock.recv(1024)

        connect()

        sock.send("PRIV:".encode())
        sock.send(personal.encode())
        open(f"2\\{rec}.txt", 'w').close()
        current_private_key = key
        current_chat_with = rec

        name = rec.split("#")[0]

        self.screen_manager.get_screen("chat_sec").chat_list.clear_widgets()
        self.screen_manager.get_screen("chat_sec").bot_name.text = name
        self.screen_manager.get_screen("chat_sec").kkk.text = key

        threading.Thread(target=self.receive_messages_private, args=(key,)).start()

        self.screen_manager.current = "chat_sec"

    @mainthread
    def add(self, message):
        global size, halign, value
        if message != "":
            value = message
            if len(value) < 6:
                size = .22
                halign = "center"
            elif len(value) < 6:
                size = .22
                halign = "center"
            elif len(value) < 11:
                size = .32
                halign = "center"
            elif len(value) < 16:
                size = .45
                halign = "center"
            elif len(value) < 21:
                size = .58
                halign = "center"
            elif len(value) < 26:
                size = .71
                halign = "center"
            else:
                size = .7
                halign = "left"
        self.screen_manager.get_screen("chat_sec").chat_list.add_widget(Response2(text=message, size_hint_x=size, halign=halign))

    def receive_messages_private(self, key):
        with open("private_key2.txt", "rb") as private_file:
            private = rr.PrivateKey.load_pkcs1(private_file.read())
        print(private)
        try:
            with open(f"2/{current_chat_with}.txt", "r") as ii:
                aa = ii.read().split("\n")
            for lo in aa:
                if lo != "\n" and lo != "":
                    self.add(lo)
            open(f"2/{current_chat_with}.txt", "w").close()
        except:
            pass
        while True:
            try:
                print(current_chat_with)
                message = sock.recv(1024)
                message = message.decode()
                print(message)
                if message:
                    if message == "NICK":
                        sock.send(self.username.encode())
                    elif message.split("#")[1].startswith(current_chat_with):
                        _, *m = message.split("---")
                        m = "".join(m)
                        m = m[2:]
                        m = m[:-1]
                        print(m)
                        print(rr.decrypt(m.encode(), private).decode())
                        # m = Decrypt(message_=m, key=key).decrypt()
                        self.add(m)
                    elif message.startswith(f"INCOMING:{self.username}#{self.id}"):
                        _, m = message.split("|||")
                        m = "".join(m)
                        m = Decrypt(message_=m, key=key).decrypt()
                        self.add(m)
                    else:
                        try:
                            sender, mess = message.split("---")
                            print(rr.decrypt(mess, private).decode())
                            with open(f"2\\{sender}.txt", "a") as file:
                                file.write(mess+"\n")
                            self.notify(f"New message from {sender}", mess)
                        except:
                            print("Invalid message received.")
                            self.add(message)
                else:
                    break
            except Exception as e:
                print(e)
                continue

    def load_groups(self):
        self.screen_manager.get_screen("group_join").group_list.clear_widgets()
        try:
            with open("data/groups.csv") as file:  # getting group key data
                data = file.read().split("\n")
        except:
            if not os.path.isfile("data/groups.csv"):
                a = open("data/groups.csv", "w")
                a.write("key\n")
                a.close()
            data = []
        c = 0
        my_bitch_rooms = [""]  # list of rooms
        try:
            for i in range(1, len(data)):
                try:
                    if data[i] == "" or data[i] == "\n":
                        pass
                    else:
                        current_line = Decrypt(message_=data[i], key=self.super_dubba_key,
                                               verbose=False).decrypt()  # decrypting every group name/key
                        if current_line is not None:
                            my_bitch_rooms.append(current_line)
                            c += 1
                except:
                    c -= 1
                    pass
        except:
            pass

        if c > 0:
            self.screen_manager.get_screen("group_join").group_num.disabled = False
            self.screen_manager.get_screen("group_join").butt.disabled = False
            self.screen_manager.get_screen("group_join").butt.hint_text = "Enter group number"
            self.rooms = my_bitch_rooms
            for i, item in enumerate(my_bitch_rooms):
                if item != "" and item != None:
                    print("1")
                    item = item.split("|")[0]
                    self.screen_manager.get_screen("group_join").group_list.add_widget(
                        Response(text=f"{i})-{item}", size_hint_x=.75))
        else:
            print("2")
            self.screen_manager.get_screen("group_join").ok.text = "No groups available."
            self.screen_manager.get_screen("group_join").group_num.disabled = True
            self.screen_manager.get_screen("group_join").butt.disabled = True
            self.screen_manager.get_screen("group_join").butt.hint_text = "Not available"

    def join_group(self, group_id):
        if group_id != "":
            group_id = int(group_id)
            if self.super_dubba_key != "":
                self.screen_manager.get_screen("chat").chat_list.clear_widgets()
                global group_key, sock, is_it_my_turn
                is_it_my_turn = True

                connect()

                key = self.rooms[group_id]
                name = key.split("|")[0]
                self.screen_manager.get_screen("chat").kkk.text = key
                self.screen_manager.get_screen("chat").bot_name.text = name
                group_key = key
                self.screen_manager.current = "chat"
            else:
                self.screen_manager.current = "login"

    def join_new_group(self, key):
        if key != "":
            if self.super_dubba_key != "":
                self.screen_manager.get_screen("chat").chat_list.clear_widgets()
                global group_key, sock, is_it_my_turn
                is_it_my_turn = True

                connect()

                name = key.split("|")[0]
                self.screen_manager.get_screen("chat").kkk.text = key
                self.screen_manager.get_screen("chat").bot_name.text = name
                group_key = key
                with open("data/groups.csv", "r") as file:
                    aa = file.read().split("\n")
                enc_key = Encrypt(message_=key, key=self.super_dubba_key).encrypt().decode()
                if enc_key not in aa:
                    with open("data/groups.csv", "a") as file:
                        file.write(f"{enc_key}\n")
                self.screen_manager.current = "chat"
            else:
                self.screen_manager.current = "login"

    def create_group(self, name):
        if name != "":
            self.screen_manager.remove_widget(self.asd)
            self.screen_manager.add_widget(self.asd)
            self.screen_manager.get_screen("group_create").name_.text = ""

            global group_key, sock, is_it_my_turn
            is_it_my_turn = True
            key = gen(100)
            group_id = str(uuid.uuid4())
            key = name + "|" + key + "|" + group_id
            group_key = key
            print(key)
            self.screen_manager.get_screen("chat").kkk.text = key
            self.screen_manager.get_screen("chat").bot_name.text = name
            # self.screen_manager.get_screen("chat").key.text = key
            with open("data/groups.csv", "a") as file:
                encc = Encrypt(message_=key, key=self.super_dubba_key).encrypt().decode()
                print(encc)
                file.write(f"{encc}\n")

            connect()

            sock.send(("ID::::::" + "|||" + self.username + "|||" + group_id).encode())
            # sock.send(f"ID::::::{group_id}".encode())
            self.screen_manager.current = "chat"
            self.screen_manager.get_screen("chat").chat_list.clear_widgets()

    @mainthread
    def send_message_private(self, message, _):
        key = rr.PublicKey.load_pkcs1(current_private_key)
        print(key)
        # sock.send(("/pm " + current_chat_with + " " + Encrypt(message_=message, key=key).encrypt().decode()).encode())
        # sock.send(("/pm " + current_chat_with + " " + message).encode())
        sock.send(f"/pm {current_chat_with} {rr.encrypt(message.encode(), key)}".encode())

        global size, halign, value
        if message != "":
            value = message
            if len(value) < 6:
                size = .22
                halign = "center"
            elif len(value) < 6:
                size = .22
                halign = "center"
            elif len(value) < 11:
                size = .32
                halign = "center"
            elif len(value) < 16:
                size = .45
                halign = "center"
            elif len(value) < 21:
                size = .58
                halign = "center"
            elif len(value) < 26:
                size = .71
                halign = "center"
            else:
                size = .7
                halign = "left"

        self.screen_manager.get_screen("chat_sec").chat_list.add_widget(
            Command2(text=message, size_hint_x=size, halign=halign))

        self.screen_manager.get_screen("chat_sec").text_input.text = ""

    def file_chooser(self, key):
        self.mf_key_group_bla = key
        print("key", key)
        filechooser.open_file(on_selection=self.selected)

    def selected(self, selection):
        try:
            self.send_file(selection[0])
        except:
            pass

    def send_file(self, file_path):
        f_size = os.path.getsize(file_path) / 1048576

        if f_size > 25:
            self.show_toaster("File is too big.")
            print("File is too big.")
        else:
            filename = str(os.path.basename(file_path))

            with open(filename, 'r') as file:
                sendfile = file.read()

            sock.send("FILE:::::".encode())

            sock.send(f"{Encrypt(message_=filename, key=group_key).encrypt().decode()}".encode())

            # print(sendfile)

            sock.send(self.username.encode())

            content = Encrypt_File(message_=sendfile, key=group_key).encrypt()
            print(content)
            sock.send(content)

            sock.send("DONE:".encode())

            self.screen_manager.get_screen("chat").chat_list.add_widget(
                Command(text=filename, size_hint_x=.75, halign="center"))

    def delete_everything(self):
        try:
            self.screen_manager.current = "signup"
            self.show_toaster("Your data will now be deleted.")
            connect()
            sock.send(f"DELETE_ALL:{self.username}:{self.password}".encode())
            r = sock.recv(1024).decode()
            if r == "success":
                """
                print("[i] Deleting groups.csv")
                with open("data/groups.csv", "a") as aa:
                    for i in range(100):
                        aa.write(str(gen(20)) + "\n")
                with open("data/groups.csv", "w") as aaa:
                    aaa.write("")
                os.remove("data/groups.csv")
                """
                self.screen_manager.current = "signup"
                self.show_toaster("Done")
            else:
                self.show_toaster("Error deleting data.")

        except:
            pass

        try:
            pass
            # os.remove(os.path.basename(__file__))
        except:
            pass
        return

    def show_toaster(self, message):
        toast(message)
        pass

    def notify(self, title, message):
        notification.notify(
            title=title,
            message=message,
            timeout=10,
            app_name='Encochat'
        )

    def message_click(self):
        print("message clicked")

    def show_id(self):
        pc.copy(self.id)
        qr = qrcode.make(self.id)
        qr.save("C:\\Users\\Admin\\PycharmProjects\\Encryptor\\MOBILE\\GUI\\assets\\qr_code_id.png")

        self.screen_manager.get_screen("show_id").img.reload()

        self.screen_manager.current = "show_id"


if __name__ == "__main__":
    LabelBase.register(name="MPoppins",
                       fn_regular="C:\\Users\\Admin\\PycharmProjects\\Encryptor\\MOBILE\\GUI\\fonts\\Poppins\\Poppins-Medium.ttf")  # Medium
    LabelBase.register(name="BPoppins",
                       fn_regular="C:\\Users\\Admin\\PycharmProjects\\Encryptor\\MOBILE\\GUI\\fonts\\Poppins\\Poppins-SemiBold.ttf")  # Semi-Bold
    ChatApp().run()
