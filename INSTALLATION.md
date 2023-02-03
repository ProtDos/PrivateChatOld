# Private Chat | Encochat
## Installation Guide

###Pre-requisites
Windows:
You don't need any pre-requisites to run the .exe file.

Linux / MacOS:
We currently don't support Encochat for these platforms.

Android:
You don't need any pre-requisites to run the .apk file.

Linux / iOS:
We currently don't support Encochat for these platforms.

Python Development:
If you want to help and support this project, you will need these requirements:
```
Python 3.6+
```
Packages:
```
kivymd
kivy
cryptography
password-strength
plyer
pyperclip
colorama
qrcode
requests
pyfiglet
```

### Step 1 | Download
Please download the files ONLY from here:
- https://app.protdos.com/download.html
- https://github.com/ProtDos/PrivateChat/...
Download the .exe variant for your Windows enviroment and the .apk for your Android phone.

### Step 2 | Install
Windows:
Run the installer and agree all messages. The app will be unpacked and will now be installed. The app will open automatically or you can open it via searching. You are now completely set up and can enjoy privacy.

Android:
After you have downloaded the .apk file you can run it by simply pressing it and now install it. The app is now on your phone and you can start chatting.

### Disclaimer
Please only use this GitHub and our website to download the app, no third party services. Someone could imitaty us and implement a hidden backdoor / trojan or a fake server to read your messages. If you want to be very secure, you can compile the source code to an .exe or .apk. This is how:

### Compiling
.exe
(not tested)
```
pip install pyinstaller
git clone https://github.com/ProtDos/PrivateChat
cd PrivateChat/PrivateChat
pyinstaller --onefile main.py
```

.apk
(You need a linux machine)
```
pip3 install --user --upgrade buildozer
sudo apt update
sudo apt install -y git zip unzip openjdk-17-jdk python3-pip autoconf libtool pkg-config zlib1g-dev libncurses5-dev libncursesw5-dev libtinfo5 cmake libffi-dev libssl-dev
pip3 install --user --upgrade Cython==0.29.19 virtualenv

git clone https://github.com/ProtDos/PrivateChat
cd PrivateChat/PrivateChat

export PATH=$PATH:~/.local/bin/

buildozer -v android debug
```
The finished a.pk file will be in the /bin/ folder in the current directory. Just run `cd /bin` to get to the file.
Pro-tip: 
To move the file to your windows downloads folder (when you run for example ubuntu as a subsystem) you can run this code: `mv <app name> /mnt/c/Users/<your_username>/Downloads`

### Errors
If you have problems installing or compiling this project, please do not hesitate to create an issue.
