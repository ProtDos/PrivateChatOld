# KivyMD
from kivymd.app import MDApp
from kivymd.uix.label import MDLabel
from kivymd.toast import toast  # for sending toast messages

# Kivy
from kivy.uix.screenmanager import ScreenManager
from kivy.lang import Builder
from kivy.clock import mainthread
from kivy.core.text import LabelBase
from kivy.core.window import Window
from kivy.uix.boxlayout import BoxLayout
from kivy.properties import StringProperty, NumericProperty  # for chat screen, displaying speech bubbles

"""
- Encrypt Private Messaging
    - https://www.youtube.com/watch?v=U_Q1vqaJi34&t=1070s
    - use private and public key, maybe store in database (public key)
- Check if messages come when being offline

Done...
"""

login = """
MDScreen:
    name: "login"
    username: username
    password: password
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "right"
                root.manager.current = "main"
        MDLabel:
            text: "W e l c o m e !"
            font_name: "BPoppins"
            font_size: "26sp"
            pos_hint: {"center_x": .6, "center_y": .85}
            color: rgba(0, 0, 59, 255)

        MDLabel:
            text: "Sign in to continue"
            font_name: "BPoppins"
            font_size: "18sp"
            pos_hint: {"center_x": .6, "center_y": .79}
            color: rgba(135, 133, 193, 255)
        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .63}
            TextInput:
                id: username
                hint_text: "Username"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .5}
            TextInput:
                id: password
                hint_text: "Password"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
                password: True
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        Button:
            text: "LOGIN"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .34}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
            on_release:
                app.login(username.text, password.text)
                #root.manager.transition.direction = "left"
                #root.manager.current = "chat"
        MDTextButton:
            text: "Forgot Password?"
            pos_hint: {"center_x": .5, "center_y": .28}
            color: rgba(68, 78, 132, 255)
            font_size: "12sp"
            font_name: "BPoppins"
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "password_reset"
        MDLabel:
            text: "Don't have an account?"
            font_name: "BPoppins"
            font_size: "11sp"
            pos_hint: {"center_x": .68, "center_y": .2}
            color: rgba(135, 133, 193, 255)
        MDTextButton:
            text: "Sign up"
            font_name: "BPoppins"
            font_size: "11sp"
            pos_hint: {"center_x": .75, "center_y": .2}
            color: rgba(135, 133, 193, 255)
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "signup"
"""
home = """
#: import get_color_from_hex kivy.utils.get_color_from_hex
#: import webbrowser webbrowser

#: import TwoLineListItem kivymd.uix.list.TwoLineListItem
#: import Window kivy.core.window.Window

MDScreen:
    name: "home"
    username_icon: username_icon
    password_icon: password_icon
    text_input2: text_input2
    text_input3: text_input3
    welcome_name: welcome_name

    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1


        MDBottomAppBar:
            title: 'Bottom navigation'
            md_bg_color: .2, .2, .2, 1
            specific_text_color: 1, 1, 1, 1

        MDBottomNavigation:
            panel_color: 1, 1, 1, 1

            MDBottomNavigationItem:
                name: "home"
                text: "Home"
                icon: "home"

                MDLabel:
                    id: welcome_name
                    text: "Welcome"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Start chatting"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat_private"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Groups"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "group"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Settings"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .45}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "settings"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Personal"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .35}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "personal"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "My ID"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .15}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        app.show_id()
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

                MDIconButton:
                    icon: "logout"
                    pos_hint: {"center_x": .9, "center_y": .05}
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "main"


            MDBottomNavigationItem:
                name: "test"
                text: "Chats"
                icon: "chat"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "home"

                MDLabel:
                    text: "Chats"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Start chatting"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat_private"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Load chats"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat_load"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

            MDBottomNavigationItem:
                name: "test2"
                text: "Settings"
                icon: "account-settings"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    text: "Settings"
                    font_name: "BPoppins"
                    font_size: "26sp"
                    pos_hint: {"center_x": .6, "center_y": .85}
                    color: rgba(0, 0, 59, 255)

                MDFloatLayout:
                    size_hint_y: .11
                    MDFloatLayout:
                        size_hint: .8, .75
                        pos_hint: {"center_x": .43, "center_y": 7}
                        TextInput:
                            id: text_input2
                            hint_text: "Set a new username"
                            size_hint: 1, None
                            pos_hint: {"center_x": .5, "center_y": .5}
                            font_size: "12sp"
                            height: self.minimum_height
                            multiline: False
                            cursor_color: 1, 170/255, 23/255, 1
                            cursor_width: "2sp"
                            background_color: 0, 0, 0, 0
                            padding: 15
                            font_name: "BPoppins"
                    MDIconButton:
                        id: username_icon
                        icon: "account-cog"
                        pos_hint: {"center_x": .91, "center_y": 7}
                        user_font_size: "12sp"
                        text_color: 1, 1, 1, 1
                        on_release:
                            app.change_username(text_input2.text)

                MDFloatLayout:
                    size_hint_y: .11
                    MDFloatLayout:
                        size_hint: .8, .75
                        pos_hint: {"center_x": .43, "center_y": 6}
                        TextInput:
                            id: text_input3
                            hint_text: "Set a new password"
                            size_hint: 1, None
                            pos_hint: {"center_x": .5, "center_y": .5}
                            font_size: "12sp"
                            height: self.minimum_height
                            multiline: False
                            cursor_color: 1, 170/255, 23/255, 1
                            cursor_width: "2sp"
                            background_color: 0, 0, 0, 0
                            padding: 15
                            font_name: "BPoppins"
                    MDIconButton:
                        id: password_icon
                        icon: "account-cog"
                        pos_hint: {"center_x": .91, "center_y": 6}
                        user_font_size: "12sp"
                        text_color: 1, 1, 1, 1
                        on_release:
                            app.change_password(text_input3.text)
                Button:
                    text: "Delete Everything"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .35}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        app.delete_everything()
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100


            MDBottomNavigationItem:
                name: "test3"
                text: "Help"
                icon: "help-circle"

                MDLabel:
                    text: "Help"
                    font_name: "BPoppins"
                    font_size: "26sp"
                    pos_hint: {"center_x": .6, "center_y": .85}
                    color: rgba(0, 0, 59, 255)

                MDLabel:
                    text: "Found a bug or improvements?"
                    font_name: "BPoppins"
                    font_size: "11sp"
                    pos_hint: {"center_x": .68, "center_y": .75}
                    color: rgba(0, 0, 59, 255)
                MDTextButton:
                    text: "Contact Us"
                    font_name: "BPoppins"
                    font_size: "11sp"
                    pos_hint: {"center_x": .68, "center_y": .7}
                    color: rgba(135, 133, 193, 255)
                    on_release:
                        webbrowser.open("https://protdos.com/contact.html")

                MDLabel:
                    text: "Contact us"
                    font_name: "BPoppins"
                    font_size: "11sp"
                    pos_hint: {"center_x": .68, "center_y": .55}
                    color: rgba(0, 0, 59, 255)
                MDTextButton:
                    text: "Mail Us"
                    font_name: "BPoppins"
                    font_size: "11sp"
                    pos_hint: {"center_x": .68, "center_y": .5}
                    color: rgba(135, 133, 193, 255)
                    on_release:
                        webbrowser.open("mailto:rootcode@duck.com")
"""
chat_private = """
MDScreen:
    name: "chat_private"
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "right"
                root.manager.current = "home"
        MDLabel:
            text: "Chat"
            font_name: "BPoppins"
            font_size: "26sp"
            pos_hint: {"center_x": .6, "center_y": .85}
            color: rgba(0, 0, 59, 255)

        MDLabel:
            text: "Start Chatting"
            font_name: "BPoppins"
            font_size: "18sp"
            pos_hint: {"center_x": .6, "center_y": .79}
            color: rgba(135, 133, 193, 255)
        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .63}
            TextInput:
                id: name
                hint_text: "Recipient"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        Button:
            text: "Chat"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .34}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
            on_release:
                app.create_chat(name.text)
"""
chat_sec = """
#:import Clipboard kivy.core.clipboard.Clipboard
<Command2>
    size_hint_y: None
    pos_hint: {"right": .98}
    height: self.texture_size[1]
    padding: 12, 10
    theme_text_color: "Custom"
    canvas.before:
        Color:
            rgb: rgba(52, 0, 234, 255)
        RoundedRectangle:
            size: self.width, self.height
            pos: self.pos
            radius: [23, 23, 0, 23]
    on_touch_down:
        app.message_click()
<Response2>
    size_hint_y: None
    pos_hint: {"x": .02}
    height: self.texture_size[1]
    padding: 12, 10
    theme_text_color: "Custom"
    #text_color: 1, 1, 1, 1
    canvas.before:
        Color:
            rgb: (1, 1, 1, 1)
        RoundedRectangle:
            size: self.width, self.height
            pos: self.pos
            radius: [23, 23, 23, 0]
MDScreen:
    name: "chat_sec"
    kkk: kkk
    bot_name: bot_name
    chat_list: chat_list
    text_input: text_input

    MDFloatLayout:
        MDFloatLayout:
            md_bg_color: 245/255, 245/255, 245/255, 1
            size_hint_y: .11
            pos_hint: {"center_y": .95}
            MDIconButton:
                icon: "arrow-left"
                pos_hint: {"center_y": .5}
                user_font_size: "30sp"
                theme_text_color: "Custom"
                text_color: rgba(26, 24, 58, 255)
                on_release:
                    root.manager.transition.direction = "right"
                    root.manager.current = "home"
            MDIconButton:
                icon: "content-copy"
                pos_hint: {"center_x": .9, "center_y": .5}
                on_release:
                    Clipboard.copy(kkk.text)
                    app.show_qr_code2(kkk.text)

            MDLabel:
                text: ""
                id: bot_name
                pos_hint: {"center_y": .5}
                halign: "center"
                font_name: "BPoppins"
                font_size: "25sp"
                theme_text_color: "Custom"
                text_color: 53/255, 56/255, 60/255, 1
            MDLabel:
                text: ""
                id: kkk
                pos_hint: {"center_y": .5}
                halign: "center"
                font_name: "BPoppins"
                font_size: "0sp"
                theme_text_color: "Custom"
                text_color: 53/255, 56/255, 60/255, 1
                opacity: 0




        ScrollView:
            size_hint_y: .77
            pos_hint: {"x": 0, "y": .116}
            do_scroll_x: False
            do_scroll_y: True
            BoxLayout:
                id: chat_list
                orientation: "vertical"
                size: (root.width, root.height)
                height: self.minimum_height
                size_hint: None, None
                pso_hint: {"top": 10}
                cols: 1
                spacing: 5
        MDFloatLayout:
            md_bg_color: 245/255, 245/255, 245/255, 1
            size_hint_y: .11
            MDFloatLayout:
                size_hint: .7, .60
                pos_hint: {"center_x": .45, "center_y": .5}
                canvas:
                    Color:
                        rgb: (238/255, 238/255, 238/255, 1)
                    RoundedRectangle:
                        size: self.size
                        pos: self.pos
                        radius: [23, 23, 23, 23]
                TextInput:
                    id: text_input
                    hint_text: "Type something..."
                    size_hint: 1, None
                    pos_hint: {"center_x": .5, "center_y": .5}
                    font_size: "12sp"
                    height: self.minimum_height
                    multiline: False
                    cursor_color: 1, 170/255, 23/255, 1
                    cursor_width: "2sp"
                    foreground_color: 1, 170/255, 23/255, 1
                    background_color: 0, 0, 0, 0
                    padding: 15
                    font_name: "BPoppins"
            MDIconButton:
                icon: "send"
                pos_hint: {"center_x": .91, "center_y": .5}
                user_font_size: "18sp"
                theme_text_color: "Custom"
                text_color: 0, 0, 0, 1
                #foreground_color: rgba(0, 0, 0, 1)
                #md_bg_color: rgba(52, 0, 231, 255)
                on_release:
                    app.send_message_private(text_input.text, kkk.text)
            MDIconButton:
                icon: "file-upload"
                pos_hint: {"center_x": .8, "center_y": .5}
                user_font_size: "18sp"
                theme_text_color: "Custom"
                text_color: 0, 0, 0, 1
                #md_bg_color: rgba(52, 0, 231, 255)
                on_release:
                    app.file_chooser(kkk.text)

"""
main = """
MDScreen:
    name: "main"
    MDFloatLayout:

        md_bg_color: 1, 1, 1, 1
        #Image:
        #     source: "logo.png"
        #    pos_hint: {"center_x": .19, "center_y": .95}
        Image:
            source: "front.png"
            size_hint: .8, .8
            pos_hint: {"center_x": .5, "center_y": .65}
        MDLabel:
            text: "PrivChat"
            font_name: "BPoppins"
            font_size: "23sp"
            pos_hint: {"center_y": .38}
            halign: "center"
            color: rgba(34, 34, 34, 255)
        MDLabel:
            text: "The most secure chat app available."
            font_name: "BPoppins"
            font_size: "13sp"
            size_hint_x: .85
            pos_hint: {"center_x": .5, "center_y": .3}
            halign: "center"
            color: rgba(127, 127, 127, 255)
        Button:
            text: "LOGIN"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .18}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "login"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
        Button:
            text: "SIGNUP"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .09}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            color: rgba(52, 0, 231, 255)
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "signup"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                Line:
                    width: 1.2
                    rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

"""
group_create = """
MDScreen:
    name: "group_create"
    name_: name_
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "right"
                root.manager.current = "home"
        MDLabel:
            text: "Group"
            font_name: "BPoppins"
            font_size: "26sp"
            pos_hint: {"center_x": .6, "center_y": .85}
            color: rgba(0, 0, 59, 255)

        MDLabel:
            text: "Create a group"
            font_name: "BPoppins"
            font_size: "18sp"
            pos_hint: {"center_x": .6, "center_y": .79}
            color: rgba(135, 133, 193, 255)
        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .63}
            TextInput:
                id: name_
                hint_text: "Group Name"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        Button:
            text: "Create"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .34}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
            on_release:
                app.create_group(name_.text)


"""
group_join = """
MDScreen:
    name: "group_join"
    group_list: group_list
    ok: ok
    group_num: group_num
    butt: butt

    MDLabel:
        text: "Groups"
        font_name: "BPoppins"
        font_size: "26sp"
        pos_hint: {"center_x": .8, "center_y": .9}
        color: rgba(0, 0, 59, 255)

    MDIconButton:
        icon: "arrow-left"
        pos_hint: {"center_y": .95}
        user_font_size: "30sp"
        theme_text_color: "Custom"
        text_color: rgba(26, 24, 58, 255)
        on_release:
            root.manager.transition.direction = "right"
            root.manager.current = "home"

    MDLabel:
        id: ok
        pos_hint: {"center_x": .5, "center_y": .7}
        halign: "center"

    ScrollView:
        size_hint_y: .6
        pos_hint: {"x": 0, "y": .116}
        do_scroll_x: False
        do_scroll_y: True
        BoxLayout:
            id: group_list
            orientation: "vertical"
            size: (root.width, root.height)
            height: self.minimum_height
            size_hint: None, None
            pso_hint: {"top": 10}
            cols: 1
            spacing: 5
            size_hint_y: None
            pos_hint: {"x": .02}
            padding: 12, 10

    MDFloatLayout:
        md_bg_color: 245/255, 245/255, 245/255, 1
        size_hint_y: .11
        MDFloatLayout:
            size_hint: .7, .60
            pos_hint: {"center_x": .45, "center_y": .5}
            canvas:
                Color:
                    rgb: (238/255, 238/255, 238/255, 1)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [23, 23, 23, 23]
            TextInput:
                input_filter: "int"
                id: group_num
                hint_text: "Enter group number"
                size_hint: 1, None
                pos_hint: {"center_x": .5, "center_y": .5}
                font_size: "12sp"
                height: self.minimum_height
                multiline: False
                cursor_color: 1, 170/255, 23/255, 1
                cursor_width: "2sp"
                foreground_color: 1, 170/255, 23/255, 1
                background_color: 0, 0, 0, 0
                padding: 15
                font_name: "BPoppins"
        MDIconButton:
            id: butt
            icon: "send"
            pos_hint: {"center_x": .91, "center_y": .5}
            user_font_size: "18sp"
            theme_text_color: "Custom"
            text_color: 0, 0, 0, 1
            #foreground_color: rgba(0, 0, 0, 1)
            #md_bg_color: rgba(52, 0, 231, 255)
            on_release:
                app.join_group(group_num.text)



    Button:
        text: "New"
        size_hint: .3, .065
        pos_hint: {"center_x": .7, "center_y": .8}
        background_color: 0, 0, 0, 0
        front_name: "BPoppins"
        canvas.before:
            Color:
                rgb: rgba(52, 0, 231, 255)
            RoundedRectangle:
                size: self.size
                pos: self.pos
                radius: [5]
        on_release:
            root.manager.transition.direction = "left"
            root.manager.current = "new_group_join"
    Button:
        text: "Load"
        size_hint: .3, .065
        pos_hint: {"center_x": .3, "center_y": .8}
        background_color: 0, 0, 0, 0
        front_name: "BPoppins"
        canvas.before:
            Color:
                rgb: rgba(52, 0, 231, 255)
            RoundedRectangle:
                size: self.size
                pos: self.pos
                radius: [5]
        on_release:
            app.load_groups()
"""
group = """
#: import get_color_from_hex kivy.utils.get_color_from_hex

MDScreen:
    name: "group"
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1


        MDBottomAppBar:
            title: 'Bottom navigation'
            md_bg_color: .2, .2, .2, 1
            specific_text_color: 1, 1, 1, 1

        MDBottomNavigation:
            panel_color: 1, 1, 1, 1

            MDBottomNavigationItem:
                name: "home"
                text: "Home"
                icon: "home"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "home"

                MDLabel:
                    text: "Group Chat"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Join a Group"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "group_join"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Create a Group"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "group_create"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

                MDIconButton:
                    icon: "logout"
                    pos_hint: {"center_x": .9, "center_y": .05}
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "main"


            MDBottomNavigationItem:
                name: "test"
                text: "Chats"
                icon: "chat"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    text: "Chats"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Start chatting"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Create new chat"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

            MDBottomNavigationItem:
                name: "test2"
                text: "Settings"
                icon: "account-settings"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"


            MDBottomNavigationItem:
                name: "test3"
                text: "Help"
                icon: "help-circle"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    text: "Help Center"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Help Center"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Error?"
                    font_name: "BPoppins"
                    font_size: "15sp"
                    pos_hint: {"center_y": .7}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Coming soon..."
                    font_name: "BPoppins"
                    font_size: "18sp"
                    pos_hint: {"center_x": .6, "center_y": .65}
                    color: rgba(135, 133, 193, 255)
                MDLabel:
                    text: "Feedback"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .6}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Bugs"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .5}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)




"""
help_ = """#: import get_color_from_hex kivy.utils.get_color_from_hex

MDScreen:
    name: "help"
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1


        MDBottomAppBar:
            title: 'Bottom navigation'
            md_bg_color: .2, .2, .2, 1
            specific_text_color: 1, 1, 1, 1

        MDBottomNavigation:
            panel_color: 1, 1, 1, 1

            MDBottomNavigationItem:
                name: "home"
                text: "Home"
                icon: "home"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    id: welcome_name
                    text: "Welcome ProtDos"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Start chatting"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Create a Group"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "group"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Join a Group"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .45}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "group"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Settings"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .35}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "settings"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Personal"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .25}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "personal"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

                MDIconButton:
                    icon: "logout"
                    pos_hint: {"center_x": .9, "center_y": .05}
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "main"


            MDBottomNavigationItem:
                name: "test"
                text: "Chats"
                icon: "chat"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    text: "Chats"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Start chatting"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Create new chat"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

            MDBottomNavigationItem:
                name: "test2"
                text: "Settings"
                icon: "account-settings"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"


            MDBottomNavigationItem:
                name: "test3"
                text: "Help"
                icon: "help-circle"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    text: "Help Center"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Help Center"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Error?"
                    font_name: "BPoppins"
                    font_size: "15sp"
                    pos_hint: {"center_y": .7}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Coming soon..."
                    font_name: "BPoppins"
                    font_size: "18sp"
                    pos_hint: {"center_x": .6, "center_y": .65}
                    color: rgba(135, 133, 193, 255)
                MDLabel:
                    text: "Feedback"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .6}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Bugs"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .5}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)



"""
new_group_join = """
MDScreen:
    name: "new_group_join"
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "right"
                root.manager.current = "home"
        MDLabel:
            text: "Group"
            font_name: "BPoppins"
            font_size: "26sp"
            pos_hint: {"center_x": .6, "center_y": .85}
            color: rgba(0, 0, 59, 255)

        MDLabel:
            text: "Join a group"
            font_name: "BPoppins"
            font_size: "18sp"
            pos_hint: {"center_x": .6, "center_y": .79}
            color: rgba(135, 133, 193, 255)
        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .63}
            TextInput:
                id: name
                hint_text: "Group Key"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        Button:
            text: "Join"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .34}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
            on_release:
                app.join_new_group(name.text)


"""
password_reset = """
MDScreen:
    name: "password_reset"
    username: username
    password: password
    password2: password

    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "right"
                root.manager.current = "main"
        MDLabel:
            text: "Reset!"
            font_name: "BPoppins"
            font_size: "26sp"
            pos_hint: {"center_x": .6, "center_y": .85}
            color: rgba(0, 0, 59, 255)

        MDLabel:
            text: "The only way to use the app, is to create a new account. All your data you have is lost."
            font_name: "BPoppins"
            font_size: "17sp"
            pos_hint: {"center_x": .55, "center_y": .74}
            color: rgba(135, 133, 193, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .60}
            TextInput:
                id: username
                hint_text: "Username"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .48}
            TextInput:
                id: password
                hint_text: "Password"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
                password: True
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .36}
            TextInput:
                id: password2
                hint_text: "Retype Password"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
                password: True
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)
        Button:
            text: "SIGN UP"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .22}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
            on_release:
                app.sign_up(username.text, password.text, password2.text)
        MDLabel:
            text: "Already have an account?"
            font_name: "BPoppins"
            font_size: "11sp"
            pos_hint: {"center_x": .68, "center_y": .15}
            color: rgba(135, 133, 193, 255)
        MDTextButton:
            text: "Login"
            font_name: "BPoppins"
            font_size: "11sp"
            pos_hint: {"center_x": .79, "center_y": .15}
            color: rgba(135, 133, 193, 255)
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "login"

"""
personal = """
#: import get_color_from_hex kivy.utils.get_color_from_hex

MDScreen:
    name: "personal"
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1


        MDBottomAppBar:
            title: 'Bottom navigation'
            md_bg_color: .2, .2, .2, 1
            specific_text_color: 1, 1, 1, 1

        MDBottomNavigation:
            panel_color: 1, 1, 1, 1

            MDBottomNavigationItem:
                name: "home"
                text: "Home"
                icon: "home"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    id: welcome_name
                    text: "Welcome ProtDos"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Start chatting"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Create a Group"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "group"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Join a Group"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .45}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "group"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Settings"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .35}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "settings"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100
                Button:
                    text: "Personal"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .25}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "personal"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

                MDIconButton:
                    icon: "logout"
                    pos_hint: {"center_x": .9, "center_y": .05}
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "main"


            MDBottomNavigationItem:
                name: "test"
                text: "Chats"
                icon: "chat"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    text: "Chats"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                Button:
                    text: "Start chatting"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .65}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        RoundedRectangle:
                            size: self.size
                            pos: self.pos
                            radius: [5]
                Button:
                    text: "Create new chat"
                    size_hint: .66, .065
                    pos_hint: {"center_x": .5, "center_y": .55}
                    background_color: 0, 0, 0, 0
                    front_name: "BPoppins"
                    color: rgba(52, 0, 231, 255)
                    on_release:
                        root.manager.transition.direction = "left"
                        root.manager.current = "chat"
                    canvas.before:
                        Color:
                            rgb: rgba(52, 0, 231, 255)
                        Line:
                            width: 1.2
                            rounded_rectangle: self.x, self.y, self.width, self.height, 5, 5, 5, 5, 100

            MDBottomNavigationItem:
                name: "test2"
                text: "Settings"
                icon: "account-settings"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"


            MDBottomNavigationItem:
                name: "test3"
                text: "Help"
                icon: "help-circle"

                MDIconButton:
                    icon: "arrow-left"
                    pos_hint: {"center_y": .95}
                    user_font_size: "30sp"
                    theme_text_color: "Custom"
                    text_color: rgba(26, 24, 58, 255)
                    on_release:
                        root.manager.transition.direction = "right"
                        root.manager.current = "main"

                MDLabel:
                    text: "Help Center"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Help Center"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .8}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Error?"
                    font_name: "BPoppins"
                    font_size: "15sp"
                    pos_hint: {"center_y": .7}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Coming soon..."
                    font_name: "BPoppins"
                    font_size: "18sp"
                    pos_hint: {"center_x": .6, "center_y": .65}
                    color: rgba(135, 133, 193, 255)
                MDLabel:
                    text: "Feedback"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .6}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)
                MDLabel:
                    text: "Bugs"
                    font_name: "BPoppins"
                    font_size: "23sp"
                    pos_hint: {"center_y": .5}
                    halign: "center"
                    color: rgba(34, 34, 34, 255)




"""
signup = """
MDScreen:
    name: "signup"
    username: username
    password: password
    password2: password2
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "right"
                root.manager.current = "main"
        MDLabel:
            text: "H i !"
            font_name: "BPoppins"
            font_size: "26sp"
            pos_hint: {"center_x": .6, "center_y": .85}
            color: rgba(0, 0, 59, 255)

        MDLabel:
            text: "Create a new account"
            font_name: "BPoppins"
            font_size: "18sp"
            pos_hint: {"center_x": .6, "center_y": .79}
            color: rgba(135, 133, 193, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .68}
            TextInput:
                id: username
                hint_text: "Username"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .56}
            TextInput:
                id: password
                hint_text: "Password"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
                password: True
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .44}
            TextInput:
                id: password2
                hint_text: "Retype Password"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
                password: True
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)
        Button:
            text: "SIGN UP"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .34}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
            on_release:
                app.sign_up(username.text, password.text, password2.text)
        MDTextButton:
            text: "Forgot Password?"
            pos_hint: {"center_x": .5, "center_y": .28}
            color: rgba(68, 78, 132, 255)
            font_size: "12sp"
            font_name: "BPoppins"
        MDLabel:
            text: "Already have an account?"
            font_name: "BPoppins"
            font_size: "11sp"
            pos_hint: {"center_x": .68, "center_y": .2}
            color: rgba(135, 133, 193, 255)
        MDTextButton:
            text: "Login"
            font_name: "BPoppins"
            font_size: "11sp"
            pos_hint: {"center_x": .79, "center_y": .2}
            color: rgba(135, 133, 193, 255)
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "login"

"""
show_id = """
MDScreen:
    name: "show_id"
    img: img

    MDFloatLayout:
        MDFloatLayout:
            md_bg_color: 245/255, 245/255, 245/255, 1
            size_hint_y: .11
            pos_hint: {"center_y": .95}
            MDIconButton:
                icon: "arrow-left"
                pos_hint: {"center_y": .5}
                user_font_size: "30sp"
                theme_text_color: "Custom"
                text_color: rgba(26, 24, 58, 255)
                on_release:
                    root.manager.transition.direction = "right"
                    root.manager.current = "home"
        MDLabel:
            text: "Your Personal ID"
            font_name: "BPoppins"
            font_size: "23sp"
            pos_hint: {"center_y": .8}
            halign: "center"
            color: rgba(34, 34, 34, 255)
        MDLabel:
            text: "Let others scan it to contact you. Your ID is also copied to your clipboard."
            font_name: "BPoppins"
            font_size: "13sp"
            size_hint_x: .85
            pos_hint: {"center_x": .5, "center_y": .3}
            halign: "center"
            color: rgba(127, 127, 127, 255)
        Image:
            id: img
            source: "qr_code_id.png"
            size_hint: (None, None)
            size: 200, 200
            pos_hint: {"center_y": .55, "center_x": .5}
"""
show_id2 = """
MDScreen:
    name: "show_qr"
    img: img

    MDFloatLayout:
        MDFloatLayout:
            md_bg_color: 245/255, 245/255, 245/255, 1
            size_hint_y: .11
            pos_hint: {"center_y": .95}
            MDIconButton:
                icon: "arrow-left"
                pos_hint: {"center_y": .5}
                user_font_size: "30sp"
                theme_text_color: "Custom"
                text_color: rgba(26, 24, 58, 255)
                on_release:
                    root.manager.transition.direction = "right"
                    root.manager.current = "chat"
        MDLabel:
            text: "Your QR-Code"
            font_name: "BPoppins"
            font_size: "23sp"
            pos_hint: {"center_y": .8}
            halign: "center"
            color: rgba(34, 34, 34, 255)
        MDLabel:
            text: "Let others scan it to get the key. The key is also copied to your clipboard."
            font_name: "BPoppins"
            font_size: "13sp"
            size_hint_x: .85
            pos_hint: {"center_x": .5, "center_y": .3}
            halign: "center"
            color: rgba(127, 127, 127, 255)
        Image:
            id: img
            source: "qr_code.png"
            size_hint: (None, None)
            size: 200, 200
            pos_hint: {"center_y": .55, "center_x": .5}
"""
show_qr2 = """
MDScreen:
    name: "show_qr2"
    img: img

    MDFloatLayout:
        MDFloatLayout:
            md_bg_color: 245/255, 245/255, 245/255, 1
            size_hint_y: .11
            pos_hint: {"center_y": .95}
            MDIconButton:
                icon: "arrow-left"
                pos_hint: {"center_y": .5}
                user_font_size: "30sp"
                theme_text_color: "Custom"
                text_color: rgba(26, 24, 58, 255)
                on_release:
                    root.manager.transition.direction = "right"
                    root.manager.current = "chat_sec"
        MDLabel:
            text: "Your QR-Code"
            font_name: "BPoppins"
            font_size: "23sp"
            pos_hint: {"center_y": .8}
            halign: "center"
            color: rgba(34, 34, 34, 255)
        MDLabel:
            text: "Let others scan it to get the key. The key is also copied to your clipboard."
            font_name: "BPoppins"
            font_size: "13sp"
            size_hint_x: .85
            pos_hint: {"center_x": .5, "center_y": .3}
            halign: "center"
            color: rgba(127, 127, 127, 255)
        Image:
            id: img
            source: "qr_code.png"
            size_hint: (None, None)
            size: 200, 200
            pos_hint: {"center_y": .55, "center_x": .5}
"""
chat_new_private = """
MDScreen:
    name: "chat_new_private"
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "right"
                root.manager.current = "home"
        MDLabel:
            text: "Chat"
            font_name: "BPoppins"
            font_size: "26sp"
            pos_hint: {"center_x": .6, "center_y": .85}
            color: rgba(0, 0, 59, 255)

        MDLabel:
            text: "Join a private chat"
            font_name: "BPoppins"
            font_size: "18sp"
            pos_hint: {"center_x": .6, "center_y": .79}
            color: rgba(135, 133, 193, 255)
        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .63}
            TextInput:
                id: name
                hint_text: "Recipient"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        MDFloatLayout:
            size_hint: .7, .07
            pos_hint: {"center_x": .5, "center_y": .53}
            TextInput:
                id: key
                hint_text: "Key"
                font_name: "MPoppins"
                size_hint_y: .75
                pos_hint: {"center_x": .43, "center_y": .5}
                background_color: 1, 1, 1, 0
                foreground_color: rgba(0, 0, 59, 255)
                cursor_color: rgba(0, 0, 59, 255)
                font_size: "14sp"
                cursor_width: "2sp"
                multiline: False
            MDFloatLayout:
                pos_hint: {"center_x": .45, "center_y": 0}
                size_hint_y: .03
                md_bg_color: rgba(178, 178, 178, 255)

        Button:
            text: "Chat"
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .34}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]
            on_release:
                app.join_chat(name.text, key.text)


"""
chat_load = """
MDScreen:
    name: "chat_load"
    group_list: group_list
    ok: ok
    group_num: group_num
    butt: butt

    MDLabel:
        text: "Groups"
        font_name: "BPoppins"
        font_size: "26sp"
        pos_hint: {"center_x": .8, "center_y": .9}
        color: rgba(0, 0, 59, 255)

    MDIconButton:
        icon: "arrow-left"
        pos_hint: {"center_y": .95}
        user_font_size: "30sp"
        theme_text_color: "Custom"
        text_color: rgba(26, 24, 58, 255)
        on_release:
            root.manager.transition.direction = "right"
            root.manager.current = "home"

    MDLabel:
        id: ok
        pos_hint: {"center_x": .5, "center_y": .7}
        halign: "center"

    ScrollView:
        size_hint_y: .6
        pos_hint: {"x": 0, "y": .116}
        do_scroll_x: False
        do_scroll_y: True
        BoxLayout:
            id: group_list
            orientation: "vertical"
            size: (root.width, root.height)
            height: self.minimum_height
            size_hint: None, None
            pso_hint: {"top": 10}
            cols: 1
            spacing: 5
            size_hint_y: None
            pos_hint: {"x": .02}
            padding: 12, 10

    MDFloatLayout:
        md_bg_color: 245/255, 245/255, 245/255, 1
        size_hint_y: .11
        MDFloatLayout:
            size_hint: .7, .60
            pos_hint: {"center_x": .45, "center_y": .5}
            canvas:
                Color:
                    rgb: (238/255, 238/255, 238/255, 1)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [23, 23, 23, 23]
            TextInput:
                input_filter: "int"
                id: group_num
                hint_text: "Enter group number"
                size_hint: 1, None
                pos_hint: {"center_x": .5, "center_y": .5}
                font_size: "12sp"
                height: self.minimum_height
                multiline: False
                cursor_color: 1, 170/255, 23/255, 1
                cursor_width: "2sp"
                foreground_color: 1, 170/255, 23/255, 1
                background_color: 0, 0, 0, 0
                padding: 15
                font_name: "BPoppins"
        MDIconButton:
            id: butt
            icon: "send"
            pos_hint: {"center_x": .91, "center_y": .5}
            user_font_size: "18sp"
            theme_text_color: "Custom"
            text_color: 0, 0, 0, 1
            #foreground_color: rgba(0, 0, 0, 1)
            #md_bg_color: rgba(52, 0, 231, 255)
            on_release:
                app.join_group(group_num.text)



    Button:
        text: "New"
        size_hint: .3, .065
        pos_hint: {"center_x": .7, "center_y": .8}
        background_color: 0, 0, 0, 0
        front_name: "BPoppins"
        canvas.before:
            Color:
                rgb: rgba(52, 0, 231, 255)
            RoundedRectangle:
                size: self.size
                pos: self.pos
                radius: [5]
        on_release:
            root.manager.transition.direction = "left"
            root.manager.current = "new_group_join"
    Button:
        text: "Load"
        size_hint: .3, .065
        pos_hint: {"center_x": .3, "center_y": .8}
        background_color: 0, 0, 0, 0
        front_name: "BPoppins"
        canvas.before:
            Color:
                rgb: rgba(52, 0, 231, 255)
            RoundedRectangle:
                size: self.size
                pos: self.pos
                radius: [5]
        on_release:
            app.load_groups()
"""
chat = """
#:import Clipboard kivy.core.clipboard.Clipboard
<Command>
    size_hint_y: None
    pos_hint: {"right": .98}
    height: self.texture_size[1]
    padding: 12, 10
    theme_text_color: "Custom"
    text_color: 1, 1, 1, 1
    canvas.before:
        Color:
            rgb: rgba(52, 0, 234, 255)
        RoundedRectangle:
            size: self.width, self.height
            pos: self.pos
            radius: [23, 23, 0, 23]
    on_touch_down:
        app.message_click()
<Response>
    size_hint_y: None
    pos_hint: {"x": .02}
    #height: self.texture_size[1]
    padding: 12, 10
    canvas.before:
        Color:
            rgb: (1, 1, 1, 1)
        RoundedRectangle:
            size: self.width, self.height
            pos: self.pos
            radius: [23, 23, 23, 0]
    BoxLayout:
        orientation: 'vertical'
        padding: 0
        Label:
            text: root.fro
            font_size: 12
            color: (0, 0, 1, 1)
            halign: 'left'
            size_hint_x: .22
        MDLabel:
            text: root.text
            font_size: 12
            halign: "center"
MDScreen:
    name: "chat"
    kkk: kkk
    bot_name: bot_name
    chat_list: chat_list
    text_input: text_input

    MDFloatLayout:
        MDFloatLayout:
            md_bg_color: 245/255, 245/255, 245/255, 1
            size_hint_y: .11
            pos_hint: {"center_y": .95}
            MDIconButton:
                icon: "arrow-left"
                pos_hint: {"center_y": .5}
                user_font_size: "30sp"
                theme_text_color: "Custom"
                text_color: rgba(26, 24, 58, 255)
                on_release:
                    root.manager.transition.direction = "right"
                    root.manager.current = "home"
            MDIconButton:
                icon: "content-copy"
                pos_hint: {"center_x": .9, "center_y": .5}
                on_release:
                    Clipboard.copy(kkk.text)
                    app.show_qr_code(kkk.text)

            MDLabel:
                text: ""
                id: bot_name
                pos_hint: {"center_y": .5}
                halign: "center"
                font_name: "BPoppins"
                font_size: "25sp"
                theme_text_color: "Custom"
                text_color: 53/255, 56/255, 60/255, 1
            MDLabel:
                text: ""
                id: kkk
                pos_hint: {"center_y": .5}
                halign: "center"
                font_name: "BPoppins"
                font_size: "0sp"
                theme_text_color: "Custom"
                text_color: 53/255, 56/255, 60/255, 1
                opacity: 0




        ScrollView:
            size_hint_y: .77
            pos_hint: {"x": 0, "y": .116}
            do_scroll_x: False
            do_scroll_y: True
            BoxLayout:
                id: chat_list
                orientation: "vertical"
                size: (root.width, root.height)
                height: self.minimum_height
                size_hint: None, None
                pso_hint: {"top": 10}
                cols: 1
                spacing: 5
        MDFloatLayout:
            md_bg_color: 245/255, 245/255, 245/255, 1
            size_hint_y: .11
            MDFloatLayout:
                size_hint: .7, .60
                pos_hint: {"center_x": .45, "center_y": .5}
                canvas:
                    Color:
                        rgb: (238/255, 238/255, 238/255, 1)
                    RoundedRectangle:
                        size: self.size
                        pos: self.pos
                        radius: [23, 23, 23, 23]
                TextInput:
                    id: text_input
                    hint_text: "Type something..."
                    size_hint: 1, None
                    pos_hint: {"center_x": .5, "center_y": .5}
                    font_size: "12sp"
                    height: self.minimum_height
                    multiline: False
                    cursor_color: 1, 170/255, 23/255, 1
                    cursor_width: "2sp"
                    foreground_color: 1, 170/255, 23/255, 1
                    background_color: 0, 0, 0, 0
                    padding: 15
                    font_name: "BPoppins"
            MDIconButton:
                icon: "send"
                pos_hint: {"center_x": .91, "center_y": .5}
                user_font_size: "18sp"
                theme_text_color: "Custom"
                text_color: 0, 0, 0, 1
                #foreground_color: rgba(0, 0, 0, 1)
                #md_bg_color: rgba(52, 0, 231, 255)
                on_release:
                    app.send_message_aaa(text_input.text, kkk.text)
            MDIconButton:
                icon: "file-upload"
                pos_hint: {"center_x": .8, "center_y": .5}
                user_font_size: "18sp"
                theme_text_color: "Custom"
                text_color: 0, 0, 0, 1
                #md_bg_color: rgba(52, 0, 231, 255)
                on_release:
                    app.file_chooser(kkk.text)

"""
bad = """
MDScreen:
    name: "bad"
    MDFloatLayout:
        md_bg_color: 1, 1, 1, 1
        MDIconButton:
            icon: "arrow-left"
            pos_hint: {"center_y": .95}
            user_font_size: "30sp"
            theme_text_color: "Custom"
            text_color: rgba(26, 24, 58, 255)
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "main"
        MDLabel:
            text: "Ooops..."
            font_name: "BPoppins"
            font_size: "23sp"
            pos_hint: {"center_y": .8}
            halign: "center"
            color: rgba(34, 34, 34, 255)
        MDLabel:
            text: "The credentials you entered are not valid."
            font_name: "BPoppins"
            font_size: "13sp"
            size_hint_x: .85
            pos_hint: {"center_x": .5, "center_y": .7}
            halign: "center"
            color: rgba(127, 127, 127, 255)
        Button:
            text: "Go back."
            size_hint: .66, .065
            pos_hint: {"center_x": .5, "center_y": .3}
            background_color: 0, 0, 0, 0
            front_name: "BPoppins"
            on_release:
                root.manager.transition.direction = "left"
                root.manager.current = "login"
            canvas.before:
                Color:
                    rgb: rgba(52, 0, 231, 255)
                RoundedRectangle:
                    size: self.size
                    pos: self.pos
                    radius: [5]


"""


# Window.size = (310, 580)

group_key = ""
user = ""

current_private_key = b""
current_chat_with = ""

is_it_my_turn = False


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


class ChatApp(MDApp):

    def change_screen(self, name):
        self.screen_manager.current = name

    def build(self):
        self.screen_manager = ScreenManager()
        self.screen_manager.add_widget(Builder.load_string(login))
        self.screen_manager.add_widget(Builder.load_string(home))
        self.screen_manager.add_widget(Builder.load_string(chat_private))
        self.screen_manager.add_widget(Builder.load_string(chat_sec))
        self.screen_manager.add_widget(Builder.load_string(main))
        self.screen_manager.add_widget(Builder.load_string(group_create))
        self.screen_manager.add_widget(Builder.load_string(group_join))
        self.screen_manager.add_widget(Builder.load_string(group))
        self.screen_manager.add_widget(Builder.load_string(password_reset))
        self.screen_manager.add_widget(Builder.load_string(chat_new_private))
        self.screen_manager.add_widget(Builder.load_string(signup))
        self.screen_manager.add_widget(Builder.load_string(help_))
        self.screen_manager.add_widget(Builder.load_string(chat_load))
        self.screen_manager.add_widget(Builder.load_string(personal))
        self.screen_manager.add_widget(Builder.load_string(bad))
        self.screen_manager.add_widget(Builder.load_string(new_group_join))
        self.screen_manager.add_widget(Builder.load_string(show_id2))
        self.screen_manager.add_widget(Builder.load_string(show_qr2))
        self.screen_manager.add_widget(Builder.load_string(show_id))
        self.screen_manager.add_widget(Builder.load_string(chat))

        return self.screen_manager


if __name__ == "__main__":
    LabelBase.register(name="MPoppins",
                       fn_regular="Poppins-Medium.ttf")
    LabelBase.register(name="BPoppins",
                       fn_regular="Poppins-SemiBold.ttf")
    ChatApp().run()
