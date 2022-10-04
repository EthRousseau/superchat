import json
import logging
import os
import socket
import sys
import threading
import traceback
from datetime import datetime
from datetime import timedelta
from time import sleep, time

import PySimpleGUI as gooey

console_height = 40
console_width = 80

gp = gooey.cprint


class server_communications_thread(threading.Thread):

    def __init__(self, user_socket):
        threading.Thread.__init__(self)
        self.user_socket = user_socket
        self.user_socket.setblocking(True)
        self.lock = threading.Lock()
        self.response_set = threading.Event()
        self.message_set = threading.Event()
        self.response = None
        self.username = None
        self.active_chat = None
        self.active_chat_users = []
        self.active_user_box = None
        self.update_buffer = []
        self.chat_histories = {}
        self.printer_thread = None

    def run(self):
        while True:
            message = self.wait_for_message()
            if not message:  # If the server gives an empty response, exit
                self.response = None
                self.response_set.set()
                break

            if (message_type := message.get('message_type')) == None:  # Is a response
                self.response = message
                self.response_set.set()
                if message.get('status') == 'leftchat':
                    break
                else:
                    continue

            if message['chat_id'] != self.active_chat:
                continue

            if message_type in ["standard", "add_user", "remove_user", "user_join", "user_leave"]:
                if DO_DEBUG:
                    print("DEBUG: GOT NEW CHAT MESSAGE")
                with self.lock:
                    self.update_buffer.append(message)
                    self.message_set.set()

    def wait_for_message(self):
        while True:
            try:
                message_len_encoded = self.user_socket.recv(8)
                break
            except socket.timeout:
                continue
        bytes_to_read = int.from_bytes(message_len_encoded, 'big')
        if not isinstance(bytes_to_read, int):
            raise Exception("Did not get INT for length of incoming message")
        new_message = ""
        if DO_DEBUG:
            print(f"DEBUG: BEGINNING TO READ MESSAGE OF {bytes_to_read} BYTES")
        while bytes_to_read > 0:
            incoming_bytes = self.user_socket.recv(bytes_to_read)
            new_message += incoming_bytes.decode()
            bytes_to_read -= len(incoming_bytes)
        if DO_DEBUG:
            print(f"DEBUG: READ {new_message} OF LEN {len(new_message)}")
        if not new_message:
            return None
        return json.loads(new_message)

    def send_to_server(self, payload):
        if self.user_socket:
            json_string = json.dumps(payload)
            encoded_msg = json_string.encode()
            message_len = len(encoded_msg)
            message_len_bytes = message_len.to_bytes(8, 'big')

            full_message = message_len_bytes + encoded_msg

            if DO_DEBUG:
                print(
                    f"DEBUG: SENDING {json_string} ({message_len} BYTES). HEADER: {message_len_bytes} ({len(message_len_bytes)} BYTES)")
            with self.lock:
                self.user_socket.sendall(full_message)

        response = self.get_response()
        return response

    def get_response(self):
        self.response_set.wait()
        response = self.response
        self.response_set.clear()
        return response

    def dequeue_update_buffer(self, window):
        while self.active_chat != None:
            self.message_set.wait()
            with self.lock:
                while self.update_buffer:
                    top_message = self.update_buffer.pop(0)
                    if top_message['historical'] == True:
                        self.chat_histories[self.active_chat][top_message['message_id']] = top_message
                    self.print_message(top_message, window)
            self.message_set.clear()

    # 'user' is the user that should be added or removed from the active users list.
    # 'add_user' is only used when user is passed. A True value means that user will be added to the list, if not found in list,
    # and false means user will be removed if they are.
    #
    # If user is not passed, it will simply load 'self.active_chat_users' into the window,
    # this most likely will do nothing unless active_chat_users has been modified elsewhere
    def update_active_users(self, window, user=None, add_user=False):
        if user:
            if add_user == True and user not in self.active_chat_users:
                self.active_chat_users.append(user)
            elif add_user == False and user in self.active_chat_users:
                self.active_chat_users.remove(user)

        # Build active users string from active users list, and send it to the window
        if len(self.active_chat_users) > 0:
            active_users_string = "Online: " + ",".join([username for username in self.active_chat_users])
        else:
            active_users_string = "It's just you here..."
        window['active_users'].update(active_users_string)

    def print_message(self, message, window):
        if DO_DEBUG:
            print(f"{message}")
        else:
            message_type = message['message_type']
            if message_type == "user_join":
                self.update_active_users(window, user=message['about_user'], add_user=True)
            elif message_type == "user_leave":
                self.update_active_users(window, user=message['about_user'], add_user=False)
            print(message)
            timestamp = int(message['timestamp'])
            datetime_timestamp = datetime.fromtimestamp(timestamp)
            time_string = "at " + datetime.strftime(datetime_timestamp, "%-I:%M %p")
            if (days_ago := (datetime.today().date() - datetime_timestamp.date()).days) == 0:
                date_string = "Today "
            elif days_ago == 1:
                date_string = "Yesterday "
            elif days_ago <= 5:
                date_string = str(days_ago) + "days ago "
            else:
                date_string = "On " + datetime.strftime(datetime_timestamp, "%b %-m")

            full_time_string = date_string + time_string

            if message_type == "standard":
                text = message['text']
                sender = message['sender']
                prev_message = self.chat_histories[self.active_chat][message['message_id'] - 1]
                prev_sender = prev_message['sender']
                prev_timestamp = prev_message['timestamp']
                should_print_time = not prev_sender == sender or timedelta(
                    seconds=(timestamp - prev_timestamp)) > timedelta(minutes=5)

                if sender == self.username:
                    if should_print_time:
                        gp(f"\nYou {full_time_string}", justification='r', font='Consolas 10')
                    gp(f"{text}", justification='r')
                else:
                    if should_print_time:
                        gp(f"\n{sender} {full_time_string}", justification='l', font='Consolas 10')
                    gp(f"{text}", justification='l')

            elif message_type == "add_user":
                gp(f"\n{full_time_string}", justification='c', font='Consolas 10')
                gp(f"{'[' + message['about_user'] + ' has been added to this chat!]'}", justification='c')
            elif message_type == "remove_user":
                gp(f"\n{full_time_string}", justification='c', font='Consolas 10')
                gp(f"{'[' + message['about_user'] + ' has been removed from this chat]'}", justification='c')
            elif message_type == "newchat":
                gp(f"\n{full_time_string}", justification='c', font='Consolas 10')
                gp(f"{'[This is the beginning of ' + str(message['chat_name']) + '! Go nuts!]'}", justification='c')

    # Mega "set state" function for loading the environment to do live chatting
    def load_chat(self, chat_id):
        # Notify server that client is loading chat
        new_chat_state = {
            "endpoint": 'change_active_chat',
            "chat_id": chat_id
        }
        response = self.send_to_server(new_chat_state)
        if response['status'] == 'joinedchat':
            # TODO, server returns the ID of the most up to date message.
            # This can be used to check if a reuqest for newer messages is required
            latest_message_server = response['newest_message']
            chat_name = response['chat_name']
        else:
            return None  # Server did not authenticate the chat join

        # Part of TODO above, only get needed chat history instead of the whole thing every time
        payload = {
            "endpoint": 'chat_history',
            "method": 'GET',
            "chat_id": chat_id,
            "last_message_id": -1  # TODO placeholder while not storing local message history
        }
        response = self.send_to_server(payload)
        with self.lock:
            self.update_buffer.extend(response['messages'])  # Load up the buffer with "new" (TODO) messages
            self.message_set.set()  # Initial unblock for printer thread
        if not self.chat_histories.get(chat_id):
            self.chat_histories[chat_id] = {}
        # Request list of users that are currently in this chat
        payload = {
            "endpoint": 'get_active_users',
            "chat_id": chat_id
        }
        response = self.send_to_server(payload)
        self.active_chat_users = response['active_users']

        # Set local active chat
        self.active_chat = chat_id
        if DO_DEBUG:
            print(f"DEBUG: SET ACTIVE CHAT TO #{chat_id}")

        # Load gooey friend
        if not DO_DEBUG:
            window = self.load_gooey(chat_name)  # Get the window
        else:
            window = None  # Don't get the window... I'm sure this was clear

        self.update_active_users(window=window)  # Write the up-to-date active user list to the window

        # Start printer function, this will start printing right on the "start" line, so everything must be ready by this point
        self.printer_thread = threading.Thread(target=self.dequeue_update_buffer, args=[window])
        self.printer_thread.start()

        return window

    def load_gooey(self, chat_name):
        gooey.theme('DarkGrey14')
        layout = [[gooey.Text(f'Welcome to {chat_name}!', font='Consolas 25'), gooey.Button('Exit')],
                  [gooey.Multiline(size=(console_width, console_height), key='-ML-', autoscroll=False,
                                   auto_refresh=True, write_only=True, reroute_cprint=True, font='Consolas 20')],
                  [gooey.Input(key='user_input', size=(console_width, 1),
                               do_not_clear=False, font='Consolas 20'), gooey.Button('Send')],
                  [gooey.StatusBar('', key='active_users', size=(20, 1), justification='l', font='Consolas 15')]]
        window = gooey.Window('superchat v0.1', layout, finalize=True)
        window['user_input'].bind("<Return>", "_Enter")
        return window

    def leave_chat(self):
        self.active_chat = None
        self.active_user_box = None
        self.message_set.set()
        self.printer_thread.join()
        new_chat_state = {
            "endpoint": 'change_active_chat',
            "chat_id": None
        }
        response = self.send_to_server(new_chat_state)


class User:

    def __init__(self, host=None, port=None):
        # Default Port
        if not port:
            port = 8000
        # Default Host
        if not host:
            host = "localhost"
        self.port = int(port)
        self.host = host

    def do_chat(self, chat_id):
        window = self.comm_thread.load_chat(chat_id)
        while True:
            if DO_DEBUG:
                new_message = input("USER_INPUT: ")
            else:
                event, values = window.read()
                if event == gooey.WIN_CLOSED or event == 'Exit':
                    break
                elif event == "user_input" + "_Enter" or event == 'Send':
                    new_message = values['user_input']
                else:
                    continue
            if new_message == "":
                continue
            elif new_message.lower() == "exit":
                break
            payload = {
                "endpoint": 'send_message',
                "method": 'POST',
                "msg": new_message,
                "chat_id": chat_id,
                "timestamp": time()
            }
            response = self.comm_thread.send_to_server(payload=payload)
            if response == None:
                break
        if not DO_DEBUG:
            window.close()
        self.comm_thread.leave_chat()

    def login(self):
        init_accept = self.comm_thread.get_response()
        if init_accept['status'] == 'busy':
            print("Server is busy right now, please try again later")
            return False
        elif init_accept['status'] != 'welcome':
            raise Exception(f"Got unknown acceptance message: {init_accept}")

        if DO_DEBUG:
            print("DEBUG: CONNECTION ACCEPTED, PROCEEDING TO LOGIN")

        username = input('Enter your username: ')
        response = self.comm_thread.send_to_server({"type": "login", 'username': username})
        if response['status'] == "online":
            self.username = username
            self.comm_thread.username = username
            return True

        elif response['status'] == "busy":
            print("You are logged in elsewhere, please log out elsewhere first")
            return False

    def run(self):  # "Main" function for User class
        print(f"Will try connecting to {self.host}:{self.port}")

        try:
            user_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)  # Create socket to connect to server with
            user_socket.connect((self.host, self.port))  # Open connection to server on host and port
        except:
            user_socket.close()
            logging.error(traceback.format_exc())
            return
        # Create new thread for communicating with the server
        try:
            self.comm_thread = server_communications_thread(user_socket)
        except:
            print("ERROR: Could not create server_comm_thread")
            logging.error(traceback.format_exc())
            return
        self.comm_thread.start()

        if self.login() == True:
            pass
        else:
            return

        payload = {
            "endpoint": 'get_chats',
        }
        response = self.comm_thread.send_to_server(payload)
        self.do_chat(response['chat_ids'][0])

        return


if len(sys.argv) < 3:
    print("Usage: python3 User4.py <host_ip> <port>")
else:
    user_obj = User(sys.argv[1], sys.argv[2])

    if len(sys.argv) > 3 and sys.argv[3] == "DO_DEBUG":
        DO_DEBUG = True
        print("######## DEBUG MODE IS ON ########")
    else:
        DO_DEBUG = False

    user_obj.run()

print("Exiting...")
