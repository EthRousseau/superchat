import json
import logging
import os
import select
import socket
import sys
import threading
import traceback
from time import sleep


class server_communications_thread(threading.Thread):

    def __init__(self, user_socket):
        threading.Thread.__init__(self)
        self.user_socket = user_socket
        self.user_socket.setblocking(0)
        self.lock = threading.Lock()
        self.message_set = threading.Event()
        self.chats_hisotry = {}
        self.response = None
        self.username = None
        self.active_chat = None
        self.active_chat_users = []
        self.active_user_box = None

    def run(self):
        while True:
            message = self.wait_for_message()
            if not message:  # If the server gives an empty response, exit
                self.response = None
                self.message_set.set()
                break

            if (message_type := message.get('message_type')) == None:  # Is a response
                self.response = message
                self.message_set.set()
                if message.get('status') == 'leftchat':
                    break
                else:
                    continue

            if message['chat_id'] != self.active_chat:
                continue

            if message_type in ["standard", "add_user", "remove_user"]:
                if DO_DEBUG:
                    print("DEBUG: GOT NEW CHAT MESSAGE")
                with self.lock:
                    self.chats_hisotry[self.active_chat].append(message)

            elif message_type == "user_join":
                self.active_chat_users.append(message['about_user'])
                self.build_active_user_box()

            elif message_type == "user_leave":
                self.active_chat_users.remove(message['about_user'])
                self.build_active_user_box()

            self.print_chat()

    def wait_for_message(self):
        ready = select.select([self.user_socket], [], [])
        if ready[0]:
            message_len_encoded = self.user_socket.recv(8)
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
        self.message_set.wait()
        response = self.response
        self.message_set.clear()
        return response

    def build_active_user_box(self):
        if len(self.active_chat_users) == 1:
            self.active_user_box = "[It's Just You Here]"
            return
        self.active_user_box = "[Active Users: "
        for username in self.active_chat_users:
            if not self.active_user_box == "[Active Users: ":
                self.active_user_box += ', '
            self.active_user_box += username
        self.active_user_box += "]"

    def print_chat(self):
        if DO_DEBUG:
            print(" ## DEBUG: BEGIN WRITING CHAT ## ")
            with self.lock:
                for message in self.chats_hisotry[self.active_chat]:
                    print(f"{message}")
            print(" ## DEBUG: END WRITING CHAT ## ")
            return
        terminal_size = os.get_terminal_size()
        terminal_width = terminal_size.columns
        terminal_height = terminal_size.lines
        os.system('clear')
        print("\n" * terminal_height)
        max_message_width = int(terminal_width * (2 / 3))

        with self.lock:
            for message in self.chats_hisotry[self.active_chat]:
                message_type = message['message_type']
                if message_type in ["user_join", "user_leave"]:
                    continue
                print("")
                if message_type == "standard":
                    text = message['text']
                    sender = message['sender']
                    if sender == self.username:
                        print(f"{'(' + sender + ')' : >{terminal_width}}")
                        while text:
                            next_space = text[max_message_width:].find(' ')
                            print(f"{text[:max_message_width + next_space] : >{terminal_width}}")
                            text = text[max_message_width + next_space:]
                    else:
                        print(f"({sender})\n{text}")
                elif message_type == "add_user":
                    print(f"{'[' + message['about_user'] + ' has been added to this chat!]' : ^{terminal_width}}")
                elif message_type == "remove_user":
                    print(f"{'[' + message['about_user'] + ' has been removed from this chat]' : ^{terminal_width}}")
                elif message_type == "newchat":
                    print(f"{'[This is the beginning of chat #' + str(message['chat_id']) + '! Go nuts!]' : ^{terminal_width}}")

        print("")
        if self.active_user_box != None:
            print("=" * int((terminal_width - len(self.active_user_box)) / 2), end='')
            print(self.active_user_box, end='')
            print("=" * int((terminal_width - len(self.active_user_box)) / 2))
        else:
            print("=" * terminal_width)

    def load_chat(self, chat_id):
        new_chat_state = {
            "endpoint": 'change_active_chat',
            "chat_id": chat_id
        }
        response = self.send_to_server(new_chat_state)
        if response['status'] == 'joinedchat':
            latest_message_server = response['newest_message']
        else:
            return False

        if not self.chats_hisotry.get(chat_id):
            self.chats_hisotry[chat_id] = []
        if len(self.chats_hisotry[chat_id]) == 0:
            last_message_id = -1
        else:
            last_message_id = self.chats_hisotry[chat_id][-1]['message_id']

        if latest_message_server < last_message_id:
            if DO_DEBUG:
                print("DEBUG: NO NEW MESSAGES")
        else:
            payload = {
                "endpoint": 'chat_history',
                "method": 'GET',
                "chat_id": chat_id,
                "last_message_id": last_message_id
            }
            response = self.send_to_server(payload)
            self.chats_hisotry[chat_id].extend(response['messages'])

        payload = {
            "endpoint": 'get_active_users',
            "chat_id": chat_id
        }
        response = self.send_to_server(payload)
        if response['active_users'] != None:
            self.active_chat_users = response['active_users']
            self.build_active_user_box()
        self.active_chat = chat_id
        if DO_DEBUG:
            print(f"DEBUG: SET ACTIVE CHAT TO #{chat_id}")
        self.print_chat()
        return True

    def leave_chat(self):
        self.active_chat = None
        self.active_user_box = None
        new_chat_state = {
            "endpoint": 'change_active_chat',
            "chat_id": self.active_chat
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
        if not self.comm_thread.load_chat(chat_id):
            print("You do not have access to that chat")
            self.comm_thread.leave_chat()
            return
        while True:
            if DO_DEBUG:
                print("DEBUG: ASKING FOR USER INPUT")
            new_message = input("")
            if new_message == "":
                self.comm_thread.print_chat()
                continue
            elif new_message.lower() == "exit":
                break
            payload = {
                "endpoint": 'message',
                "method": 'POST',
                "msg": new_message,
                "chat_id": chat_id
            }
            response = self.comm_thread.send_to_server(payload=payload)
            if response == None:
                break
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
