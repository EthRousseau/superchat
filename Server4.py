import json
import logging
import random
import socket
import sys
import threading
import traceback
import select


class chat():

    def __init__(self, id, users=None):
        self.chat_id = id
        self.chat_lock = threading.Lock()
        self.message_history = {}  # Dict of message history for this chat instance. Keys are ints in accending order inc by 1

        # Dict of updates to this chat i.e. userjoin, etc.
        # Keys are saem as message_hisotry, and will be slotted in as if it were another message:
        # i.e. if the most recent MESSAGE is #5 then the next UPDATE will be #6, even if there are no updates yet
        self.update_history = {}

        self.all_history = {}

        self.users = {}  # Dict of user_thread that have access to this chat
        if users:
            for user_thread in users:
                self.add_user(user_thread)

        self.active_users = {}  # Dict of user_thread that are currently looking at this chat

    def add_message(self, message):
        with self.chat_lock:
            message['chat_id'] = self.chat_id
            message_id = message['message_id'] = len(self.all_history)
            self.message_history[message_id] = message
            self.all_history[message_id] = message

        for user in self.active_users.values():
            user.send_message(message)

    def send_update(self, update):
        update['chat_id'] = self.chat_id
        with self.chat_lock:
            message_id = update['message_id'] = len(self.all_history)
            self.update_history[message_id] = update
            self.all_history[message_id] = update
        for user in self.active_users.values():
            user.send_message(update)

    def add_user(self, user):  # Perminantly add a user to this chat, state persists after user goes offline
        with self.chat_lock:
            if self.users.get(user.username):
                return
            else:
                self.users[user.username] = user
        if DO_DEBUG:
            print(f"DEBUG: ADDED {user.username} TO CHAT#{self.chat_id}")
        user_join_message = {
            "message_type": 'add_user',
            "sender": "SERVER",
            "about_user": user.username
        }
        self.send_update(user_join_message)

    def remove_user(self, user):  # Perminantly remove a user from this chat, state persists after user goes offline
        with self.chat_lock:
            if not self.users.get(user.username):
                return
            else:
                del self.users[user.username]
        if DO_DEBUG:
            print(f"DEBUG: REMOVED {user.username} FROM CHAT#{self.chat_id}")
        user_remove_message = {
            "message_type": 'remove_user',
            "sender": "SERVER",
            "about_user": user.username
        }
        self.send_update(user_remove_message)

    def user_join(self, user):  # User is now online and in this chat
        with self.chat_lock:
            self.active_users[user.username] = user
        user_join_message = {
            "message_type": 'user_join',
            "sender": "SERVER",
            "about_user": user.username
        }
        self.send_update(user_join_message)

    def user_leave(self, user):  # User was active this chat, and is no longer. Still could have access to it
        with self.chat_lock:
            del self.active_users[user.username]
        user_leave_message = {
            "message_type": 'user_leave',
            "sender": "SERVER",
            "about_user": user.username
        }
        self.send_update(user_leave_message)

    def get_chat_history(self, last_message):
        with self.chat_lock:
            return list(self.all_history.values())[last_message + 1:]

    def get_latest_message_id(self):
        with self.chat_lock:
            return len(self.all_history) - 1

    def get_active_users(self):  # returns a list of usernames of active users in this chat
        return list(self.active_users.keys())


class userThread():

    def __init__(self, user_socket, username):
        self.user_socket = user_socket
        self.user_socket.setblocking(True)
        # self.user_socket.setblocking(False)
        self.username = username

        self.friends = []  # Usernames of which user is friends
        # Usernames waiting for this user to accept them (wow so famous)
        self.incoming_friend_requests = []

        self.chats = {}

        self.active_chat = None

        self.lock = threading.Lock()

    # Send a message to the user. msg is expected to be string, not bytes

    def set_socket(self, new_socket):
        self.user_socket = new_socket

    def send_message(self, payload):

        json_string = json.dumps(payload)
        encoded_msg = json_string.encode()
        message_len = len(encoded_msg)
        message_len_bytes = message_len.to_bytes(8, 'big')

        full_message = message_len_bytes + encoded_msg

        if DO_DEBUG:
            print(
                f"DEBUG: SENDING {json_string} TO {self.username} ({message_len} BYTES). HEADER: {message_len_bytes} ({len(message_len_bytes)} BYTES)")
        with self.lock:
            self.user_socket.sendall(full_message)

    def receive_user_message(self):
        message_len_encoded = self.user_socket.recv(8)
        bytes_to_read = int.from_bytes(message_len_encoded, 'big')
        if not isinstance(bytes_to_read, int):
            raise Exception("Did not get INT for length of incoming message")
        if bytes_to_read == 0:
            return None
        new_message = ""
        if DO_DEBUG:
            print(f"DEBUG: BEGINNING TO READ MESSAGE OF {bytes_to_read} BYTES FROM {self.username}")
        while bytes_to_read > 0:
            incoming_bytes = self.user_socket.recv(bytes_to_read)
            new_message += incoming_bytes.decode()
            bytes_to_read -= len(incoming_bytes)
        if DO_DEBUG:
            print(f"DEBUG: READ {new_message} OF LEN {len(new_message)} FROM {self.username}")
        if not new_message:
            return None
        return json.loads(new_message)

    def add_to_chat(self, chat):
        if not self.chats.get(chat_id := chat.chat_id):
            with self.lock:
                self.chats[chat_id] = chat
            if DO_DEBUG:
                print(f"DEBUG: ADDED CHAT #{chat_id} TO USER: {self.username}")

    # Returns either True or False. True if user is still online, false if user is terminating the connection
    # i.e. returns truthyness of "connection will continue"
    # user_msg is expected to be string, not byes

    def handle_user_message(self, user_msg):
        if DO_DEBUG:
            print(f"DEBUG: GOT {user_msg} FROM {self.username}")

        method = user_msg.get('method')
        match user_msg['endpoint']:

            case "message":
                if method == "POST":
                    new_message = {
                        "message_type": 'standard',
                        "sender": self.username,
                        "text": user_msg['msg']
                    }
                    server_obj.add_message_to_chat(new_message, user_msg['chat_id'])
                    response = {
                        "status": '#POSTED'
                    }
            case "get_chats":
                chat_ids = []
                for chat_id in self.chats.keys():
                    chat_ids.append(chat_id)
                response = {
                    "chat_ids": chat_ids
                }

            case "chat_history":
                if method == "GET":
                    messages = server_obj.all_chats[user_msg['chat_id']
                                                    ].get_chat_history(user_msg['last_message_id'])
                    if len(messages) == 0:
                        newest_message_id = 0
                    else:
                        newest_message_id = messages[-1]['message_id']
                    response = {
                        "messages": messages,
                        "newest_message_id": newest_message_id
                    }

            case "user_state":
                if method == "GET":
                    print("TODO: Get online users list")

                if method == "POST":
                    if user_msg['new_state'] == 'offline':  # User wants to leave
                        response = {
                            "status": 'confirm_offline',
                        }

            case "change_active_chat":
                chat_id = user_msg['chat_id']
                if chat_id == None:
                    if self.active_chat != None:
                        self.chats[self.active_chat].user_leave(self)
                    self.active_chat = None
                    response = {
                        "status": 'leftchat',
                    }
                elif chat := self.chats.get(chat_id):
                    self.active_chat = chat_id
                    chat.user_join(self)
                    response = {
                        "status": "joinedchat",
                        "chat_id": chat_id,
                        "newest_message": chat.get_latest_message_id()
                    }
                else:
                    response = {
                        "status": "UNAUTHORIZED"
                    }

            case "get_active_users":
                users_list = self.chats.get(user_msg['chat_id']).get_active_users()
                response = {
                    "active_users": users_list
                }

        return response

    def listen_to_user(self):
        try:
            while True:
                user_msg = self.receive_user_message()
                if user_msg == None:
                    break
                response = self.handle_user_message(user_msg)
                if response == "EXIT":
                    break
                self.send_message(response)
                if response.get("status") == 'confirm_offline':
                    break
        except Exception as e:
            logging.error(traceback.format_exc())

        self.user_socket.close()
        self.user_socket = None
        server_obj.set_user_offline(self)
        if DO_DEBUG:
            print(f"DEBUG: USER_THREAD FOR USER {self.username} IS CLOSED")

    def start_user_thread(self):
        self.session_thread = threading.Thread(target=self.listen_to_user)
        self.session_thread.start()


class Server:

    def __init__(self, port=None):
        # Default Port
        self.port = 8000

        # If less than 2 args are input, use default values
        if not port:
            print(f"Usage: python3 Server.py <portNumber>\n"
                  f"Now using portNumber={self.port}")
        else:  # Otherwise, use CLI inputs
            self.port = int(port)

        self.known_users = {}  # Dict of users who have logged into the "app". Keys are usernames and values are user_thread objects
        self.max_users = 5  # Max number of users that can be connected to the server at any time
        self.connected_users = {}  # List of users who are CURRENTLY connected to the app. Values are user_thread objects
        self.server_lock = threading.Lock()  # Thread lock
        self.all_chats = {}  # Dict of all chat rooms that exist, Keys are chat_id and values are chat objects

    def connect_user(self, user_thread):
        online_status = {
            "status": "online"
        }
        user_thread.send_message(online_status)
        if DO_DEBUG:
            print(f"DEBUG: CONIRM JOIN: {user_thread.username}")
        with self.server_lock:
            self.connected_users[user_thread.username] = user_thread

    def set_user_offline(self, user_thread):
        with self.server_lock:
            print(f"{user_thread.username} is going offline")
            del self.connected_users[user_thread.username]

    def init_user_connection(self, user_socket, user_address):
        try:
            self.send_message({"status": "welcome"}, user_socket, user_address)
            message = self.recieve_message(user_socket, user_address)
            if message == None:
                raise Exception("ERROR: Got None response from user")

            if message.get('type') != "login":
                raise Exception(f"Expected \"login\" but got {message}")

            new_username = message['username']
            if new_username in list(self.connected_users.keys()):  # User is already logged in
                self.send_message({"status": "busy"}, user_socket, user_address)
                user_socket.close()
                return

            if not (user_thread := self.known_users.get(new_username)):  # Brand new user
                user_thread = userThread(user_socket, new_username)
                self.known_users[new_username] = user_thread

            else:  # User already exists
                user_thread.set_socket(user_socket)
                print(f"{new_username} is back!")

            if DO_DEBUG:
                print(f"DEBUG: HANDING OFF CONNECTION: {user_address} IS NOW {new_username}")

            self.connect_user(user_thread)

            if len(self.all_chats) == 0:  # This chat stuff is all just for testing ideally user will create their own chat
                base_chat = self.get_new_chat()
            else:
                base_chat = self.all_chats[0]
            self.add_user_to_chat(user_thread, base_chat)

            user_thread.start_user_thread()
        except:
            print(f"ERROR: Could not initialize user connection for {user_address}")
            logging.error(traceback.format_exc())

    def send_message(self, payload, user_socket, user_address):
        json_string = json.dumps(payload)
        encoded_msg = json_string.encode()
        message_len = len(encoded_msg)
        message_len_bytes = message_len.to_bytes(8, 'big')

        full_message = message_len_bytes + encoded_msg

        if DO_DEBUG:
            print(
                f"DEBUG: SENDING {json_string} TO {user_address} ({message_len} BYTES). HEADER: {message_len_bytes} ({len(message_len_bytes)} BYTES)")
        with self.server_lock:
            user_socket.sendall(full_message)

    def recieve_message(self, user_socket, user_address):
        if DO_DEBUG:
            print(f"DEBUG: WAITING ON MESSAGE FROM {user_address}")
        ready = select.select([user_socket], [], [])
        if ready[0]:
            message_len_encoded = user_socket.recv(8)
            bytes_to_read = int.from_bytes(message_len_encoded, 'big')
            if not isinstance(bytes_to_read, int):
                raise Exception("Did not get INT for length of incoming message")
            if bytes_to_read == 0:
                return None
            new_message = ""
            if DO_DEBUG:
                print(f"DEBUG: BEGINNING TO READ MESSAGE OF {bytes_to_read} BYTES FROM {user_address}")
            while bytes_to_read > 0:
                incoming_bytes = user_socket.recv(bytes_to_read)
                new_message += incoming_bytes.decode()
                bytes_to_read -= len(incoming_bytes)
        if DO_DEBUG:
            print(f"DEBUG: READ {new_message} OF LEN {len(new_message)} FROM {user_address}")
        if new_message == "":
            return None
        return json.loads(new_message)

    def get_new_chat(self):
        with self.server_lock:
            new_chat_id = len(self.all_chats)
            new_chat = chat(new_chat_id)
            self.all_chats[new_chat_id] = new_chat
        new_chat_message = {
            "message_type": "newchat"
        }
        new_chat.send_update(new_chat_message)
        return new_chat

    def add_user_to_chat(self, user_thread, chat):
        user_thread.add_to_chat(chat)
        chat.add_user(user_thread)

    def add_message_to_chat(self, message, chat_id):
        chat = self.all_chats.get(chat_id)
        if not chat:
            raise Exception("ERROR: Chat ID not found")
        chat.add_message(message)

    # Run server
    def run(self):

        print(f"Server using port number={self.port}")

        # Open a server socket on the portNumber
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server_socket:
                server_socket.bind(("", self.port))
                server_socket.listen()

                while True:  # Listen for new connections indefinitely
                    user_socket, user_address = server_socket.accept()  # Block execution until connection is recieved
                    # with user_socket:
                    if DO_DEBUG:
                        print(f"DEBUG: NEW CONNECTION: {user_address}")
                    if len(self.connected_users) >= self.max_users:  # Check if busy
                        busy_message = {
                            "status": "busy"
                        }
                        self.send_message(user_socket, busy_message, user_address)
                        user_socket.close()
                        print(f"Denied {user_address}, max online users reached")
                        continue

                    init_user_thread = threading.Thread(target=self.init_user_connection, args=[
                                                        user_socket, user_address])
                    init_user_thread.start()

        except KeyboardInterrupt:
            server_socket.close()
        except:
            server_socket.close()
            logging.error(traceback.format_exc())
        print("\nExiting...")


server_obj = Server(sys.argv[1])
if sys.argv[2]:
    DO_DEBUG = True
else:
    DO_DEBUG = False
server_obj.run()
