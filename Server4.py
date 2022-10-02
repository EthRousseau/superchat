from email import message
import json
import logging
import random
import socket
import sys
import threading
import traceback


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
        # self.user_socket.setblocking(False)
        self.username = username  # Not lowered, must be lowered for each sKey lookup

        self.friends = []  # Non lowered usernames of which user is friends
        # Non lowered usernames waiting for this user to accept them (wow so famous)
        self.incoming_friend_requests = []

        self.chats = {}

        self.active_chat = None

        self.lock = threading.Lock()

    # Send a message to the user. msg is expected to be string, not bytes

    def set_socket(self, new_socket):
        self.user_socket = new_socket

    def send_message(self, msg):

        if self.user_socket:
            if DO_DEBUG:
                print(f"DEBUG: ATTEMPTING TO SEND {msg} TO {self.username}")
            msg = json.dumps(msg)
            message_len = len(msg)
            message_len_bytes = message_len.to_bytes(8, 'big')

            with self.lock:
                self.user_socket.sendall(message_len_bytes)
                if DO_DEBUG:
                    print(
                        f"DEBUG: NOTIFIED NEXT MESSAGE IS OF LEN: {message_len}. NOTIFICATION WAS OF SIZE: {len(message_len_bytes)}")
                self.user_socket.sendall(msg.encode())
            if DO_DEBUG:
                print(f"DEBUG: SENT {message_len} BYTES TO {self.username}")

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
        if not user_msg:
            return "EXIT"
        try:
            user_msg_json = json.loads(user_msg)
        except:
            print("ERROR: Non JSON passed to handle_user_message")
            return "EXIT"
        if DO_DEBUG:
            print(f"DEBUG: GOT {user_msg_json} FROM {self.username}")

        method = user_msg_json.get('method')
        match user_msg_json['endpoint']:

            case "message":
                if method == "POST":
                    new_message = {
                        "message_type": 'standard',
                        "sender": self.username,
                        "text": user_msg_json['msg']
                    }
                    server_obj.add_message_to_chat(new_message, user_msg_json['chat_id'])
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
                    messages = server_obj.all_chats[user_msg_json['chat_id']
                                                    ].get_chat_history(user_msg_json['last_message_id'])
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
                    if user_msg_json['new_state'] == 'offline':  # User wants to leave
                        response = {
                            "status": 'confirm_offline',
                        }

            case "change_active_chat":
                chat_id = user_msg_json['chat_id']
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
                users_list = self.chats.get(user_msg_json['chat_id']).get_active_users()
                response = {
                    "active_users": users_list
                }

        return response

    def listen_to_user(self):
        try:
            while True:
                user_msg = self.user_socket.recv(1024)
                response = self.handle_user_message(user_msg.decode())
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

        self.known_users = {}  # Dict of users who have logged into the "app". Keys are usernames.lower() and values are user_thread objects
        self.max_users = 5  # Max number of users that can be connected to the server at any time
        self.connected_users = []  # List of users who are CURRENTLY connected to the app. Values are user_thread objects
        self.server_lock = threading.Lock()  # Thread lock
        self.all_chats = {}  # Dict of all chat rooms that exist, Keys are chat_id and values are chat objects

    def connect_user(self, user_thread):
        online_status = {
            "type": "#login",
            "status": "#online"
        }
        user_thread.send_message(online_status)
        if DO_DEBUG:
            print(f"DEBUG: CONIRM JOIN: {user_thread.username}")
        with self.server_lock:
            self.connected_users.append(user_thread)

    def set_user_offline(self, user_thread):
        with self.server_lock:
            print(f"{user_thread.username} is going offline")
            self.connected_users.remove(user_thread)

    def init_user_connection(self, user_socket):
        self.send_message(user_socket, {"status": "#welcome"})
        message = user_socket.recv(1024).decode()
        if not message:
            return
        new_username_dict = json.loads(message)
        if new_username_dict['type'] != "#join":
            raise Exception(f"Expected #join message for new user but got {new_username_dict['type']}")

        new_username = new_username_dict['username']
        for user in self.connected_users:
            if user.username == new_username:
                online_status = {
                    "type": "#login",
                    "status": "#busy"
                }
                self.send_message(user_socket, online_status)
                user_socket.close()
                return
        if not (user_thread := self.known_users.get(new_username.lower())):
            # This is a brand new user
            user_thread = userThread(user_socket, new_username)
            self.known_users[new_username.lower()] = user_thread
        else:
            # This user already exists, set their connection to use the new socket
            # this is so the users data can continue to exist between sessions,
            # but their connection can update to accomodate a new one.
            user_thread.set_socket(user_socket)
            print(f"{new_username} is back!")
        self.connect_user(user_thread)
        if len(self.all_chats) == 0:
            base_chat = self.get_new_chat()
        else:
            base_chat = self.all_chats[0]
        self.add_user_to_chat(user_thread, base_chat)
        user_thread.start_user_thread()

    def send_message(self, user_socket, message):
        message = json.dumps(message)
        message_len = len(message)
        message_len_bytes = message_len.to_bytes(8, 'big')
        user_socket.sendall(message_len_bytes)
        user_socket.sendall(message.encode())

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
                        user_socket.sendall(json.dumps({"status": "#busy"}).encode())
                        user_socket.close()
                        print(f"Denied {user_address}, max online reached")
                        continue

                    init_user_thread = threading.Thread(target=self.init_user_connection, args=[user_socket])
                    init_user_thread.start()

        except:
            server_socket.close()
            trace = traceback.format_exc()
        finally:
            if trace:
                print(trace)
            else:
                print("Exiting...")


server_obj = Server(sys.argv[1])
if sys.argv[2]:
    DO_DEBUG = True
server_obj.run()
