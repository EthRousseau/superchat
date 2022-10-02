string = "HI THERE"

message_len = len(string)
message_len_bytes = message_len.to_bytes(8, 'big')
print(f"Bytes to send: {message_len}")
print(f"Notification len: {len(message_len_bytes)}")
print(f"Encoded message len: {len(string.encode())}")
print(f"Notif and message: {message_len_bytes + string.encode()}")
print(f"Len notif and message: {len(message_len_bytes + string.encode())}")
