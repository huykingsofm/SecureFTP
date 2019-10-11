import socket
from constant import BUFFER_SIZE

IP = input("IP: ")
Port = int(input("Port: "))

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind((IP, Port))
    s.listen(1)

    conn, addr = s.accept()
    content = b""
    while True:
        data = conn.recv(BUFFER_SIZE)
        if not data:
            break
        content += data

filename = input("Save file as: ")
with open(filename, "wb") as f:
    f.write(content)
print("Done")
