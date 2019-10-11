import socket
from constant import BUFFER_SIZE

IP = input("IP: ")
Port = int(input("Port: "))
filename = input("File name: ")


with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.connect((IP, Port))
    with open(filename, "rb") as f:
        while True:
            data = f.read(BUFFER_SIZE)
            if data == b'':
                break
            s.sendall(data)
