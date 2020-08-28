import os
import socket
import hashlib
from DefinedError import InvalidArgument
from SecureTCP import STCPSocket, STCPSocketClosed
from CustomPrint import StandardPrint

key = b"0123456789abcdef"

def __hash_a_file__(filename, buffer_size = 10 ** 6):
    sha1 = hashlib.sha1(b"")
    with open(filename, "rb") as stream:
        data = stream.read(buffer_size)
        sha1.update(data)
    return sha1.digest()

class SFTPServer(object):
    def __init__(self, address, newfilename, cipher, save_file_after: int = 65536, buffer_size: int = 1024, verbosities:tuple = ("error", )):
        self.address = address
        self.newfilename = newfilename
        self.save_file_after = save_file_after
        self.buffer_size = buffer_size
        self.cipher = cipher
        self.__print__ = StandardPrint(f"From SFTP {address}", verbosities)

    def _wait(self):
        self.socket = STCPSocket(cipher= self.cipher, buffer_size= self.buffer_size, verbosities= ())
        self.socket.bind(self.address)
        self.socket.listen()
        return self.socket.accept()
    
    def start(self):
        client, address = self._wait()
        self.__print__(f"Connected to {address}", "notification")

        client.send(b"$request file_size")
        data = client.recv()
        expected_file_size = int.from_bytes(data, "big")

        client.send(b"$request file_hash")
        expected_sha1 = client.recv()

        current_size = 0
        total_size = 0
        fstream = open(self.newfilename, "wb")

        while True:
            try:
                data = client.recv()
            except STCPSocketClosed as e:
                break
    
            if not data:
                continue

            fstream.write(data)
            current_size += len(data)
            total_size += len(data)
            if current_size >= self.save_file_after:
                fstream.close()
                fstream = open(self.newfilename, "ab")
                current_size = 0
            self.__print__(f"received total {total_size} bytes", "notification")

            try:
                client.send(f"$done {total_size}".encode())
            except STCPSocketClosed:
                pass
            except Exception as e:
                self.__print__(repr(e), "error")

        fstream.close()
        client.close()
        self.socket.close()

        if total_size < expected_file_size:
            self.__print__("Not enough file size", "notification")
            return False

        if total_size > expected_file_size:
            self.__print__("File size is larger than expected", "notification")
            return False

        sha1 = __hash_a_file__(self.newfilename)
        if sha1 != expected_sha1:
            self.__print__("Non-integrity file", "notification")
            return False

        self.__print__(f"Received file successfully, save at {self.newfilename}", "notification")
        return True

class SFTPClient(object):
    def __init__(self, server_address, filename, cipher, buffer_size = 65535, verbosities: tuple = ("error", )):
        self.server_address = server_address
        self.filename = filename
        self.buffer_size = buffer_size
        self.cipher = cipher
        self.__print__ = StandardPrint("From SFTP Client", verbosities)

    def _connect(self):
        self.socket = STCPSocket(cipher= self.cipher)
        self.socket.connect(self.server_address)
    
    def start(self):
        self._connect()
        fstream = open(self.filename, "rb")
        total_size = 0
        file_size = os.path.getsize(self.filename)
        file_size = file_size.to_bytes(8, "big")
        data = self.socket.recv()
        if data == b"$request file_size":
            self.socket.send(file_size)

        sha1 = __hash_a_file__(self.filename)
        data = self.socket.recv()
        if data == b"$request file_hash":
            self.socket.send(sha1)

        while True:
            data = fstream.read(self.buffer_size)
            if not data:
                break
            self.socket.send(data)
            total_size += len(data)
            self.__print__(f"sended total {total_size} bytes", "notification")
            self.socket.recv()
        self.socket.close()
        fstream.close()
        
        return True

if __name__ == "__main__":
    print(__hash_a_file__("a"))
    print(__hash_a_file__("new.new"))