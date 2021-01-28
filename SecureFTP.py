import os
import socket
import hashlib
from .LocalVNetwork import STCPSocket
from .LocalVNetwork import StandardPrint
from .LocalVNetwork.SecureTCP import STCPSocketClosed

def __check_ip__(ip):
    try:
        socket.inet_aton(ip)
        return True
    except:
        return False

def __hash_a_file__(filename, buffer_size = 10 ** 6):
    sha1 = hashlib.sha1(b"")
    with open(filename, "rb") as stream:
        while True:
            data = stream.read(buffer_size)
            if not data:
                break
            sha1.update(data)
    return sha1.digest()

class SFTP(object):
    def __init__(self, address, address_owner, verbosities = ("error", "warning")):
        """
        address ~ (ip, port)
        address_owner ~ "self" or "partner"
        """
        assert isinstance(address, tuple), "Address must be a tuple"
        assert len(address) == 2, "Address must be (ip, port) format"
        assert __check_ip__(address[0]), "Invalid IP ({})".format(address[0])
        assert isinstance(address[1], int) and address[1] >= 0 and address[1] <= 65535, "Invalid port ({})".format(address[1])
        assert address_owner in ["self", "partner"], "Address owner must be only \"self\" or \"owner\""

        self.__address__ = address
        self.__address_owner__ = address_owner
        self.__print__ = StandardPrint("From SFTP", verbosities = verbosities)
        self.__verbosities__ = verbosities
    
    def __connect__(self):
        s = STCPSocket(
            cipher= self.__cipher__, 
            buffer_size= self.__buffer_size__, 
            verbosities= ("error", "warning")
        )
        if self.__address_owner__ == "self":
            s.bind(self.__address__)
            s.listen()
            self.__socket__, partner_address = s.accept()
            self.__print__("notification", "{} connected".format(partner_address))
            s.close()
        else:
            s.connect(self.__address__)
            self.__socket__ = s
            self.__print__("notification", "Connect to {} successfully".format(self.__address__))

    def __send__(self):
        fstream = open(self.__file_name__, "rb")
        total_size = 0
        file_size = os.path.getsize(self.__file_name__)
        file_size = file_size.to_bytes(8, "big")
        data = self.__socket__.recv()
        if data == b"$request file_size":
            self.__socket__.send(file_size)
        else:
            return False

        sha1 = __hash_a_file__(self.__file_name__)
        data = self.__socket__.recv()
        if data == b"$request file_hash":
            self.__socket__.send(sha1)
        else:
            return False

        complete = False
        while True:
            try:
                data = fstream.read(self.__buffer_size__)
                if not data:
                    complete = True
                    break
                self.__socket__.sendall(data)
                total_size += len(data)
                self.__print__("notification", f"sent total {total_size} bytes")
                self.__socket__.recv()
            except Exception as e:
                self.__print__("error", repr(e))
                break
        
        self.__socket__.send(b"$sending_complete")
        try:
            if not complete:
                return False

            data = self.__socket__.recv()
            if data != b"$result success":
                return False

            return True
        finally:
            fstream.close()
            self.__socket__.close()

    def __receive__(self):
        try:
            self.__socket__.send(b"$request file_size")
            data = self.__socket__.recv()
        except STCPSocketClosed:
            return False
        except Exception as e:
            self.__print__("error", repr(e))
            return False

        expected_file_size = int.from_bytes(data, "big")

        try:
            self.__socket__.send(b"$request file_hash")
            expected_sha1 = self.__socket__.recv()
        except STCPSocketClosed:
            return False
        except Exception as e:
            self.__print__("error", repr(e))
            return False

        current_size = 0
        total_size = 0
        fstream = open(self.__storage_path__, "wb")

        while True:
            try:
                data = self.__socket__.recv()
            except STCPSocketClosed:
                break
            except Exception as e:
                self.__print__("error", repr(e))
                break
    
            if not data:
                continue

            if data == b"$sending_complete":
                break

            fstream.write(data)
            current_size += len(data)
            total_size += len(data)
            if current_size >= self.__save_file_after__:
                fstream.close()
                fstream = open(self.__storage_path__, "ab")
                current_size = 0
            self.__print__("notification", f"received total {total_size} bytes")

            try:
                self.__socket__.send(f"$done {total_size}".encode())
            except STCPSocketClosed:
                break
            except Exception as e:
                self.__print__("error", repr(e))
                break

        fstream.close()

        result = True
        message = ""
        if total_size < expected_file_size:
            self.__print__("notification", "File size is smaller than expected")
            message = "File size is smaller than expected"
            result = False

        if total_size > expected_file_size:
            self.__print__("notification", "File size is larger than expected")
            message = "File size is larger than expected"
            result = False

        sha1 = __hash_a_file__(self.__storage_path__)
        if sha1 != expected_sha1:
            self.__print__("notification", "Non-integrity file")
            message = "File integrity is compromised"
            result = False

        self.__print__("notification", f"Received file successfully, save at {self.__storage_path__}")

        if result == True:
            self.__socket__.send(b"$result success")
        else:
            self.__socket__.send(b"$result failure " + message.encode())
        self.__socket__.close()
        return result

    def as_sender(self, file_name, cipher, buffer_size = 65535):
        self.__file_name__ = file_name
        self.__cipher__ = cipher
        self.__buffer_size__ = buffer_size
        self.__role__ = "sender"

    def as_receiver(self, storage_path, cipher, save_file_after: int = 65536, buffer_size: int = 1024):
        self.__storage_path__ = storage_path
        self.__cipher__ = cipher
        self.__save_file_after__ = save_file_after
        self.__buffer_size__ = buffer_size
        self.__role__ = "receiver"

    def start(self):
        self.__connect__()
        if self.__role__ == "sender":
            return self.__send__()
        else:
            return self.__receive__()

if __name__ == "__main__":
    print(__hash_a_file__("a"))
    print(__hash_a_file__("new.new"))