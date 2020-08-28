import socket
import threading
import errno
import copy
import time
import Cipher
import Packet
import SecurePacket
from PacketBuffer import PacketBuffer
from CustomPrint import StandardPrint

class STCPSocketException(Exception): ...
class STCPSocketClosed(STCPSocketException): ...

class STCPSocket(object):
    def __init__(self, cipher = Cipher.NoCipher(), buffer_size = 1024, verbosities: tuple = ("error", )):
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.cipher = cipher
        self.cipher.reset_params()

        self.packet_encoder = SecurePacket.SecurePacketEncoder(self.cipher)
        self.packet_decoder = SecurePacket.SecurePacketDecoder(self.cipher)
        self.buffer = None
        self.buffer_size = buffer_size
        self.__print__ = StandardPrint(f"STCP Socket", verbosities)

        self.process = threading.Event()

    def __enter__(self):
        return self

    def __exit__(self, *args):
        return self.socket.__exit__(args)

    def _start_serve(self):
        self.__print__("Start serve socket...", "notification")
        while not self.isclosed():
            try:
                data = self.socket.recv(self.buffer_size)
            except socket.error as e:
                self.close()
                if e.errno in (errno.ECONNRESET, errno.ECONNABORTED):
                    break
                else:
                    self.__print__(repr(e), "error")
                    raise e
            except Exception as e:
                self.close()
                self.__print__(repr(e), "error")
                raise e
            else:
                self.buffer.push(data)
                self.process.set()
        self.__print__("Stop serve socket...", "notification")

    def recv(self, reload_time = 0.3):
        data = b''
        n_try = 0
        while not data:
            if self.isclosed() and n_try >= 3:
                raise STCPSocketClosed("Connection closed")

            if len(self.buffer) == 0 and self.isclosed() == False:
                self.process.wait()

            try:
                data = self.buffer.pop()
            except Packet.CannotExtractPacket as e: 
                # Not enough length of packet
                self.__print__(repr(e), "warning")
                break
            except SecurePacket.CipherTypeMismatch as e: 
                # Cipher's type mismatch
                self.__print__(repr(e), "warning")
                break
            except Cipher.DecryptFailed as e: 
                # Cannot decrypt the packet: authentication failed, wrong parameters, ...
                self.__print__(repr(e), "warning")
                break
            except Exception as e:
                self.__print__(repr(e), "error")
                break
            finally:
                if not data:
                    time.sleep(reload_time)

            n_try += 1

        self.process.clear()
        return data
        
    def send(self, data):
        self.cipher.reset_params()
        packet = self.packet_encoder(data)
        self.__print__("Send: {}".format(packet), "notification")
        return self.socket.send(packet)

    def sendall(self, data):
        self.cipher.reset_params()
        packet = self.packet_encoder(data)
        self.__print__("Send: {}".format(packet), "notification")
        return self.socket.sendall(packet)
    
    def bind(self, address):
        return self.socket.bind(address)

    def listen(self):
        self.__print__("Server listen...", "notification")
        return self.socket.listen()

    def accept(self):
        socket, addr = self.socket.accept()
        self.__print__("Server accept {}".format(addr), "notification")
        socket = self._fromsocket(socket, addr, start_serve= True)
        return socket, addr

    def connect(self, address):
        ret = self.socket.connect(address)

        server = threading.Thread(target= self._start_serve)
        server.setDaemon(True)
        server.start()

        self.buffer = PacketBuffer(self.packet_decoder, address, self.__print__.verbosities)
        self.__print__.prefix = f"STCP Socket {address}"
        return ret

    def close(self):
        self.process.set()
        return self.socket.close()

    def isclosed(self):
        return self.socket._closed
    
    def _fromsocket(self, socket: socket.socket, address, start_serve = True):
        cipher = copy.copy(self.cipher)
        dtp = STCPSocket(cipher, self.buffer_size, self.__print__.verbosities)
        dtp.socket = socket
        dtp.__print__.prefix = f"STCP Socket {address}"
        dtp.buffer = PacketBuffer(dtp.packet_decoder, address, dtp.__print__.verbosities)
        if start_serve:
            server = threading.Thread(target= dtp._start_serve)
            server.setDaemon(True)
            server.start()
        return dtp


if __name__ == "__main__":
    a = STCPSocket()
    a.bind(("127.0.0.1", 9999))
    a.listen()
    b, _ = a.accept()
    print(b.recv())
    b.close()
    a.close()
    