import SecurePacket
import Packet
import Cipher
from CustomPrint import StandardPrint

class PacketBufferException(Exception): ...
class PacketBufferOverflow(PacketBufferException): ...

class PacketBuffer():
    def __init__(self, decoder, identifier = None, verbosities: tuple = ("error", )):
        self.buffer = []
        self.packet_decoder = decoder
        prefix = "PacketBuffer"
        if identifier != None:
            prefix = f"PacketBuffer {identifier}"
        self.__print__ = StandardPrint(prefix, verbosities)
        self.current_packet = b""

    def push(self, packet:bytes):
        self.__print__("Push the message: {}".format(packet), "notification")
        self.buffer.append(packet)

    def pop(self):
        try:
            if len(self.buffer) == 0:
                return b""
                
            self.current_packet += self.buffer[0]
            del self.buffer[0]

            self.__print__("Pop the message: {}".format(self.current_packet), "notification")
            
            if self.packet_decoder == None:
                ret = self.current_packet
                self.current_packet = b""
                return ret
                
            packet_tuple = self.packet_decoder(self.current_packet)
            packet_size = packet_tuple["packet_size"]
            
            if packet_size < len(self.current_packet):
                raise PacketBufferOverflow("Received packet's length is larger than the expected size of packet")

            self.current_packet = b""
            return packet_tuple["payload"]
        except SecurePacket.SecurePacketException as e:
            raise e
        except Packet.PacketException as e:
            raise e
        except Cipher.CipherException as e:
            raise e
        except Exception as e:
            self.__print__(e, "error")
            return b""

    def __len__(self):
        return len(self.buffer)

if __name__ == "__main__":
    from SecurePacket import SecurePacketEncoder, SecurePacketDecoder
    from Cipher import AES_CTR
    import os
    key = os.urandom(16)
    cipher = AES_CTR(key)

    packet_encoder = SecurePacketEncoder(cipher)
    packet_decoder = SecurePacketDecoder(cipher)
    packetbuffer = PacketBuffer(packet_decoder)

    nonce = os.urandom(16)
    cipher.set_param(0, nonce)
    packetbuffer.push(packet_encoder(b"huythongminh"))
    print("Buffer 1:", packetbuffer.buffer)

    nonce = os.urandom(16)
    cipher.set_param(0, nonce)
    packetbuffer.push(packet_encoder(b"123"))
    print("Buffer 2", packetbuffer.buffer)

    print("Pop 1:", packetbuffer.pop())
    print("Buffer 3:", packetbuffer.buffer)
    print("Pop 2:", packetbuffer.pop())
    print("Buffer 4:", packetbuffer.buffer)