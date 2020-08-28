import struct
from Packet import PacketEncoder, PacketDecoder
from Cipher import XorCipher, cipher_from_hash, hash_name
from DefinedError import InvalidArgument

class SecurePacketException(Exception): ...
class CipherTypeMismatch(SecurePacketException): ...

class SecurePacketEncoder(PacketEncoder):
    # A packet generator encrypting by AES-256 and hashing by MD5 
    def __init__(self, cipher):
        self.cipher = cipher

    def __call__(self, payload: bytes):
        payload = self.cipher.encrypt(payload)
        packet = super().__call__(payload)
        
        # SECURE HEADER = TYPE_OF_CIPHER (2 bytes) + NUMBER_OF_PARAMS(1 byte) 
        #                 + PARAM1_SIZE + PARAM1 + PARAM2_SIZE + PARAM2 + ...
        # TYPE_OF_CIPHER is the hash value of the cipher class

        secure_header = hash_name(self.cipher) + struct.pack(">B", self.cipher.number_of_params)
        
        for i in range(self.cipher.number_of_params):
            param = self.cipher.get_param(i)

            if not isinstance(param, bytes):
                raise InvalidArgument("Parameter of cipher must be a bytes object")
            
            param_size = len(param)
            param_struct = "B{}s".format(param_size)
            secure_header += struct.pack(param_struct, param_size, param)

        # Set new header size = old header size + secure header size
        old_header_size = struct.unpack(">H", packet[:2])[0]
        packet = packet[:old_header_size] + secure_header + packet[old_header_size:]
        new_header_size = old_header_size + len(secure_header)
        new_header_size = struct.pack(">H", new_header_size)

        # Return the packet with new header size
        return new_header_size + packet[2:]

class SecurePacketDecoder(PacketDecoder):
    # A packet generator encrypting by AES-256 and hashing by MD5 
    def __init__(self, cipher):
        self.cipher = cipher

    def __call__(self, packet: bytes):
        packet_dict = super().__call__(packet)
        
        # ORIGINAL HEADER = HEADER_SIZE (2 bytes) + PAYLOAD_SIZE (2 byte)
        original_header_size = 6
        
        # SECURE HEADER: TYPE_OF_CIPHER (2 bytes) + NUMBER_OF_PARAMS(1 byte) 
        #                 + PARAM1_SIZE + PARAM1 + PARAM2_SIZE + PARAM2 + ...
        cipher_hashvalue = packet[original_header_size: original_header_size + 2]
        cipher_type = cipher_from_hash.get(cipher_hashvalue, None)

        if cipher_type == None or not isinstance(self.cipher, cipher_type):
            raise CipherTypeMismatch("Cipher type mismatch")
        
        number_of_params = struct.unpack(">B", packet[original_header_size + 2: original_header_size + 3])[0]
        current_index = original_header_size + 3
        for i in range(number_of_params):
            param_size = struct.unpack(">B", packet[current_index: current_index + 1])[0]
            current_index += 1
            
            param = struct.unpack(">{}s".format(param_size), packet[current_index: current_index + param_size])[0]
            current_index += param_size
            
            self.cipher.set_param(i, param)
            
        packet_dict["payload"] = self.cipher.decrypt(packet_dict["payload"])
        return packet_dict

if __name__ == "__main__":
    cipher = XorCipher(key = b'1')
    cipher.set_param(0, b'3')
    packet_encoder = SecurePacketEncoder(cipher)
    m = packet_encoder("huythongminh".encode())
    print(m)

    packet_decoder = SecurePacketDecoder(cipher)
    print(packet_decoder(m))