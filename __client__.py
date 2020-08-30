from SecureFTP import SFTPClient
from SecureFTP import AES_CTR

key = b"0123456789abcdef"
if __name__ == "__main__":
    cipher = AES_CTR(key)
    client = SFTPClient(
        server_address= ("127.0.0.1", 9999), 
        filename= "a", 
        cipher = cipher, 
        buffer_size= int(2.9 * 10**6), 
        verbosities= ("error", "warning", "notification"))
    client.start()
    pass
