from SecureFTP import SFTPClient, key
from LocalVNetwork import AES_CTR

if __name__ == "__main__":
    cipher = AES_CTR(key)
    client = SFTPClient(
        server_address= ("127.0.0.1", 9999), 
        filename= "a", 
        cipher = cipher, 
        buffer_size= int(20 * 10**6), 
        verbosities= ("error", "warning", "notification"))
    client.start()
    pass
