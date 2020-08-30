from SecureFTP import SFTPServer
from SecureFTP import AES_CTR

key = b"0123456789abcdef"
if __name__ == "__main__":
    cipher = AES_CTR(key)
    server = SFTPServer(
        address= ("127.0.0.1", 9999), 
        newfilename= "new.new", 
        cipher = cipher,
        save_file_after= 10**6, 
        buffer_size= 3 * 10**6,
        verbosities= ("error", "warning", "notification")
        )
    server.start()
    pass