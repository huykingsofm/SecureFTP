from SecureFTP import SFTP
from SecureFTP import AES_CTR

key = b"0123456789abcdef"
if __name__ == "__main__":
    cipher = AES_CTR(key)
    ftp_sender = SFTP(
        ("127.0.0.1", 9999),
        address_owner= "partner",
        verbosities= ("error", "warning", "notification")
    )
    ftp_sender.as_sender(
        file_name= "a",
        cipher= cipher,
        buffer_size= int(2.9 * 10 ** 6),
    )
    print(ftp_sender.start())
    
    """client = SFTPClient(
        server_address= ("127.0.0.1", 9999), 
        filename= "a", 
        cipher = cipher, 
        buffer_size= int(2.9 * 10**6), 
        verbosities= ("error", "warning", "notification"))
    client.start()"""
    pass
