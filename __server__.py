from SecureFTP import SFTP
from SecureFTP import AES_CTR

key = b"0123456789abcdef"
if __name__ == "__main__":
    cipher = AES_CTR(key)
    cipher = AES_CTR(key)
    ftp_receiver = SFTP(
        ("127.0.0.1", 9999),
        address_owner= "self",
        verbosities= {"dev": {"error", "warning", "notification"}, "user": {"notification"}}
    )
    ftp_receiver.as_receiver(
        storage_path= "new.new",
        cipher= cipher,
        save_file_after= 10 ** 6,
        buffer_size= 3 * 10 ** 6
    )
    print(ftp_receiver.start())
    """ server = SFTPServer(
        address= ("127.0.0.1", 9999), 
        newfilename= "new.new", 
        cipher = cipher,
        save_file_after= 10**6, 
        buffer_size= 3 * 10**6,
        verbosities= ("error", "warning", "notification")
        )
    server.start() """
    pass