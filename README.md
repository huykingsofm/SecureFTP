# SecureFTP
A custom File Transport Protocol for security purpose

# TESTING
```
# Step 1
$ git clone https://github.com/huykingsofm/SecureFTP
$ git submodule update --recursive

# Step 2
# Let's move or copy __server__.py and __client__.py from SecureFTP to current directory
# Example:
# Before moving
#    -- CurrentDir/
#    ------ SecureFTP/
#    ---------- __server__.py
#    ---------- __client__.py
#    ---------- otherfiles...
# After moving
#    -- CurrentDir/
#    ------ __server__.py
#    ------ __client__.py
#    ------ SecureFTP/
#    ---------- otherfiles...

# Step 3
$ python __server__.py

# Step 4
# Adjust parameter `filename` in __client__.py to your file which you want to tranfer 
$ python __client__.py
```

# USAGE
## SFTPServer
### @Constructor
```Python
def __init__(
    address, 
    newfilename, 
    cipher, 
    save_file_after: int = 65536, 
    buffer_size: int = 1024, 
    verbosities:tuple = ("error", )
    )
```
**Parameters**
+ `address`: the tuple of `(ip, port)`.
+ `newfilename`: the name of received file
+ `cipher`: the object of subclass of [_Cipher](./Cipher.py). By default, `NoCipher`. Recommend the object of `AES_CTR`.
+ `save_file_after`: save file after receiving the certain number of bytes, avoid being out of memory. 
+ `buffer_size`: the maximum size of packet (include header) every time receving, expected that it is larger than `buffer_size` of `SFTPClient` because client not include header to maximum packet size.
+ `verbosities`: a tuple which each element is in `"error"`, `"warning"`, `"notification"`.

### @Method
```Python
def start(self)
```
**Parameters**  
No parameters

**Return**  
A boolean value indicate whether the process be successful or not.

## SFTPClient
### @Constructor
```Python
def __init__(
    server_address, 
    filename, 
    cipher, 
    buffer_size: int = 1024, 
    verbosities:tuple = ("error", )
    )
```
**Parameters**
+ `server_address`: the tuple of `(ip, port)`.
+ `filename`: the name of sending file
+ `cipher`: the object of subclass of [_Cipher](./Cipher.py). By default, `NoCipher`. Recommend the object of `AES_CTR`.
+ `buffer_size`: the maximum bytes data of file every time sending, expected that it is smaller than `buffer_size` of `SFTPServer` because server include header to maximum packet size, client does not.
+ `verbosities`: a tuple which each element is in `"error"`, `"warning"`, `"notification"`.

### @Method
```Python
def start(self)
```
**Parameters**  
No parameters

**Return**  
A boolean value indicate whether the process be successful or not.