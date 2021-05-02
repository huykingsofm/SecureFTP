import threading
import time

from sft.listener import SFTListener
from sft.client import SFTClientResponser
from sft.protocol.definition import SFTProtocols, SFTRoles

from hks_pylib.logger import Display
from hks_pylib.logger import StandardLoggerGenerator
from hks_pylib.logger.standard import StdUsers, StdLevels
from hks_pylib.cryptography.ciphers.symmetrics import AES_CTR


KEY = b"0123456789abcedffedcba9876543210"


def run_server(role):
    logger_generator = StandardLoggerGenerator("tests/server.{}.log".format(role))

    listener = SFTListener(
            cipher=AES_CTR(KEY),
            address=("127.0.0.1", 2000),
            logger_generator=logger_generator,
            display={StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL},
            role=role,
            buffer_size=10**8,
        )
    _print = logger_generator.generate("SFT Listener", 
    {StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL})

    listener.listen()
    responser = listener.accept(start_responser=True)
    listener.close()
    if role == SFTRoles.SENDER:
        responser.activate(SFTProtocols.SFT, "tests/file.500MB")

    result = responser.wait_result(SFTProtocols.SFT)
    _print(StdUsers.USER, StdLevels.INFO, "Result:", result)
    responser.close()


def run_client(role):
    logger_generator = StandardLoggerGenerator("tests/client.{}.log".format(role))

    client = SFTClientResponser(
        cipher=AES_CTR(KEY),
        address=("127.0.0.1", 2000),
        name="SFTClient",
        logger_generator=logger_generator,
        display={StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL},
        role=role,
        buffer_size=10**8
    )
    _print = logger_generator.generate("SFT Client",
    {StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL})
    client.connect()
    client.start(thread=True)
    if role == SFTRoles.SENDER:
        client.activate(SFTProtocols.SFT, "tests/file.500MB")

    result = client.wait_result(SFTProtocols.SFT)
    client.close()
    _print(StdUsers.USER, StdLevels.INFO, "Result:", result, type(result))
    
def test_sft():
    t1 = threading.Thread(target=run_server, args=(SFTRoles.SENDER, ), name="SERVER")
    t1.start()

    time.sleep(1)

    t2 = threading.Thread(target=run_client, args=(SFTRoles.RECEIVER, ), name="CLIENT")
    t2.start()

    t1.join()
    t2.join()

if __name__ == "__main__":
    test_sft()
