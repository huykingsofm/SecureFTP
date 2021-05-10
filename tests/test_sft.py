from sys import path
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


def run_server(role, is_activate):
    logger_generator = StandardLoggerGenerator("tests/sft.{}.log".format(role.name))

    listener = SFTListener(
            cipher=AES_CTR(KEY),
            address=("127.0.0.1", 2000),
            logger_generator=logger_generator,
            display={StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL},
            buffer_size=10**8,
        )

    listener.get_scheme(
            SFTProtocols.SFT,
            SFTRoles.RECEIVER
        ).config(directory="tests/")

    _print = logger_generator.generate("SFT Listener", 
    {StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL})

    listener.listen()
    responser = listener.accept(start_responser=True)
    listener.close()

    if is_activate:
        if role == SFTRoles.RECEIVER:
            responser.activate(SFTProtocols.SFT, role, token="tests/file.500MB")
        else:
            responser.activate(SFTProtocols.SFT, role, path="tests/file.500MB", token="default")

    result = responser.wait_result(SFTProtocols.SFT, role, timeout=60)
    _print(StdUsers.USER, StdLevels.INFO, "Result:", result)
    responser.close()


def run_client(role, is_activate):
    logger_generator = StandardLoggerGenerator("tests/sft.{}.log".format(role.name))

    client = SFTClientResponser(
        cipher=AES_CTR(KEY),
        address=("127.0.0.1", 2000),
        name="SFTClient",
        logger_generator=logger_generator,
        display={StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL},
        buffer_size=10**8
    )

    client.get_scheme(
            SFTProtocols.SFT,
            SFTRoles.RECEIVER
        ).config(directory="tests/")

    _print = logger_generator.generate("SFT Client",
    {StdUsers.USER: Display.ALL, StdUsers.DEV: Display.ALL})
    client.connect()
    client.start(thread=True)

    if is_activate:
        if role == SFTRoles.RECEIVER:
            client.activate(SFTProtocols.SFT, role, token="tests/file.500MB")
        else:
            client.activate(SFTProtocols.SFT, role, path="tests/file.500MB", token="default")

    result = client.wait_result(SFTProtocols.SFT, role, timeout=60)
    client.close()
    _print(StdUsers.USER, StdLevels.INFO, "Result:", result)

def test_sft():
    t1 = threading.Thread(target=run_server, args=(SFTRoles.RECEIVER, True), name="SERVER")
    t1.start()

    time.sleep(1)

    t2 = threading.Thread(target=run_client, args=(SFTRoles.SENDER, False), name="CLIENT")
    t2.start()

    t1.join()
    t2.join()

if __name__ == "__main__":
    test_sft()
