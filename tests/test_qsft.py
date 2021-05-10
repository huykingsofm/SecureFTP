import time
import threading

from hks_pylib.logger.standard import StdUsers, StdLevels
from sft.protocol import DEFAULT_TOKEN

from sft.protocol.definition import SFTRoles
from hks_pylib.logger import StandardLoggerGenerator

from sft.qsft.server import QSFTServer
from sft.qsft.client import QSFTClient


KEY = b"0123456789abcedffedcba9876543210"


def run_server(role: SFTRoles):
    logger_generator = StandardLoggerGenerator("tests/qsftserver.{}.log".format(role.name))

    logger = logger_generator.generate("SERVER", {StdUsers.USER: [StdLevels.INFO]})

    logger(StdUsers.USER, StdLevels.INFO, "SERVER RUN AS", role.name)
    server = QSFTServer(logger_generator=logger_generator)
    server.config(SFTRoles.RECEIVER, directory="./tests")

    if role == SFTRoles.SENDER:
        result = server.send()
    else:
        result = server.receive()

    logger(StdUsers.USER, StdLevels.INFO, "SERVER RESULT :", result)


def run_client(role: SFTRoles, filename):
    logger_generator = StandardLoggerGenerator("tests/qsftclient.{}.log".format(role.name))

    logger = logger_generator.generate("CLIENT", {StdUsers.USER: [StdLevels.INFO]})

    logger(StdUsers.USER, StdLevels.INFO, "CLIENT RUN AS", role.name)
    client = QSFTClient(logger_generator=logger_generator)
    client.config(SFTRoles.RECEIVER, directory="./tests")

    if role == SFTRoles.SENDER:
        result = client.send(filename)
    else:
        result = client.receive(filename)

    logger(StdUsers.USER, StdLevels.INFO, "CLIENT RESULT:", result)


def test_qsft():
    t1 = threading.Thread(
            target=run_server,
            args=(SFTRoles.SENDER, ),
            name="SERVER"
        )
    t1.start()

    time.sleep(1)

    t2 = threading.Thread(
            target=run_client,
            args=(SFTRoles.RECEIVER, "tests/file.500MB"),
            name="CLIENT"
        )
    t2.start()

    t1.join()
    t2.join()

if __name__ == "__main__":
    test_qsft()
