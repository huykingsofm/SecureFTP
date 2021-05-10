import os

from hks_pylib.logger import Display
from hks_pylib.logger.standard import StdUsers
from hks_pylib.cryptography.ciphers.hkscipher import HKSCipher
from hks_pylib.cryptography.ciphers.symmetrics import NoCipher
from hks_pylib.logger.logger_generator import InvisibleLoggerGenerator, LoggerGenerator

from sft.client import SFTClientResponser
from sft.qsft.definition import DEFAULT_ADDRESS
from sft.protocol.definition import SFTProtocols, SFTRoles


class QSFTClient(object):
    def __init__(self,
                cipher: HKSCipher = NoCipher(),
                address: tuple = DEFAULT_ADDRESS,
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {StdUsers.DEV: Display.ALL}
            ):
        self._client = SFTClientResponser(
                cipher=cipher,
                address=address,
                logger_generator=logger_generator,
                display=display
            )

        self._client.connect()

        self._client.start(True)

    def config(self, role: SFTRoles, **kwargs):
        self._client.session_manager().get_scheme(
                SFTProtocols.SFT,
                role
            ).config(**kwargs)

    def send(self, path: str):
        if not os.path.isfile(path):
            raise Exception("File not found.")

        self._client.activate(SFTProtocols.SFT, SFTRoles.SENDER, path=path)

        result = self._client.wait_result(SFTProtocols.SFT, SFTRoles.SENDER, timeout=60)

        self._client.close()

        return result

    def receive(self, filename):
        self._client.activate(SFTProtocols.SFT, SFTRoles.RECEIVER, token=filename)

        result = self._client.wait_result(SFTProtocols.SFT, SFTRoles.RECEIVER, timeout=60)

        self._client.close()

        return result
