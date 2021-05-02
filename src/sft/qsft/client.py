import os

from hks_pylib.logger import Display
from hks_pylib.logger.standard import StdUsers
from hks_pylib.cryptography.ciphers.hkscipher import HKSCipher
from hks_pylib.cryptography.ciphers.symmetrics import NoCipher
from hks_pylib.logger.logger_generator import InvisibleLoggerGenerator, LoggerGenerator

from sft.client import SFTClientResponser
from sft.qsft.definition import DEFAULT_ADDRESS
from sft.protocol.definition import SFTProtocols, SFTRoles


class QSFTClient(SFTClientResponser):
    def __init__(self,
                role: SFTRoles,
                cipher: HKSCipher = NoCipher(),
                address: tuple = DEFAULT_ADDRESS,
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {StdUsers.DEV: Display.ALL}
            ):
        super().__init__(
                role=role,
                cipher=cipher,
                address=address,
                logger_generator=logger_generator,
                display=display
            )
        
        self._role = role

        self.connect()

    def transfer(self, filename: str = None):
        if self._role == SFTRoles.RECEIVER and filename is not None:
            raise Exception("Receiver doesn't need parameter filename")

        if filename is not None and not os.path.isfile(filename):
            raise Exception("File not found.")
        
        self.start(True)

        if self._role == SFTRoles.SENDER:
            self.activate(SFTProtocols.SFT, filename=filename)

        result = self.wait_result(SFTProtocols.SFT)

        self.close()

        return result