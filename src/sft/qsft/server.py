import os

from hks_pylib.logger import Display
from hks_pylib.logger.standard import StdUsers
from hks_pylib.cryptography.ciphers.hkscipher import HKSCipher
from hks_pylib.cryptography.ciphers.symmetrics import NoCipher
from hks_pylib.logger.logger_generator import InvisibleLoggerGenerator, LoggerGenerator

from sft.listener import SFTListener
from sft.qsft.definition import DEFAULT_ADDRESS
from sft.protocol.definition import SFTProtocols, SFTRoles


class QSFTServer(object):
    def __init__(self,
                address: tuple = DEFAULT_ADDRESS,
                cipher: HKSCipher = NoCipher(),
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {StdUsers.DEV: Display.ALL}
            ) -> None:

        self._listener = SFTListener(
                cipher=cipher,
                address=address,
                logger_generator=logger_generator,
                display=display
            )

    def config(self, role: SFTRoles, **kwargs):
        self._listener.session_manager().get_session(
                SFTProtocols.SFT,
                role
            ).scheme().config(**kwargs)

    def send(self):
        self._listener.listen()
        self._server = self._listener.accept()
        self._listener.close()

        result = self._server.wait_result(SFTProtocols.SFT, SFTRoles.SENDER)

        self._server.close()

        return result

    def receive(self):
        self._listener.listen()
        self._server = self._listener.accept()
        self._listener.close()

        result = self._server.wait_result(SFTProtocols.SFT, SFTRoles.RECEIVER)

        self._server.close()

        return result
