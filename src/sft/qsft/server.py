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
                role: SFTRoles,
                address: tuple = DEFAULT_ADDRESS,
                cipher: HKSCipher = NoCipher(),
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {StdUsers.DEV: Display.ALL}
            ) -> None:
        assert isinstance(role, SFTRoles)

        self._role = role

        self._listener = SFTListener(
                cipher=cipher,
                address=address,
                role=role,
                logger_generator=logger_generator,
                display=display
            )

        self._listener.listen()
        self._server = self._listener.accept(start_responser=False)
        self._listener.close()

    def config(self, **kwargs):
        self._server.session_manager().get_session(SFTProtocols.SFT).scheme().config(
                **kwargs
            )

    def transfer(self, filename: str = None):
        if self._role == SFTRoles.RECEIVER and filename is not None:
            raise Exception("Receiver doesn't need parameter filename")

        if filename is not None and not os.path.isfile(filename):
            raise Exception("File not found.")

        self._server.start(True)

        if self._role == SFTRoles.SENDER:
            self._server.activate(SFTProtocols.SFT, filename=filename)

        result = self._server.wait_result(SFTProtocols.SFT)

        self._server.close()
        
        return result
