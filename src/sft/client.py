from hks_pylib.logger import Display
from hks_pylib.logger import LoggerGenerator
from hks_pylib.logger.standard import StdUsers
from hks_pylib.logger import InvisibleLoggerGenerator
from hks_pylib.cryptography.ciphers.hkscipher import HKSCipher

from csbuilder.client import ClientResponser

from sft.protocol.sender import SFTSenderScheme
from sft.protocol.receiver import SFTReceiverScheme
from sft.protocol import DEFAULT_TIMEOUT, DEFAULT_BUFFER_SIZE


class SFTClientResponser(ClientResponser):
    def __init__(self,
                cipher: HKSCipher,
                address: tuple,
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {StdUsers.DEV: Display.ALL},
                name: str = "SFTClient",
                buffer_size: int = DEFAULT_BUFFER_SIZE
            ) -> None:

        super().__init__(
                cipher=cipher,
                address=address,
                buffer_size=buffer_size,
                name=name,
                logger_generator=logger_generator,
                display=display
            )

        self.session_manager().create_session(
                scheme=SFTSenderScheme(forwarder=self._forwarder.name),
                timeout=DEFAULT_TIMEOUT,
                logger_generator=logger_generator,
                display=display
            )

        self.session_manager().create_session(
                scheme=SFTReceiverScheme(forwarder=self._forwarder.name),
                timeout=DEFAULT_TIMEOUT,
                logger_generator=logger_generator,
                display=display
            )

