from hks_pylib.logger import Display
from hks_pylib.logger import LoggerGenerator
from hks_pylib.logger.standard import StdUsers
from hks_pylib.logger import InvisibleLoggerGenerator
from hks_pylib.cryptography.ciphers.hkscipher import HKSCipher

from csbuilder.client import ClientResponser

from sft.protocol.sender_scheme import SFTSenderScheme
from sft.protocol.receiver_scheme import SFTReceiverScheme
from sft.protocol import DEFAULT_TIMEOUT, DEFAULT_BUFFER_SIZE, SFTRoles


class SFTClientResponser(ClientResponser):
    def __init__(self,
                cipher: HKSCipher,
                address: tuple,
                role: SFTRoles,
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {StdUsers.DEV: Display.ALL},
                name: str = "SFTClient",
                buffer_size: int = DEFAULT_BUFFER_SIZE
            ) -> None:
        assert isinstance(role, SFTRoles)

        super().__init__(
            cipher=cipher,
            address=address,
            buffer_size=buffer_size,
            name=name,
            logger_generator=logger_generator,
            display=display
        )

        if role == SFTRoles.SENDER:
            self._scheme = SFTSenderScheme(forwarder_name=self._forwarder.name)
        else:
            self._scheme = SFTReceiverScheme()

        self.session_manager().create_session(
                scheme=self._scheme,
                timeout=DEFAULT_TIMEOUT,
                logger_generator=logger_generator,
                display=display
            )

    def config(self, **kwargs):
        self._scheme.config(**kwargs)
