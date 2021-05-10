from hks_pylib.logger import LoggerGenerator, Display
from hks_pylib.logger import InvisibleLoggerGenerator
from hks_pylib.cryptography.ciphers.hkscipher import HKSCipher

from csbuilder.server import Listener

from sft.protocol import DEFAULT_TIMEOUT
from sft.protocol import DEFAULT_BUFFER_SIZE

from sft.protocol.sender import SFTSenderScheme
from sft.protocol import SFTProtocols, SFTRoles
from sft.protocol.receiver import SFTReceiverScheme


class SFTListener(Listener):
    def __init__(self,
                cipher: HKSCipher,
                address: tuple,
                name: str = "SFTListener",
                buffer_size: int = DEFAULT_BUFFER_SIZE,
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {"dev": Display.ALL}
            ) -> None:

        super().__init__(
                address=address,
                cipher=cipher,
                name=name,
                buffer_size=buffer_size,
                logger_generator=logger_generator,
                display=display
            )

        self.session_manager().create_session(
                scheme=SFTSenderScheme(forwarder=None),
                timeout=DEFAULT_TIMEOUT
            )

        self.session_manager().create_session(
                scheme=SFTReceiverScheme(forwarder=None),
                timeout=DEFAULT_TIMEOUT
            )


    def construct_responser(self, socket, address):
        responser = super().construct_responser(socket, address)

        forwarder = responser._forwarder.name

        responser.session_manager().get_scheme(
                SFTProtocols.SFT,
                SFTRoles.SENDER
            ).config(forwarder=forwarder)

        responser.session_manager().get_scheme(
                SFTProtocols.SFT,
                SFTRoles.RECEIVER
            ).config(forwarder=forwarder)

        return responser
