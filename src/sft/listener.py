from hks_pylib.logger import LoggerGenerator, Display
from hks_pylib.logger import InvisibleLoggerGenerator
from hks_pylib.cryptography.ciphers.hkscipher import HKSCipher

from csbuilder.server import Listener

from sft.server import SFTServerResponser
from sft.protocol import DEFAULT_BUFFER_SIZE, SFTRoles


class SFTListener(Listener):
    def __init__(self,
                cipher: HKSCipher,
                address: tuple,
                role: SFTRoles,
                name: str = "SFTListener",
                buffer_size: int = DEFAULT_BUFFER_SIZE,
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {"dev": Display.ALL}
            ) -> None:
        assert isinstance(role, SFTRoles)

        super().__init__(
                address=address,
                cipher=cipher,
                responser_cls=SFTServerResponser,
                name=name,
                buffer_size=buffer_size,
                logger_generator=logger_generator,
                display=display
            )

        self.config_responser(role=role)  
