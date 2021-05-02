from hks_pylib.logger import LoggerGenerator, Display
from hks_pylib.logger import InvisibleLoggerGenerator

from hks_pynetwork.external import STCPSocket

from csbuilder.server import ServerResponser
from csbuilder.standard import StandardRole

from sft.protocol import DEFAULT_TIMEOUT, SFTRoles
from sft.protocol.sender_scheme import SFTSenderScheme
from sft.protocol.receiver_scheme import SFTReceiverScheme


class SFTServerResponser(ServerResponser):
    def __init__(self,
                role: SFTRoles,
                socket: STCPSocket,
                address: tuple,
                logger_generator: LoggerGenerator = InvisibleLoggerGenerator(),
                display: dict = {"dev": Display.ALL}
            ) -> None:
        assert isinstance(role.value, StandardRole)

        self._role = role

        super().__init__(
                socket=socket,
                address=address,
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
