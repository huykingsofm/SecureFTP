import os
from typing import Callable
import csbuilder

from hks_pylib.done import Done
from hks_pylib.hksenum import HKSEnum

from csbuilder.scheme import Scheme
from csbuilder.scheme.result import SchemeResult
from csbuilder.cspacket.cspacket import CSPacket

from sft.file import FileReader
from sft.protocol import DEFAULT_INT_SIZE
from sft.protocol import DEFAULT_BUFFER_SIZE, DEFAULT_TOKEN
from sft.protocol.definition import SFTReceiverStates, SFTProtocols, SFTRoles


class SenderStep(HKSEnum):
    NONE = "none"
    REQUESTING = "requesting"
    WAITING = "waiting"
    SENDING = "sending"


@csbuilder.scheme(SFTProtocols.SFT, SFTRoles.SENDER, SFTReceiverStates.REQUEST)
class SFTSenderScheme(Scheme):
    def __init__(self, forwarder: str) -> None:
        super().__init__()

        self._forwarder: str = forwarder

        self._detoken_fn: Callable = lambda x: x

        self._buffer_size = DEFAULT_BUFFER_SIZE

        self._step: str = SenderStep.NONE

        self._file: FileReader = None

        self._info = {}

    def config(self, **kwargs):
        detoken = kwargs.pop("detoken", None)
        buffer_size = kwargs.pop("buffer_size", None)
        forwarder = kwargs.pop("forwarder", None)

        if kwargs:
            raise Exception("Invalid parameters {}.".format(list(kwargs.keys())))

        if buffer_size:
            if not isinstance(buffer_size, int) or buffer_size <= 0:
                raise Exception("Buffer size must be a positive integer.")

            self._buffer_size = buffer_size

        if detoken:
            if not callable(detoken):
                raise Exception("Token must must be a Callable object.")

            self._detoken_fn = detoken

        if forwarder:
            if not isinstance(forwarder, str):
                raise Exception("Forwarder must be a str object.")

            self._forwarder = forwarder

    def cancel(self, *args, **kwargs):
        self._step = SenderStep.NONE

        if self._file:
            self._file.close()
            self._file = None

        self._info = {}

        super().cancel(*args, **kwargs)

    @csbuilder.active_activation
    def activation(self, path: str, token: str = DEFAULT_TOKEN):
        if self._step is not SenderStep.NONE:
            return None, None

        if os.path.isfile(path) is False:
            raise Exception("File not found ({})".format(path))

        if not isinstance(token, str):
            raise Exception("Parameter token must be a str.")

        request_packet = self.generate_packet(self._states.REQUEST)
        request_packet.payload(token.encode())

        self._step = SenderStep.REQUESTING

        self._file = FileReader(path)

        return self._forwarder, request_packet

    @csbuilder.response(SFTReceiverStates.IGNORE)
    def resp_ignore(self, source: str, packet: CSPacket):
        return SchemeResult(
                None,
                None,
                False,
                Done(False, reason="Ignore", message=packet.payload()))

    def __create_info_packet(self):
        self._info["filename"] = self._file.name()

        file_digest = self._file.digest()
        filesize = self._file.size()

        info_packet = self.generate_packet(self._states.INFO)

        info_packet.payload(len(self._file.name()).to_bytes(DEFAULT_INT_SIZE, "big"))
        info_packet.update_payload(self._file.name().encode())

        info_packet.update_payload(len(file_digest).to_bytes(DEFAULT_INT_SIZE, "big"))
        info_packet.update_payload(file_digest)

        info_packet.update_payload(filesize.to_bytes(DEFAULT_INT_SIZE, "big"))

        return info_packet

    @csbuilder.response(SFTReceiverStates.REQUEST)
    def resp_request(self, source: str, packet: CSPacket):
        if self._step is SenderStep.NONE:
            deny_reason = None
            deny_packet = self.generate_packet(self._states.DENY)

            try:
                recv_token = packet.payload().decode()
                self._info["filename"] = self._detoken_fn(recv_token)
            except TimeoutError:
                deny_packet.payload(b"Expired token")
                deny_reason = "Expired token"
            except Exception as e:
                deny_packet.payload(b"Invalid token")
                deny_reason = "Invalid token ({})".format(e)

            if deny_reason:
                return SchemeResult(
                        source,
                        deny_packet,
                        False,
                        Done(False, reason=deny_reason)
                    )

            self._file = FileReader(self._info["filename"])

            info_packet = self.__create_info_packet()

            self._step = SenderStep.WAITING

            return SchemeResult(source, info_packet, True)
        else:
            return self.ignore(source, reason="Invalid step")

    @csbuilder.response(SFTReceiverStates.ACCEPT)
    def resp_accept(self, source: str, packet: CSPacket):
        if self._step == SenderStep.REQUESTING:
            info_packet = self.__create_info_packet()

            self._step = SenderStep.WAITING

            return SchemeResult(source, info_packet, True, Done(None))
        else:
            return self.ignore(source, reason="Invalid step")

    @csbuilder.response(SFTReceiverStates.DENY)
    def resp_deny(self, source: str, packet: CSPacket):
        if self._step is SenderStep.REQUESTING:
            return SchemeResult(
                    None,
                    None,
                    False,
                    Done(False, reason="Deny", message=packet.payload())
                )
        else:
            return self.ignore(source, reason="Invalid step")

    @csbuilder.response(SFTReceiverStates.REQUIRE)
    def resp_require(self, source: str, packet: CSPacket):
        if self._step == SenderStep.SENDING or self._step == SenderStep.WAITING:
            payload = packet.payload()

            boffset = payload[0: DEFAULT_INT_SIZE]
            bbuffer_size = payload[DEFAULT_INT_SIZE: 2 * DEFAULT_INT_SIZE]

            offset = int.from_bytes(boffset, "big")
            buffer_size = int.from_bytes(bbuffer_size, "big")

            nbytes_to_read = min(buffer_size, self._buffer_size)

            data = self._file.read(offset, nbytes_to_read)

            send_packet = self.generate_packet(self._states.SEND)

            send_packet.option(offset.to_bytes(DEFAULT_INT_SIZE, "big"))
            send_packet.payload(data)

            self._step = SenderStep.SENDING

            return SchemeResult(source, send_packet, True, Done(None))
        else:
            return self.ignore(source, reason="Invalid payload")

    @csbuilder.response(SFTReceiverStates.SUCCESS)
    def resp_success(self, source: str, packet: CSPacket):
        if self._step == SenderStep.SENDING or self._step == SenderStep.WAITING:
            return SchemeResult(
                    None,
                    None,
                    False,
                    Done(True, **self._info))
        else:
            return self.ignore(source, reason="Invalid step")

    @csbuilder.response(SFTReceiverStates.FAILURE)
    def resp_failure(self, source: str, packet: CSPacket):
        if self._step == SenderStep.SENDING or self._step == SenderStep.WAITING:
            message = packet.payload()
            return SchemeResult(
                    None,
                    None,
                    False,
                    Done(False, reason="Failure", message=message)
                )
        else:
            return self.ignore(source, reason="Invalid step")
