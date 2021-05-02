import io
import os
import csbuilder

from hks_pylib.done import Done
from hks_pylib.hksenum import HKSEnum

from csbuilder.scheme import Scheme
from csbuilder.scheme.result import SchemeResult
from csbuilder.cspacket.cspacket import CSPacket

from sft.util import get_file_digest
from sft.protocol import DEFAULT_INT_SIZE
from sft.protocol import DEFAULT_BUFFER_SIZE, DEFAULT_TOKEN
from sft.protocol.definition import SFTReceiverStates, SFTProtocols, SFTRoles


class SenderStep(HKSEnum):
    NONE = "none"
    REQUESTING = "requesting"
    SENDING = "sending"


@csbuilder.scheme(SFTProtocols.SFT, SFTRoles.SENDER)
class SFTSenderScheme(Scheme):
    def __init__(self, forwarder_name: str) -> None:
        super().__init__()

        self._forwarder_name: str = forwarder_name

        self._buffer_size = DEFAULT_BUFFER_SIZE
        self._token = DEFAULT_TOKEN

        self._step: str = SenderStep.NONE
        self._filename: str = None
        self._stream: io.BufferedIOBase = None

    def config(self, **kwargs):
        token = kwargs.pop("token", None)
        buffer_size = kwargs.pop("buffer_size", None)

        if kwargs:
            raise Exception("Invalid parameters {}.".format(list(kwargs.keys())))

        if buffer_size:
            if not isinstance(buffer_size, int) or buffer_size <= 0:
                raise Exception("Buffer size must be a positive integer.")

            self._buffer_size = buffer_size

        if token:
            if not isinstance(token, str):
                raise Exception("Token must be a str object.")
            self._token = token

    def cancel(self, *args, **kwargs):
        if self._stream is not None:
            self._stream.close()

        self._step = SenderStep.NONE
        self._stream = None
        self._filename = None
        super().cancel(*args, **kwargs)

    @csbuilder.activation
    def activation(self, filename: str, *args):
        if self._step is not SenderStep.NONE:
            return None, None

        if os.path.isfile(filename) is False:
            raise Exception("File not found ({})".format(filename))

        request_packet = CSPacket(self._protocol, self._states.REQUEST)
        request_packet.payload(self._token.encode())

        self._step = SenderStep.REQUESTING
        self._filename = filename

        return self._forwarder_name, request_packet

    @csbuilder.response(SFTReceiverStates.IGNORE)
    def resp_ignore(self, source: str, packet: CSPacket):
        return SchemeResult(None, None, False, Done(False, reason="Ignored."))

    @csbuilder.response(SFTReceiverStates.ACCEPT)
    def resp_accept(self, source: str, packet: CSPacket):
        if self._step == SenderStep.REQUESTING:
            self._step = SenderStep.SENDING
            
            file_digest = get_file_digest(self._filename)
            filesize = os.path.getsize(self._filename)
            self._stream = open(self._filename, "rb")
            
            info_packet = CSPacket(self._protocol, self._states.INFO)
            
            info_packet.payload(len(self._filename).to_bytes(DEFAULT_INT_SIZE, "big"))
            info_packet.update_payload(self._filename.encode())
            
            info_packet.update_payload(len(file_digest).to_bytes(DEFAULT_INT_SIZE, "big"))
            info_packet.update_payload(file_digest)
            
            info_packet.update_payload(filesize.to_bytes(DEFAULT_INT_SIZE, "big"))

            return SchemeResult(source, info_packet, True, Done(None))
        else:
            return self.ignore(source)

    @csbuilder.response(SFTReceiverStates.DENY)
    def resp_deny(self, source: str, packet: CSPacket):
        if self._step is SenderStep.REQUESTING:
            return SchemeResult(None, None, False, Done(False, reason="Denied."))
        else:
            return self.ignore(source)
    
    @csbuilder.response(SFTReceiverStates.REQUIRE)
    def resp_require(self, source: str, packet: CSPacket):
        if self._step == SenderStep.SENDING:
            offset = int.from_bytes(packet.payload()[0:DEFAULT_INT_SIZE], "big")
            recv_buffer_size = int.from_bytes(packet.payload()[DEFAULT_INT_SIZE: 2 * DEFAULT_INT_SIZE], "big")

            nbytes_to_read = min(recv_buffer_size, self._buffer_size)

            self._stream.seek(offset)
            data = self._stream.read(nbytes_to_read)

            send_packet = CSPacket(self._protocol, self._states.SEND)

            send_packet.option(offset.to_bytes(DEFAULT_INT_SIZE, "big"))
            send_packet.payload(data)

            return SchemeResult(source, send_packet, True, Done(None))
        else:
            return self.ignore(source)
    
    @csbuilder.response(SFTReceiverStates.SUCCESS)
    def resp_success(self, source: str, packet: CSPacket):
        if self._step == SenderStep.SENDING:
            return SchemeResult(None, None, False, Done(True))
        else:
            return self.ignore(source)
    
    @csbuilder.response(SFTReceiverStates.FAILURE)
    def resp_failure(self, source: str, packet: CSPacket):
        if self._step == SenderStep.SENDING:
            reason = packet.payload()
            return SchemeResult(None, None, False, Done(False, reason=reason))
        else:
            return self.ignore(source)
