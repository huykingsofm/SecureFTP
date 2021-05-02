import io
import os
import random
import csbuilder

from hks_pylib.done import Done
from hks_pylib.hksenum import HKSEnum

from csbuilder.cspacket import CSPacket
from csbuilder.scheme import Scheme, SchemeResult

from sft.util import get_file_digest
from sft.protocol import DEFAULT_INT_SIZE
from sft.protocol import DEFAULT_BUFFER_SIZE, DEFAULT_TOKEN
from sft.protocol.definition import SFTSenderStates, SFTProtocols, SFTRoles


class ReceiverStep(HKSEnum):
    NONE = "none"
    ACCEPTED = "accepted"
    RECEIVING = "receiving"


DEFAULT_RECV_DIRECTORY = "./"


@csbuilder.scheme(SFTProtocols.SFT, SFTRoles.RECEIVER, SFTSenderStates.REQUEST)
class SFTReceiverScheme(Scheme):
    def __init__(self) -> None:
        super().__init__()

        self._directory = DEFAULT_RECV_DIRECTORY
        self._token = DEFAULT_TOKEN
        self._buffer_size = DEFAULT_BUFFER_SIZE

        self._step = ReceiverStep.NONE
        
        self._filename: str = None
        self._stream: io.BufferedIOBase = None
        self._offset: int = None
        self._filesize: int = None
        self._expected_file_digest: bytes = None

        self._max_try = 3
        self._remain_try = self._max_try

    def config(self, **kwargs):
        directory = kwargs.pop("directory", None)
        token = kwargs.pop("token", None)
        buffer_size = kwargs.pop("buffer_size", None)

        if kwargs:
            raise Exception("Invalid parameters {}.".format(list(kwargs.keys())))

        if directory:
            if not os.path.isdir(directory):
                raise Exception("Directory {} is not found.".format(directory))
            
            if self._role == SFTRoles.SENDER:
                raise Exception("The sender doesn't need paramters directory.")

            self._directory = directory

        if buffer_size:
            if not isinstance(buffer_size, int) or buffer_size <= 0:
                raise Exception("Buffer size must be a positive integer.")

            self._buffer_size = buffer_size

        if token:
            assert isinstance(token, str)
            self._token = token

    def cancel(self, *args, **kwargs):
        if self._stream is not None:
            self._stream.close()

        self._step = ReceiverStep.NONE
        self._filename = None
        self._stream = None
        self._offset = None
        self._filesize = None
        self._expected_file_digest = None
        self._remain_try = self._max_try
        super().cancel(*args, **kwargs)

    @csbuilder.response(SFTSenderStates.IGNORE)
    def resp_ignore(self, source: str, packet: CSPacket):
        return SchemeResult(None, None, False, Done(False, reason="Ignored."))

    @csbuilder.response(SFTSenderStates.REQUEST)
    def resp_request(self, source: str, packet: CSPacket):
        if self._step is ReceiverStep.NONE:
            deny_packet = CSPacket(self._protocol, self._states.DENY)
            accept_packet = CSPacket(self._protocol, self._states.ACCEPT)
            try:
                token = packet.payload().decode()
            except:
                return SchemeResult(
                        source,
                        deny_packet,
                        False,
                        Done(False, reason="Invalid token.")
                    )

            if token != self._token:
                return SchemeResult(
                        source,
                        deny_packet,
                        False,
                        Done(False, reason="Token mismatched")
                    )

            self._step = ReceiverStep.ACCEPTED

            return SchemeResult(
                    source,
                    accept_packet,
                    True,
                    Done(None)
                )
        else:
            return self.ignore(source)

    def __get_require_packet(self):
        boffset = self._offset.to_bytes(DEFAULT_INT_SIZE, "big")
        bbuffer_size = self._buffer_size.to_bytes(DEFAULT_INT_SIZE, "big")

        packet = CSPacket(self._protocol, self._states.REQUIRE)
        packet.payload(boffset)
        packet.update_payload(bbuffer_size)

        return packet

    @csbuilder.response(SFTSenderStates.INFO)
    def resp_info(self, source: str, packet: CSPacket):
        if self._step == ReceiverStep.ACCEPTED:
            self._step = ReceiverStep.RECEIVING

            filename_size = int.from_bytes(packet.payload()[0:DEFAULT_INT_SIZE], "big")
            filename = packet.payload()[DEFAULT_INT_SIZE : DEFAULT_INT_SIZE + filename_size].decode()

            current_cursor = DEFAULT_INT_SIZE + filename_size
            digest_size = int.from_bytes(
                    packet.payload()[current_cursor: current_cursor + DEFAULT_INT_SIZE],
                    "big"
                )
            current_cursor += DEFAULT_INT_SIZE
            digest = packet.payload()[current_cursor: current_cursor + digest_size]

            current_cursor += digest_size
            filesize = int.from_bytes(
                    packet.payload()[current_cursor: current_cursor + DEFAULT_INT_SIZE],
                    "big"
                )

            self._recv_filename = os.path.split(filename)[-1]

            tmp_file = "{}.{}".format(self._recv_filename, str(random.randint(10**7, 10**8)))
            self._filename = os.path.join(self._directory, tmp_file)
            self._stream = open(self._filename, "wb")
            self._expected_file_digest = digest
            self._filesize = filesize
            self._offset = 0

            packet = self.__get_require_packet()

            return SchemeResult(source, packet, True, Done(None))
        else:
            return self.ignore(source)

    @csbuilder.response(SFTSenderStates.SEND)
    def resp_send(self, source: str, packet: CSPacket):
        if self._step == ReceiverStep.RECEIVING:
            failure_packet = CSPacket(self._protocol, self._states.FAILURE)

            offset = int.from_bytes(packet.option()[0:DEFAULT_INT_SIZE], "big")

            if offset != self._offset:
                if self._remain_try > 0:
                    require_packet = self.__get_require_packet()
                    self._remain_try -= 1
                    return SchemeResult(
                            source,
                            require_packet,
                            True,
                            Done(None)
                        )
                else:
                    reason = "Wrong offset (tried {} times)".format(self._max_try)
                    failure_packet.payload(b"Wrong offset.")
                    return SchemeResult(
                            source,
                            failure_packet,
                            False,
                            Done(False, reason=reason)
                        )
            try:
                nbytes_wrritten = self._stream.write(packet.payload())
            except Exception as e:
                failure_packet.payload(repr(e).encode())
                return SchemeResult(
                        source,
                        failure_packet,
                        False,
                        Done(False, reason="Unknown error ({})".format(repr(e)))
                    )

            self._offset += nbytes_wrritten
            if self._offset == self._filesize:
                try:
                    self._stream.close()
                    self._stream = None

                    file_digest = get_file_digest(self._filename)

                    if file_digest != self._expected_file_digest:
                        failure_packet.payload(b"Integrity is compromised")
                        return SchemeResult(
                                source,
                                failure_packet,
                                False,
                                Done(False, reason="Integrity is compromised")
                            )

                except Exception as e:
                    failure_packet.payload(repr(e).encode())
                    return SchemeResult(
                            source,
                            failure_packet,
                            False,
                            Done(False, reason="Unknown error.")
                        )

                success_packet = CSPacket(self._protocol, self._states.SUCCESS)
                return SchemeResult(
                        source,
                        success_packet,
                        False,
                        Done(
                            True,
                            filename=self._filename,
                            recv_filename=self._recv_filename
                        )
                    )

            elif self._offset > self._filesize:
                failure_packet.payload(b"Received too much")
                return SchemeResult(
                        source,
                        failure_packet,
                        False,
                        Done(False, reason="Received too much")
                    )

            self._remain_try = self._max_try
            require_packet = self.__get_require_packet()

            return SchemeResult(source, require_packet, True, Done(None))
        else:
            return self.ignore(source)
