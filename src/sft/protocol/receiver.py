import os
import time
from typing import Callable

import csbuilder

from hks_pylib.done import Done
from hks_pylib.hksenum import HKSEnum

from csbuilder.cspacket import CSPacket
from csbuilder.scheme import Scheme, SchemeResult

from sft.file import FileWriter
from sft.protocol import DEFAULT_INT_SIZE
from sft.protocol import DEFAULT_BUFFER_SIZE, DEFAULT_TOKEN
from sft.protocol.definition import SFTSenderStates, SFTProtocols, SFTRoles


class ReceiverStep(HKSEnum):
    NONE = "none"
    REQUESTING = "requesting"
    ACCEPTED = "accepted"
    RECEIVING = "receiving"


DEFAULT_RECV_DIRECTORY = "./"


@csbuilder.scheme(SFTProtocols.SFT, SFTRoles.RECEIVER, SFTSenderStates.REQUEST)
class SFTReceiverScheme(Scheme):
    DEFAULT_NTRIES = 3

    def __init__(self, forwarder: str = None) -> None:
        super().__init__()

        self._forwarder = forwarder

        self._directory = DEFAULT_RECV_DIRECTORY

        self._detoken_fn: Callable = lambda x: x

        self._buffer_size = DEFAULT_BUFFER_SIZE

        self._step = ReceiverStep.NONE

        self._file: FileWriter = None
        self._expected_filesize: int = None
        self._expected_digest: bytes = None

        self._remain_ntries = self.DEFAULT_NTRIES

        self._info = {}

    def config(self, **kwargs):
        directory = kwargs.pop("directory", None)
        detoken = kwargs.pop("detoken", None)
        buffer_size = kwargs.pop("buffer_size", None)
        forwarder = kwargs.pop("forwarder", None)

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

        if detoken:
            if not callable(detoken):
                raise Exception("Paramameter tokens must be a Callable.")

            self._detoken_fn = detoken

        if forwarder:
            if not isinstance(forwarder, str):
                raise Exception("Parameter forwarder expected to be a str.")

            self._forwarder = forwarder

    def cancel(self, *args, **kwargs):
        self._step = ReceiverStep.NONE

        if self._file:
            self._file.close()
            self._file = None

        self._expected_filesize = None
        self._expected_digest = None

        self._remain_ntries = self.DEFAULT_NTRIES

        self._info = {}

        super().cancel(*args, **kwargs)
    
    
    @csbuilder.active_activation
    def activation(self, token: str = DEFAULT_TOKEN):
        if self._step is not ReceiverStep.NONE:
            return None, None

        if not isinstance(token, str):
            raise Exception("Parameter token must be a str.")

        request_packet = self.generate_packet(self._states.REQUEST)
        request_packet.payload(token.encode())

        self._step = ReceiverStep.REQUESTING

        return self._forwarder, request_packet

    @csbuilder.response(SFTSenderStates.IGNORE)
    def resp_ignore(self, source: str, packet: CSPacket):
        return SchemeResult(
                None,
                None,
                False,
                Done(False, reason="Ignore", message=packet.payload())
            )

    @csbuilder.response(SFTSenderStates.DENY)
    def resp_deny(self, source: str, packet: CSPacket):
        if self._step == ReceiverStep.REQUESTING:
            return SchemeResult(
                    None,
                    None,
                    False,
                    Done(False, reason="Deny", message=packet.payload())
                )
        else:
            return self.ignore(source, reason="Invalid step")

    @csbuilder.response(SFTSenderStates.REQUEST)
    def resp_request(self, source: str, packet: CSPacket):
        if self._step is ReceiverStep.NONE:
            deny_reason = None
            deny_packet = self.generate_packet(self._states.DENY)

            try:
                recv_token = packet.payload().decode()
                self._info["detoken_value"] = self._detoken_fn(recv_token)

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

            self._step = ReceiverStep.ACCEPTED

            accept_packet = self.generate_packet(self._states.ACCEPT)
            return SchemeResult(source, accept_packet, True)
        else:
            return self.ignore(source, reason="Invalid step")

    def __get_require_packet(self):
        boffset = self._file.size().to_bytes(DEFAULT_INT_SIZE, "big")
        bbuffer_size = self._buffer_size.to_bytes(DEFAULT_INT_SIZE, "big")

        packet = self.generate_packet(self._states.REQUIRE)
        packet.payload(boffset)
        packet.update_payload(bbuffer_size)

        return packet

    @csbuilder.response(SFTSenderStates.INFO)
    def resp_info(self, source: str, packet: CSPacket):
        if self._step == ReceiverStep.ACCEPTED or self._step == ReceiverStep.REQUESTING:
            payload = packet.payload()

            cursor = 0

            filename_size = int.from_bytes(payload[cursor: cursor + DEFAULT_INT_SIZE], "big")
            cursor += DEFAULT_INT_SIZE

            filename = payload[cursor: cursor + filename_size].decode()
            cursor += filename_size

            digest_size = int.from_bytes(payload[cursor: cursor + DEFAULT_INT_SIZE], "big")
            cursor += DEFAULT_INT_SIZE

            digest = payload[cursor: cursor + digest_size]
            cursor += digest_size

            filesize = int.from_bytes(payload[cursor: cursor + DEFAULT_INT_SIZE], "big")
            cursor += DEFAULT_INT_SIZE

            if len(payload[cursor:]) > 0:
                reason = "Too many parameters"
                failure_packet = self.generate_packet(self._states.FAILURE)
                failure_packet.payload(reason.encode())
                return SchemeResult(
                        source,
                        failure_packet,
                        False,
                        Done(False, reason=reason)
                    )

            original_filename = os.path.split(filename)[1]

            tmp_filename = ".".join([original_filename, str(time.time_ns())])
            tmp_path = os.path.join(self._directory, tmp_filename)

            self._file = FileWriter(tmp_path)
            self._expected_digest = digest
            self._expected_filesize = filesize

            self._step = ReceiverStep.RECEIVING

            packet = self.__get_require_packet()

            self._info["filename"] = original_filename
            self._info["path"] = tmp_path

            return SchemeResult(source, packet, True)
        else:
            return self.ignore(source, reason="Invalid step")

    @csbuilder.response(SFTSenderStates.SEND)
    def resp_send(self, source: str, packet: CSPacket):
        if self._step == ReceiverStep.RECEIVING:
            failure_packet = self.generate_packet(self._states.FAILURE)

            offset = int.from_bytes(packet.option()[0:DEFAULT_INT_SIZE], "big")

            if offset != self._file.size():
                if self._remain_ntries > 0:
                    require_packet = self.__get_require_packet()
                    self._remain_ntries -= 1
                    return SchemeResult(source, require_packet, True)

                else:
                    reason = "Wrong offset (tried {} times)".format(self.DEFAULT_NTRIES)
                    failure_packet.payload(b"Wrong offset.")
                    return SchemeResult(
                            source,
                            failure_packet,
                            False,
                            Done(False, reason=reason)
                        )
            try:
                self._file.write(packet.payload())
            except Exception as e:
                failure_packet.payload(b"Unknown error")
                return SchemeResult(
                        source,
                        failure_packet,
                        False,
                        Done(False, reason="Unknown error ({})".format(e))
                    )

            if self._file.size() == self._expected_filesize:
                try:
                    self._file.close()

                    if self._file.digest() != self._expected_digest:
                        failure_packet.payload(b"Integrity is compromised")
                        return SchemeResult(
                                source,
                                failure_packet,
                                False,
                                Done(False, reason="Integrity is compromised")
                            )

                except Exception as e:
                    failure_packet.payload(b"Unknown error")
                    return SchemeResult(
                            source,
                            failure_packet,
                            False,
                            Done(False, reason="Unknown error ({}).".format(e))
                        )

                success_packet = self.generate_packet(self._states.SUCCESS)
                return SchemeResult(
                        source,
                        success_packet,
                        False,
                        Done(True, **self._info)
                    )

            elif self._file.size() > self._expected_filesize:
                failure_packet.payload(b"Received too much")
                return SchemeResult(
                        source,
                        failure_packet,
                        False,
                        Done(False, reason="Received too much")
                    )

            self._remain_ntries = self.DEFAULT_NTRIES
            require_packet = self.__get_require_packet()

            return SchemeResult(source, require_packet, True)
        else:
            return self.ignore(source, reason="Invalid step")
