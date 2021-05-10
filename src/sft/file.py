import os
from hks_pylib.cryptography.hashes import HKSHash, SHA256


class File(object):
    def __init__(self, filename: str) -> None:
        self._filename = filename
        self._stream = None

    def name(self):
        return self._filename

    def size(self):
        raise NotImplementedError()

    def digest(self, hash_obj: HKSHash = SHA256(), buffer_size: int = 65535):
        hash_obj.reset()
        with open(self._filename, "rb") as stream:
            while True:
                data = stream.read(buffer_size)
                if not data:
                    break
                hash_obj.update(data)
        return hash_obj.finalize()

    def close(self):
        if self._stream:
            self._stream.close()
            self._stream = None


class FileReader(File):
    def __init__(self, filename: str) -> None:
        super().__init__(filename)

        if os.path.isfile(self._filename) is False:
            raise Exception("File not found")

        self._stream = open(self._filename, "rb")
        self._filesize = os.path.getsize(filename)

    def size(self):
        return self._filesize

    def read(self, start: int = None, length: int = None):
        if start is not None:
            self._stream.seek(start)
        return self._stream.read(length)


class FileWriter(File):
    def __init__(self, filename: str) -> None:
        super().__init__(filename)
        self._stream = open(self._filename, "wb")
        self._current_size = 0

    def write(self, data: bytes):
        written_nbytes = self._stream.write(data)
        self._current_size += written_nbytes
        return written_nbytes

    def size(self):
        return self._current_size
