from hks_pylib.cryptography.hashes import SHA256, HKSHash


def get_file_digest(filename, buffer_size = 10 ** 6, hash_obj: HKSHash = SHA256()):
    hash_obj.reset()
    with open(filename, "rb") as stream:
        while True:
            data = stream.read(buffer_size)
            if not data:
                break
            hash_obj.update(data)
    return hash_obj.finalize()
