import hashlib

CHUNK = 1024 * 1024


def sha256_file(path):
    """Hash a file in 1 MB chunks (GGUFs are >1 GB, RAM is small)."""
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(CHUNK)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def sha256_bytes(data):
    return hashlib.sha256(data).hexdigest()
