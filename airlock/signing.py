"""ed25519 signing: `cryptography` if importable, else `openssl pkeyutl`."""
import os
import subprocess
import tempfile

from airlock.config import ROOT

KEYDIR = os.path.join(ROOT, "keys")
PRIV = os.path.join(KEYDIR, "airlock.key")
PUB = os.path.join(KEYDIR, "airlock.pub")

try:
    from cryptography.hazmat.primitives.asymmetric import ed25519
    from cryptography.hazmat.primitives import serialization
    from cryptography.exceptions import InvalidSignature
    HAVE_CRYPTO = True
except ImportError:
    HAVE_CRYPTO = False


def keygen(force=False):
    if os.path.exists(PRIV) and not force:
        return False
    if not os.path.isdir(KEYDIR):
        os.makedirs(KEYDIR)
    if HAVE_CRYPTO:
        key = ed25519.Ed25519PrivateKey.generate()
        priv = key.private_bytes(serialization.Encoding.PEM,
                                 serialization.PrivateFormat.PKCS8,
                                 serialization.NoEncryption())
        pub = key.public_key().public_bytes(serialization.Encoding.PEM,
                                            serialization.PublicFormat.SubjectPublicKeyInfo)
        with open(PRIV, "wb") as f:
            f.write(priv)
        with open(PUB, "wb") as f:
            f.write(pub)
    else:
        subprocess.check_call(["openssl", "genpkey", "-algorithm", "ed25519", "-out", PRIV])
        subprocess.check_call(["openssl", "pkey", "-in", PRIV, "-pubout", "-out", PUB])
    os.chmod(PRIV, 0o600)
    return True


def sign(data, priv_path=PRIV):
    if HAVE_CRYPTO:
        with open(priv_path, "rb") as f:
            key = serialization.load_pem_private_key(f.read(), None)
        return key.sign(data)
    with tempfile.NamedTemporaryFile() as t:
        t.write(data)
        t.flush()
        return subprocess.check_output(["openssl", "pkeyutl", "-sign", "-inkey", priv_path,
                                        "-rawin", "-in", t.name])


def verify(data, sig, pub_path=PUB):
    if HAVE_CRYPTO:
        with open(pub_path, "rb") as f:
            pub = serialization.load_pem_public_key(f.read())
        try:
            pub.verify(sig, data)
            return True
        except InvalidSignature:
            return False
    with tempfile.NamedTemporaryFile() as d, tempfile.NamedTemporaryFile() as s:
        d.write(data); d.flush()
        s.write(sig); s.flush()
        return subprocess.call(["openssl", "pkeyutl", "-verify", "-pubin", "-inkey", pub_path,
                                "-rawin", "-in", d.name, "-sigfile", s.name],
                               stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def fingerprint(pub_path=PUB):
    from airlock.bundle import sha256_file
    return sha256_file(pub_path)[:16]
