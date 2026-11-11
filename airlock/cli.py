import sys

from airlock import signing
from airlock.bundle import sha256_file


def cmd_keygen(args):
    created = signing.keygen()
    print(("generated" if created else "exists") + " keys/airlock.pub fingerprint " + signing.fingerprint())
    return 0


def cmd_hash(args):
    for p in args:
        print(sha256_file(p) + "  " + p)
    return 0


COMMANDS = {"keygen": cmd_keygen, "hash": cmd_hash}


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if not argv or argv[0] not in COMMANDS:
        print("usage: python3 -m airlock {" + "|".join(sorted(COMMANDS)) + "}")
        return 2
    return COMMANDS[argv[0]](argv[1:])


if __name__ == "__main__":
    sys.exit(main())
