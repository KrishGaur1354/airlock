import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def load(path=None):
    """Parse airlock.conf (KEY=VALUE) by hand; environment overrides file."""
    conf = {}
    path = path or os.path.join(ROOT, "airlock.conf")
    if os.path.exists(path):
        with open(path) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                k, v = line.split("=", 1)
                conf[k.strip()] = v.strip()
    for k, v in os.environ.items():
        if k.startswith("AIRLOCK_"):
            conf[k] = v
    return conf
