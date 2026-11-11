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
    for k in list(conf):
        if k in os.environ and k.startswith("AIRLOCK_"):
            conf[k] = os.environ[k]
    return conf
