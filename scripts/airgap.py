#!/usr/bin/env python3
"""Run the Airlock gateway inside an unprivileged, network-less Linux namespace.

The gateway process gets NO network interface except loopback, so its /probe egress test
fails because the kernel says so. It talks to the outside world through exactly two unix sockets:
  run/ollama.sock   host relay -> Ollama on 127.0.0.1:11434   (inference)
  run/gateway.sock  the gateway's HTTP server                 (forward it with `ssh -L 8000:<path>`)
Scope: only the gateway is isolated. Ollama still runs on the host network (reported as a POA&M gap).

    python3 scripts/airgap.py
"""
import os
import socket
import subprocess
import sys
import threading

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUN = os.path.join(ROOT, "run")
OLLAMA_SOCK = os.path.join(RUN, "ollama.sock")
GATEWAY_SOCK = os.path.join(RUN, "gateway.sock")
OLLAMA_ADDR = ("127.0.0.1", 11434)


def _pump(a, b):
    try:
        while True:
            data = a.recv(65536)
            if not data:
                break
            b.sendall(data)
    except OSError:
        pass
    finally:
        for s in (a, b):
            try:
                s.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass


def _serve_relay(listener, connect):
    def handle(c):
        try:
            u = connect()
        except OSError:
            c.close()
            return
        threading.Thread(target=_pump, args=(c, u), daemon=True).start()
        threading.Thread(target=_pump, args=(u, c), daemon=True).start()
    while True:
        c, _ = listener.accept()
        handle(c)


def _unix_listener(path):
    if os.path.exists(path):
        os.unlink(path)
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    os.chmod(path, 0o600)
    s.listen(16)
    return s


def outer():
    if not os.path.isdir(RUN):
        os.makedirs(RUN)
    os.chmod(RUN, 0o700)
    listener = _unix_listener(OLLAMA_SOCK)
    threading.Thread(target=_serve_relay, args=(listener, lambda: socket.create_connection(OLLAMA_ADDR, 3)),
                     daemon=True).start()
    env = dict(os.environ, AIRLOCK_SOCKET=GATEWAY_SOCK)
    print("host: relay %s -> %s:%d" % (OLLAMA_SOCK, OLLAMA_ADDR[0], OLLAMA_ADDR[1]))
    print("host: starting gateway in a network-less namespace (unshare -rn)")
    try:
        rc = subprocess.call(["unshare", "-rn", sys.executable, os.path.abspath(__file__), "--inner"], env=env, cwd=ROOT)
    except KeyboardInterrupt:
        rc = 0
    for p in (OLLAMA_SOCK, GATEWAY_SOCK):
        if os.path.exists(p):
            os.unlink(p)
    return rc


def inner():
    subprocess.check_call(["ip", "link", "set", "lo", "up"])
    with open("/proc/net/dev") as f:
        ifaces = [l.split(":")[0].strip() for l in f.readlines()[2:]]
    print("namespace: network interfaces = %s" % ", ".join(ifaces))
    lst = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    lst.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lst.bind(OLLAMA_ADDR)  # the gateway keeps talking to 127.0.0.1:11434; it lands on the unix relay
    lst.listen(16)

    def connect():
        s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        s.connect(OLLAMA_SOCK)
        return s
    threading.Thread(target=_serve_relay, args=(lst, connect), daemon=True).start()
    sys.path.insert(0, ROOT)
    from airlock import gateway
    gateway.serve()
    return 0


if __name__ == "__main__":
    sys.exit(inner() if "--inner" in sys.argv else outer())
