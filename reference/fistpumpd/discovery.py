import json
import socket
import threading
import time

MAX = 4096


class Responder:
    def __init__(self, port, info, bind="0.0.0.0"):
        self.info = info
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.socket.bind((bind, port))
        self.port = self.socket.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self.loop, daemon=True)

    def start(self):
        self.thread.start()
        return self

    def loop(self):
        self.socket.settimeout(0.5)
        while self.running:
            try:
                data, sender = self.socket.recvfrom(MAX)
            except socket.timeout:
                continue
            except OSError:
                return
            try:
                message = json.loads(data)
            except ValueError:
                continue
            if isinstance(message, dict) and message.get("who") and message.get("reply") is not None:
                reply = json.dumps(self.info() if callable(self.info) else self.info).encode()
                try:
                    self.socket.sendto(reply, (sender[0], int(message["reply"])))
                except (OSError, ValueError):
                    pass

    def stop(self):
        self.running = False
        self.socket.close()


def probe(targets, wait=3.0, bind="0.0.0.0"):
    listener = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listener.bind((bind, 0))
    listener.settimeout(0.2)
    reply_port = listener.getsockname()[1]
    sender = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sender.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
    found = {}
    deadline = time.monotonic() + wait
    sent = 0.0
    try:
        while time.monotonic() < deadline:
            if time.monotonic() - sent > 1.0:
                for target in targets:
                    try:
                        sender.sendto(json.dumps({"who": True, "reply": reply_port}).encode(), tuple(target))
                    except OSError:
                        pass
                sent = time.monotonic()
            try:
                data, _ = listener.recvfrom(MAX)
            except socket.timeout:
                continue
            try:
                info = json.loads(data)
            except ValueError:
                continue
            if isinstance(info, dict) and isinstance(info.get("addr"), str):
                found[info["addr"]] = info
    finally:
        listener.close()
        sender.close()
    return list(found.values())
