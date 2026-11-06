"""Bounded loopback serving; never release authority state while a handler runs."""
import socket
import threading
import time

from werkzeug.serving import ThreadedWSGIServer, WSGIRequestHandler


SHUTDOWN_SECONDS = 3


class QuietHandler(WSGIRequestHandler):
    def setup(self):
        self.request.settimeout(2)
        super().setup()

    def log_request(self, code="-", size="-"): pass


class LocalServer(ThreadedWSGIServer):
    daemon_threads = True
    block_on_close = False

    def __init__(self, application):
        self.condition = threading.Condition()
        self.active = set()
        self.stopping = False
        self.shutdown_thread = None
        super().__init__("127.0.0.1", 0, application, handler=QuietHandler)

    def process_request(self, request, address):
        with self.condition:
            if self.stopping or len(self.active) >= 16:
                self.shutdown_request(request)
                return
            self.active.add(request)
            self.condition.notify_all()
        try:
            super().process_request(request, address)
        except BaseException:
            with self.condition:
                self.active.discard(request)
                self.condition.notify_all()
            self.shutdown_request(request)
            raise

    def process_request_thread(self, request, address):
        try:
            super().process_request_thread(request, address)
        finally:
            with self.condition:
                self.active.discard(request)
                self.condition.notify_all()

    def stop(self):
        deadline = time.monotonic() + SHUTDOWN_SECONDS
        with self.condition:
            self.stopping = True
            for request in list(self.active):
                try: request.shutdown(socket.SHUT_RDWR)
                except OSError: pass
            if self.shutdown_thread is None:
                self.shutdown_thread = threading.Thread(target=self.shutdown, daemon=True)
                self.shutdown_thread.start()
        self.shutdown_thread.join(max(0, deadline - time.monotonic()))
        if self.shutdown_thread.is_alive(): return False
        self.server_close()
        with self.condition:
            while self.active:
                remaining = deadline - time.monotonic()
                if remaining <= 0: return False
                self.condition.wait(remaining)
        return True
