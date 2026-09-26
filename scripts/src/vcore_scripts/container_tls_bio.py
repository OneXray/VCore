"""Fixture-only public OpenSSL MemoryBIO driver; never a TLS implementation."""

import ssl


class TlsBio:
    def __init__(self, stream, context, *, server):
        self.stream = stream
        self.incoming = ssl.MemoryBIO()
        self.outgoing = ssl.MemoryBIO()
        self.tls = context.wrap_bio(
            self.incoming,
            self.outgoing,
            server_side=server,
            server_hostname=None if server else "localhost",
        )
        self.perform(self.tls.do_handshake)

    def flush(self):
        while self.outgoing.pending:
            self.stream.sendall(self.outgoing.read())

    def perform(self, operation, *args):
        while True:
            try:
                result = operation(*args)
                self.flush()
                return result
            except ssl.SSLWantWriteError:
                self.flush()
            except ssl.SSLWantReadError:
                self.flush()
                chunk = self.stream.recv(65536)
                if chunk:
                    self.incoming.write(chunk)
                else:
                    self.incoming.write_eof()

    def recv(self, length):
        try:
            return self.perform(self.tls.read, length)
        except (ssl.SSLEOFError, ssl.SSLZeroReturnError):
            return b""

    def sendall(self, data):
        offset = 0
        while offset < len(data):
            offset += self.perform(self.tls.write, data[offset:])
