import configparser
import contextlib
from importlib.util import module_from_spec, spec_from_file_location
from os.path import dirname, join
import socketserver
import struct
from threading import Thread
from types import SimpleNamespace
import zlib

import pytest


def recv_exact(sock, size):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise ConnectionError("client closed the connection")
        data.extend(chunk)
    return bytes(data)


def send_server_init(sock, width=2, height=2):
    pixel_format = struct.pack("!BBBBHHHBBB3x", 32, 24, 0, 1, 255, 255, 255, 16, 8, 0)
    name = b"mock-vnc"
    sock.sendall(struct.pack("!HH", width, height) + pixel_format + struct.pack("!I", len(name)) + name)


class MockVNCServer:
    def __init__(self, scenario):
        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                with contextlib.suppress(BrokenPipeError, ConnectionResetError, ConnectionError):
                    scenario(self.request)

        self.server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), Handler)
        self.server.daemon_threads = True
        self.thread = Thread(target=self.server.serve_forever, daemon=True)

    @property
    def port(self):
        return self.server.server_address[1]

    def __enter__(self):
        self.thread.start()
        return self

    def __exit__(self, exc_type, exc_value, traceback):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()


class Logger:
    def __init__(self):
        self.messages = []

    def debug(self, message):
        self.messages.append(message)

    def display(self, message):
        self.messages.append(message)

    def fail(self, message):
        self.messages.append(message)

    def success(self, message):
        self.messages.append(message)

    def highlight(self, message):
        self.messages.append(message)


@pytest.fixture(scope="module")
def protocol():
    path = join(dirname(dirname(__file__)), "nxc", "protocols", "vnc.py")
    spec = spec_from_file_location("nxc_vnc_protocol_test", path)
    module = module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def make_connection(protocol, port):
    obj = object.__new__(protocol.vnc)
    obj.host = "127.0.0.1"
    obj.port = port
    obj.hostname = "mock-vnc"
    obj.args = SimpleNamespace(vnc_timeout=2, screentime=0)
    obj.logger = Logger()
    obj.config = configparser.ConfigParser()
    obj.config.add_section("nxc")
    obj.config.set("nxc", "pwn3d_label", "Pwn3d!")
    obj.password = ""
    obj.username = ""
    obj.admin_privs = False
    obj.conn = None
    obj.RFBversion = None
    obj.rfb_version = None
    obj.server_version = None
    obj.stype = None
    obj.security_types = []
    obj.auth_methods = []
    obj.auth_type = None
    obj.noauth = False
    obj.error_reason = None
    obj.framebuffer_width = 0
    obj.framebuffer_height = 0
    obj.server_name = ""
    obj.pixel_format = None
    return obj


def test_rfb_38_security_type_enumeration(protocol):
    def scenario(sock):
        sock.sendall(b"RFB 003.008\n")
        assert recv_exact(sock, 12) == b"RFB 003.008\n"
        sock.sendall(b"\x02\x01\x02")

    with MockVNCServer(scenario) as server:
        connection = make_connection(protocol, server.port)
        assert connection.probe_rfb() == [1, 2]
        assert connection.RFBversion == pytest.approx(3.8)
        assert connection.noauth is True
        assert connection.auth_methods == ["None", "VNC Authentication"]


def test_rfb_33_security_failure_reason(protocol):
    def scenario(sock):
        sock.sendall(b"RFB 003.003\n")
        assert recv_exact(sock, 12) == b"RFB 003.003\n"
        reason = b"too many security failures"
        sock.sendall(struct.pack("!I", 0) + struct.pack("!I", len(reason)) + reason)

    with MockVNCServer(scenario) as server:
        connection = make_connection(protocol, server.port)
        assert connection.probe_rfb() is None
        assert "too many security failures" in connection.error_reason


def test_rfb_38_security_failure_reason(protocol):
    def scenario(sock):
        sock.sendall(b"RFB 003.008\n")
        recv_exact(sock, 12)
        reason = b"no matching security type"
        sock.sendall(b"\x00" + struct.pack("!I", len(reason)) + reason)

    with MockVNCServer(scenario) as server:
        connection = make_connection(protocol, server.port)
        assert connection.probe_rfb() is None
        assert "no matching security type" in connection.error_reason


def test_vnc_authentication_success(protocol):
    response = {}

    def scenario(sock):
        sock.sendall(b"RFB 003.008\n")
        recv_exact(sock, 12)
        sock.sendall(b"\x02\x01\x02")
        assert recv_exact(sock, 1) == b"\x02"
        challenge = bytes(range(16))
        sock.sendall(challenge)
        response["value"] = recv_exact(sock, 16)
        sock.sendall(struct.pack("!I", 0))
        assert recv_exact(sock, 1) == b"\x01"
        send_server_init(sock)

    with MockVNCServer(scenario) as server:
        connection = make_connection(protocol, server.port)
        assert connection.plaintext_login("", "secret") is True
        assert len(response["value"]) == 16
        assert response["value"] != bytes(range(16))
        assert connection.auth_type == 2
        assert any("Pwn3d" in message for message in connection.logger.messages)


def test_vnc_authentication_failure_reason(protocol):
    def scenario(sock):
        sock.sendall(b"RFB 003.008\n")
        recv_exact(sock, 12)
        sock.sendall(b"\x01\x02")
        assert recv_exact(sock, 1) == b"\x02"
        sock.sendall(bytes(range(16)))
        recv_exact(sock, 16)
        reason = b"password mismatch"
        sock.sendall(struct.pack("!I", 1) + struct.pack("!I", len(reason)) + reason)

    with MockVNCServer(scenario) as server:
        connection = make_connection(protocol, server.port)
        assert connection.plaintext_login("", "wrong") is False
        assert any("Authentication failed: password mismatch" in message for message in connection.logger.messages)


def read_png_rgb(filename):
    data = filename.read_bytes()
    assert data.startswith(b"\x89PNG\r\n\x1a\n")
    offset = 8
    width = height = None
    compressed = bytearray()
    while offset < len(data):
        length = struct.unpack("!I", data[offset:offset + 4])[0]
        chunk_type = data[offset + 4:offset + 8]
        chunk_data = data[offset + 8:offset + 8 + length]
        offset += 12 + length
        if chunk_type == b"IHDR":
            width, height = struct.unpack("!II", chunk_data[:8])
        elif chunk_type == b"IDAT":
            compressed.extend(chunk_data)
        elif chunk_type == b"IEND":
            break
    scanlines = zlib.decompress(compressed)
    stride = width * 3
    assert len(scanlines) == height * (stride + 1)
    rgb = bytearray()
    for row in range(height):
        start = row * (stride + 1)
        assert scanlines[start] == 0
        rgb.extend(scanlines[start + 1:start + 1 + stride])
    return width, height, rgb


def test_screenshot_raw_framebuffer(protocol, tmp_path, monkeypatch):
    def scenario(sock):
        sock.sendall(b"RFB 003.008\n")
        recv_exact(sock, 12)
        sock.sendall(b"\x01\x01")
        assert recv_exact(sock, 1) == b"\x01"
        sock.sendall(struct.pack("!I", 0))
        assert recv_exact(sock, 1) == b"\x01"
        send_server_init(sock)
        assert recv_exact(sock, 20)[0] == 0
        assert recv_exact(sock, 8)[0] == 2
        assert recv_exact(sock, 10)[0] == 3
        pixels = b"\x00\x00\xff\x00" + b"\x00\xff\x00\x00" + b"\xff\x00\x00\x00" + b"\xff\xff\xff\x00"
        sock.sendall(b"\x00\x00\x00\x01" + struct.pack("!HHHHi", 0, 0, 2, 2, 0) + pixels)

    monkeypatch.setattr(protocol, "NXC_PATH", str(tmp_path))
    with MockVNCServer(scenario) as server:
        connection = make_connection(protocol, server.port)
        connection.screenshot()
        screenshots = list((tmp_path / "screenshots").glob("*.png"))
        assert len(screenshots) == 1
        width, height, rgb = read_png_rgb(screenshots[0])
        assert (width, height) == (2, 2)
        assert bytes(rgb) == b"\xff\x00\x00\x00\xff\x00\x00\x00\xff\xff\xff\xff"
        assert any("Screenshot saved" in message for message in connection.logger.messages)


def test_screenshot_unsupported_encoding_reason(protocol, tmp_path, monkeypatch):
    def scenario(sock):
        sock.sendall(b"RFB 003.008\n")
        recv_exact(sock, 12)
        sock.sendall(b"\x01\x01")
        recv_exact(sock, 1)
        sock.sendall(struct.pack("!I", 0))
        recv_exact(sock, 1)
        send_server_init(sock)
        recv_exact(sock, 20)
        recv_exact(sock, 8)
        recv_exact(sock, 10)
        sock.sendall(b"\x00\x00\x00\x01" + struct.pack("!HHHHi", 0, 0, 2, 2, 2))

    monkeypatch.setattr(protocol, "NXC_PATH", str(tmp_path))
    with MockVNCServer(scenario) as server:
        connection = make_connection(protocol, server.port)
        connection.screenshot()
        assert any("Screenshot failed: unsupported framebuffer encoding 2" in message for message in connection.logger.messages)
