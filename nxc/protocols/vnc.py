import asyncio
from datetime import datetime
from pathlib import Path
import re
import socket
import struct
from time import sleep
import zlib

from cryptography.hazmat.primitives.ciphers import Cipher, modes
from termcolor import colored
try:
    from cryptography.hazmat.decrepit.ciphers.algorithms import TripleDES
except ImportError:
    from cryptography.hazmat.primitives.ciphers.algorithms import TripleDES

from nxc.config import host_info_colors
from nxc.connection import connection
from nxc.helpers.logger import highlight
from nxc.helpers.path import sanitize_path_component
from nxc.logger import NXCAdapter
from nxc.paths import NXC_PATH


SECURITY_TYPES = {
    0: "Invalid",
    1: "None",
    2: "VNC Authentication",
    5: "RA2",
    6: "RA2ne",
    16: "Tight",
    17: "Ultra",
    18: "TLS",
    19: "VeNCrypt",
    20: "GTK-VNC SASL",
    21: "MD5 Hash Authentication",
    22: "Colin Dean xvp",
    30: "Apple Remote Desktop",
    35: "RSA-AES",
    113: "MSLogonII",
}

SUPPORTED_VERSIONS = ((3, 8), (3, 7), (3, 3))
PNG_SIGNATURE = b"\x89PNG\r\n\x1a\n"


class VNCError(Exception):
    pass


class VNCProtocolError(VNCError):
    pass


class VNCAuthenticationError(VNCError):
    pass


class VNCUnsupportedAuthentication(VNCError):
    pass


class VNCDisplayError(VNCError):
    pass


def read_exact(sock, size, stage):
    data = bytearray()
    while len(data) < size:
        chunk = sock.recv(size - len(data))
        if not chunk:
            raise VNCProtocolError(f"connection closed while reading {stage}")
        data.extend(chunk)
    return bytes(data)


def read_reason(sock):
    length = struct.unpack("!I", read_exact(sock, 4, "failure reason length"))[0]
    if length > 1024 * 1024:
        raise VNCProtocolError(f"failure reason is too long ({length} bytes)")
    return read_exact(sock, length, "failure reason").decode("utf-8", errors="replace")


def security_type_name(security_type):
    return SECURITY_TYPES.get(security_type, f"Unknown ({security_type})")


def parse_version(banner):
    match = re.fullmatch(rb"RFB (\d{3})\.(\d{3})\n", banner)
    if not match:
        raise VNCProtocolError(f"invalid RFB banner {banner!r}")
    return int(match.group(1)), int(match.group(2))


def negotiate_version(server_version):
    for version in SUPPORTED_VERSIONS:
        if server_version >= version:
            return version
    raise VNCProtocolError(f"unsupported RFB version {server_version[0]}.{server_version[1]}")


def read_security_types(sock, version):
    if version == (3, 3):
        security_type = struct.unpack("!I", read_exact(sock, 4, "security type"))[0]
        if security_type == 0:
            raise VNCProtocolError(f"server refused connection: {read_reason(sock)}")
        return [security_type]

    count = read_exact(sock, 1, "security type count")[0]
    if count == 0:
        raise VNCProtocolError(f"server refused connection: {read_reason(sock)}")
    return list(read_exact(sock, count, "security types"))


def encrypt_challenge(password, challenge):
    key = password.encode("latin-1", errors="replace")[:8].ljust(8, b"\0")
    reversed_key = bytes(int(f"{byte:08b}"[::-1], 2) for byte in key)
    encryptor = Cipher(TripleDES(reversed_key * 3), modes.ECB()).encryptor()
    return encryptor.update(challenge) + encryptor.finalize()


def png_chunk(chunk_type, data):
    return struct.pack("!I", len(data)) + chunk_type + data + struct.pack("!I", zlib.crc32(chunk_type + data) & 0xFFFFFFFF)


def write_png(filename, width, height, rgb):
    stride = width * 3
    scanlines = bytearray()
    for row in range(height):
        scanlines.append(0)
        scanlines.extend(rgb[row * stride:(row + 1) * stride])
    image = PNG_SIGNATURE
    image += png_chunk(b"IHDR", struct.pack("!IIBBBBB", width, height, 8, 2, 0, 0, 0))
    image += png_chunk(b"IDAT", zlib.compress(scanlines))
    image += png_chunk(b"IEND", b"")
    Path(filename).write_bytes(image)


class vnc(connection):
    def __init__(self, args, db, host):
        self.RFBversion = None
        self.rfb_version = None
        self.server_version = None
        self.stype = None
        self.security_types = []
        self.auth_methods = []
        self.auth_type = None
        self.noauth = False
        self.error_reason = None
        self.framebuffer_width = 0
        self.framebuffer_height = 0
        self.server_name = ""
        self.pixel_format = None
        connection.__init__(self, args, db, host)

    def proto_logger(self):
        self.logger = NXCAdapter(
            extra={
                "protocol": "VNC",
                "host": self.host,
                "port": self.port,
                "hostname": self.hostname,
            }
        )

    def print_host_info(self):
        if self.RFBversion is None:
            return
        noauth = colored(f" (No Auth:{self.noauth})", host_info_colors[2], attrs=["bold"]) if self.noauth else ""
        self.logger.display(f"RFB {self.RFBversion}{noauth}")
        if self.auth_methods:
            self.logger.display(f"Authentication methods: {', '.join(self.auth_methods)}")

    def probe_rfb(self):
        try:
            with socket.create_connection((self.host, self.port), timeout=self.args.vnc_timeout) as sock:
                version, security_types = self.handshake(sock)
        except (OSError, VNCError) as e:
            self.error_reason = str(e)
            self.logger.debug(f"RFB probe failed: {e}")
            return None

        self.rfb_version = version
        self.RFBversion = float(f"{version[0]}.{version[1]}")
        self.security_types = security_types
        self.auth_methods = [security_type_name(security_type) for security_type in security_types]
        self.noauth = 1 in security_types
        return security_types

    def handshake(self, sock):
        banner = read_exact(sock, 12, "server banner")
        server_version = parse_version(banner)
        version = negotiate_version(server_version)
        self.server_version = server_version
        sock.sendall(f"RFB {version[0]:03d}.{version[1]:03d}\n".encode())
        return version, read_security_types(sock, version)

    def enum_host_info(self):
        self.stype = self.probe_rfb()
        if self.stype is None:
            self.logger.fail(f"RFB handshake failed: {self.error_reason}")
        else:
            self.logger.debug(f"RFB {self.RFBversion} security types: {self.stype}")

    def create_conn_obj(self):
        try:
            with socket.create_connection((self.host, self.port), timeout=self.args.vnc_timeout):
                pass
        except TimeoutError as e:
            self.logger.debug(f"Connection timed out: {e}")
            self.logger.fail(f"Connection timed out after {self.args.vnc_timeout}s")
            return False
        except ConnectionRefusedError as e:
            self.logger.debug(f"Connection refused: {e}")
            self.logger.fail("Connection refused")
            return False
        except OSError as e:
            self.logger.fail(f"Connection failed: {e}")
            return False
        return True

    def select_security_type(self, security_types, password):
        ordered = (2, 1) if password else (1, 2)
        for security_type in ordered:
            if security_type in security_types:
                return security_type
        return security_types[0]

    def read_security_result(self, sock, version):
        result = struct.unpack("!I", read_exact(sock, 4, "security result"))[0]
        if result == 0:
            return
        if version >= (3, 8):
            try:
                reason = read_reason(sock)
            except VNCProtocolError as e:
                raise VNCAuthenticationError(f"server rejected authentication ({e})") from e
            raise VNCAuthenticationError(reason or "server rejected authentication")
        raise VNCAuthenticationError("server rejected authentication")

    def authenticate(self, sock, version, security_types, password):
        security_type = security_types[0] if version == (3, 3) else self.select_security_type(security_types, password)
        self.auth_type = security_type
        if version > (3, 3):
            sock.sendall(bytes([security_type]))

        if security_type == 1:
            if version >= (3, 8):
                self.read_security_result(sock, version)
        elif security_type == 2:
            challenge = read_exact(sock, 16, "VNC authentication challenge")
            sock.sendall(encrypt_challenge(password, challenge))
            self.read_security_result(sock, version)
        else:
            raise VNCUnsupportedAuthentication(f"server requires {security_type_name(security_type)} ({security_type})")

        sock.sendall(b"\x01")
        server_init = read_exact(sock, 24, "server init")
        width, height = struct.unpack("!HH", server_init[:4])
        pixel_format = struct.unpack("!BBBBHHHBBB3x", server_init[4:20])
        name_length = struct.unpack("!I", server_init[20:24])[0]
        if width == 0 or height == 0:
            raise VNCProtocolError(f"server reported an invalid framebuffer size {width}x{height}")
        if name_length > 1024 * 1024:
            raise VNCProtocolError(f"server name is too long ({name_length} bytes)")
        self.framebuffer_width = width
        self.framebuffer_height = height
        self.pixel_format = pixel_format
        self.server_name = read_exact(sock, name_length, "server name").decode("utf-8", errors="replace")
        return width, height, pixel_format

    def connect_and_authenticate(self, password):
        sock = socket.create_connection((self.host, self.port), timeout=self.args.vnc_timeout)
        try:
            version, security_types = self.handshake(sock)
            self.rfb_version = version
            self.RFBversion = float(f"{version[0]}.{version[1]}")
            self.security_types = security_types
            self.auth_methods = [security_type_name(security_type) for security_type in security_types]
            self.noauth = 1 in security_types
            width, height, pixel_format = self.authenticate(sock, version, security_types, password)
        except Exception as e:
            sock.close()
            self.logger.debug(f"VNC session failed: {e}")
            raise
        return sock, width, height, pixel_format

    def plaintext_login(self, username, password):
        self.username = username
        self.password = password
        try:
            sock, _, _, _ = self.connect_and_authenticate(password)
            sock.close()
            self.admin_privs = True
            self.logger.success("{} {}".format(password, highlight(f"({self.config.get('nxc', 'pwn3d_label')})" if self.admin_privs else "")))
            return True
        except TimeoutError:
            self.logger.fail(f"{password} - Connection timed out after {self.args.vnc_timeout}s")
        except VNCUnsupportedAuthentication as e:
            self.logger.fail(f"{password} - Authentication failed: {e}")
        except VNCAuthenticationError as e:
            self.logger.fail(f"{password} - Authentication failed: {e}")
        except VNCProtocolError as e:
            self.logger.fail(f"{password} - RFB handshake failed: {e}")
        except VNCError as e:
            self.logger.fail(f"{password} - VNC error: {e}")
        except OSError as e:
            self.logger.fail(f"{password} - Connection failed: {e}")
        return False

    def set_pixel_format(self, sock):
        sock.sendall(struct.pack("!B3xBBBBHHHBBB3x", 0, 32, 24, 0, 1, 255, 255, 255, 16, 8, 0))

    def set_encodings(self, sock):
        sock.sendall(struct.pack("!BxH", 2, 1) + struct.pack("!i", 0))

    def request_framebuffer(self, sock):
        sock.sendall(struct.pack("!BBHHHH", 3, 0, 0, 0, self.framebuffer_width, self.framebuffer_height))

    def read_colour_map(self, sock):
        header = read_exact(sock, 5, "colour map header")
        colours = struct.unpack("!H", header[3:5])[0]
        read_exact(sock, colours * 6, "colour map")

    def read_cut_text(self, sock):
        read_exact(sock, 3, "server cut text header")
        length = struct.unpack("!I", read_exact(sock, 4, "server cut text length"))[0]
        if length > 16 * 1024 * 1024:
            raise VNCDisplayError(f"server cut text is too long ({length} bytes)")
        read_exact(sock, length, "server cut text")

    def pixel_to_rgb(self, pixel, pixel_format):
        bits_per_pixel, _, big_endian, true_colour, red_max, green_max, blue_max, red_shift, green_shift, blue_shift = pixel_format[:10]
        if bits_per_pixel != 32 or not true_colour or not red_max or not green_max or not blue_max:
            raise VNCDisplayError(f"unsupported pixel format {bits_per_pixel}bpp")
        value = int.from_bytes(pixel, "big" if big_endian else "little")
        return (
            ((value >> red_shift) & red_max) * 255 // red_max,
            ((value >> green_shift) & green_max) * 255 // green_max,
            ((value >> blue_shift) & blue_max) * 255 // blue_max,
        )

    def read_framebuffer_update(self, sock):
        read_exact(sock, 1, "framebuffer update padding")
        rectangle_count = struct.unpack("!H", read_exact(sock, 2, "framebuffer rectangle count"))[0]
        image = bytearray(self.framebuffer_width * self.framebuffer_height * 3)
        for _ in range(rectangle_count):
            x, y, width, height, encoding = struct.unpack("!HHHHi", read_exact(sock, 12, "framebuffer rectangle"))
            if encoding == -224:
                break
            if encoding != 0:
                raise VNCDisplayError(f"unsupported framebuffer encoding {encoding}")
            if x + width > self.framebuffer_width or y + height > self.framebuffer_height:
                raise VNCDisplayError(f"framebuffer rectangle {width}x{height} at {x},{y} exceeds the desktop size")

            raw = read_exact(sock, width * height * 4, "raw framebuffer data")
            for row in range(height):
                source = row * width * 4
                target = ((y + row) * self.framebuffer_width + x) * 3
                for _ in range(width):
                    image[target:target + 3] = self.pixel_to_rgb(raw[source:source + 4], self.pixel_format)
                    source += 4
                    target += 3
        return image

    def capture_framebuffer(self, sock):
        self.set_pixel_format(sock)
        self.set_encodings(sock)
        self.request_framebuffer(sock)
        while True:
            message_type = read_exact(sock, 1, "server message")[0]
            if message_type == 0:
                return self.read_framebuffer_update(sock)
            if message_type == 1:
                self.read_colour_map(sock)
            elif message_type == 2:
                continue
            elif message_type == 3:
                self.read_cut_text(sock)
            else:
                raise VNCDisplayError(f"unsupported server message type {message_type}")

    def screenshot_path(self):
        screenshots_dir = (Path(NXC_PATH) / "screenshots").expanduser().resolve()
        screenshots_dir.mkdir(parents=True, exist_ok=True)
        filename = (screenshots_dir / sanitize_path_component(f"{self.hostname}_{self.host}_{datetime.now().strftime('%Y-%m-%d_%H%M%S')}.png", max_bytes=251)).resolve()
        if screenshots_dir not in filename.parents:
            raise VNCDisplayError("screenshot path escaped the screenshots directory")
        return filename

    def capture_screenshot(self):
        try:
            sock, width, height, _ = self.connect_and_authenticate(self.password)
            with sock:
                sleep(self.args.screentime)
                image = self.capture_framebuffer(sock)
            filename = self.screenshot_path()
            write_png(filename, width, height, image)
            self.logger.highlight(f"Screenshot saved {filename}")
        except TimeoutError as e:
            self.logger.debug(f"Screenshot timed out: {e}")
            self.logger.fail(f"Screenshot failed: timed out after {self.args.vnc_timeout}s waiting for framebuffer data")
        except VNCUnsupportedAuthentication as e:
            self.logger.fail(f"Screenshot failed: {e}")
        except VNCAuthenticationError as e:
            self.logger.fail(f"Screenshot failed: authentication rejected: {e}")
        except VNCProtocolError as e:
            self.logger.fail(f"Screenshot failed: RFB protocol error: {e}")
        except VNCDisplayError as e:
            self.logger.fail(f"Screenshot failed: {e}")
        except VNCError as e:
            self.logger.fail(f"Screenshot failed: {e}")
        except OSError as e:
            self.logger.fail(f"Screenshot failed: connection error: {e}")

    async def screen(self):
        self.capture_screenshot()

    def screenshot(self):
        asyncio.run(self.screen())

    def disconnect(self):
        if self.conn is not None:
            self.conn.close()
