import errno
import logging
import os
import select
import socket
import struct
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(name)s: %(message)s",
)
logger = logging.getLogger(__name__)

LISTEN_HOST = "0.0.0.0"
LISTEN_PORT = 443

KEY_EXCHANGE = 1
SOCKS5_HANDSHAKE = 2
TCP_STREAM = 3

LISTENING = 1

CONNECTING = 2
ESTABLISHED = 3

HANDSHAKING_TLS = 4
ESTABLISHED_MUX = 5


ClientConnections: set["ClientConnection"] = set()

TargetConnection_id_counter = 0


def alloc_connection_id() -> int:
    global TargetConnection_id_counter
    cid = TargetConnection_id_counter
    TargetConnection_id_counter += 1
    return cid


class ListenerConnection:
    __slots__ = (
        'sock',
        'host', 'port',
        'state'
    )

    def __init__(self, host: str = LISTEN_HOST, port: int = LISTEN_PORT):
        self.host = host
        self.port = port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind((host, port))
        self.sock.listen(128)
        self.sock.setblocking(False)

        self.state = LISTENING

    def read(self):
        try:
            conn, addr = self.sock.accept()
        except BlockingIOError:
            return None

        return ClientConnection(conn, addr)

    def close(self):
        try:
            self.sock.close()
            logger.info("监听连接已关闭")
        except Exception as e:
            logger.warning("关闭监听连接失败：error=%s", e, exc_info=True)


class ClientConnection:
    clear_threshold = 1024 * 1024 * 16
    buffer_size = 1024 * 1024 * 4 * 16
    high_watermark = 1024 * 1024 * 4 * 12
    timeout = 60 * 10

    __slots__ = (
        'sock',
        'addr',
        'state',

        'read_buffer', 'write_buffer',
        'read_offset', 'write_offset',

        'cipher',
        'private_key', 'public_key', 'public_key_bytes',
        'peer_public_key', 'shared_secret',
        'session_key',

        'Connection_by_socket', 
        'TargetConnection_by_id', 
        'TargetConnections',

        'last_active_time'
    )

    def __init__(self, sock: socket.socket, addr):
        self.sock = sock
        self.addr = addr
        self.sock.setblocking(False)

        self.state = HANDSHAKING_TLS
        self.read_buffer = bytearray()
        self.write_buffer = bytearray()
        self.read_offset = 0
        self.write_offset = 0

        self.Connection_by_socket: dict[socket.socket, object] = {}
        self.TargetConnection_by_id: dict[int, "TargetConnection"] = {}
        self.TargetConnections: set["TargetConnection"] = set()

        self.Connection_by_socket[self.sock] = self
        ClientConnections.add(self)

        self.last_active_time = time.time()

        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes_raw()

    def handshake(self, data:bytearray) -> None:
        if self.state != HANDSHAKING_TLS:
            raise ConnectionError("ClientConnection 未处于 HANDSHAKING_TLS 状态却收到 KEY_EXCHANGE 帧")

        self.peer_public_key = X25519PublicKey.from_public_bytes(bytes(data))
        self.shared_secret = self.private_key.exchange(self.peer_public_key)
        self.write(KEY_EXCHANGE, 0, bytearray(self.public_key_bytes))

        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(self.shared_secret)

        self.cipher = ChaCha20Poly1305(self.session_key)

        self.state = ESTABLISHED_MUX
        logger.info("ClientConnection 握手已完成：addr=%s，进入 ESTABLISHED_MUX 状态", self.addr)
        return

    def encrypt_func(self, data: bytearray) -> bytearray:
        nonce = os.urandom(12)
        encrypted_data = self.cipher.encrypt(nonce, data, None)
        return bytearray(nonce + encrypted_data)

    def decrypt_func(self, data: bytearray) -> bytearray:
        nonce = data[:12]
        encrypted_data = data[12:]
        decrypted_data = self.cipher.decrypt(nonce, encrypted_data, None)
        return bytearray(decrypted_data)

    def read_clear(self):
        if self.read_offset == len(self.read_buffer):
            self.read_buffer.clear()
            self.read_offset = 0
        elif self.read_offset > self.clear_threshold:
            self.read_buffer = self.read_buffer[self.read_offset:]
            self.read_offset = 0

    def write_clear(self):
        if self.write_offset == len(self.write_buffer):
            self.write_buffer.clear()
            self.write_offset = 0
        elif self.write_offset > self.clear_threshold:
            self.write_buffer = self.write_buffer[self.write_offset:]
            self.write_offset = 0

    @property
    def size_to_read(self):
        return len(self.read_buffer) - self.read_offset

    @property
    def size_to_write(self):
        return len(self.write_buffer) - self.write_offset

    def recv(self):
        while True:
            if len(self.read_buffer) > ClientConnection.buffer_size:
                raise ConnectionError("client read_buffer 过大，target 端卡住了？")

            try:
                data = self.sock.recv(4096)
            except BlockingIOError:
                return
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    return
                raise

            if not data:
                raise ConnectionError("client 端关闭连接")

            self.read_buffer.extend(data)
            self.last_active_time = time.time()

    def send(self) -> None:
        total_len = len(self.write_buffer)
        
        while self.write_offset < total_len:
            try:
                n = self.sock.send(memoryview(self.write_buffer)[self.write_offset:])
            except BlockingIOError:
                return

            self.write_offset += n
            if n == 0:
                raise ConnectionError("向 client 发送失败")
            else:
                self.last_active_time = time.time()
        
        self.write_clear()

    def read_frame(self) -> tuple[int, int, bytearray] | None:
        header_len = 1 + 4 + 4
        if self.size_to_read < header_len:
            return None

        header = memoryview(self.read_buffer)[self.read_offset : self.read_offset + header_len]
        frame_type = header[0]
        length = struct.unpack_from("!I", header, 1)[0] 
        stream_id = struct.unpack_from("!I", header, 5)[0]

        del header

        if self.state == HANDSHAKING_TLS:
            if frame_type != KEY_EXCHANGE:
                raise ConnectionError(f"在 HANDSHAKING_TLS 状态下收到非 KEY_EXCHANGE 帧: {frame_type}")
            else:
                pass
        elif self.state == ESTABLISHED_MUX:
            if frame_type not in (SOCKS5_HANDSHAKE, TCP_STREAM):
                raise ConnectionError(f"在 ESTABLISHED_MUX 状态下收到非 SOCKS5_HANDSHAKE 或 TCP_STREAM 帧: {frame_type}")
            else:
                pass

        total_len = header_len + length
        if self.size_to_read < total_len:
            return None

        payload = memoryview(self.read_buffer)[self.read_offset + header_len : self.read_offset + total_len]
        if self.state == ESTABLISHED_MUX:
            payload = self.decrypt_func(payload)

        payload_bytearray = bytearray(payload)
        del payload

        self.read_offset += total_len
        self.read_clear()
        return frame_type, stream_id, payload_bytearray

    def dispatch_frame(self, frame_type: int, stream_id: int, payload: bytearray) -> None:
        target_conn = self.TargetConnection_by_id.get(stream_id)
        if target_conn is None:
            logger.warning("收到未知 stream_id 的帧：stream_id=%s", stream_id)
            return
        target_conn.write(payload)

    def read(self):
        while True:
            frame = self.read_frame()
            if frame is None:
                return
            frame_type, stream_id, payload = frame
            if frame_type == SOCKS5_HANDSHAKE:
                if stream_id in self.TargetConnection_by_id:
                    raise ConnectionError(f"重复的 stream_id: {stream_id}")
                try:
                    TargetConnection(self, stream_id, payload)
                except Exception as e:
                    logger.error("创建 TargetConnection 失败：error=%s", e, exc_info=True)
            elif frame_type == TCP_STREAM:
                self.dispatch_frame(frame_type, stream_id, payload)
            elif frame_type == KEY_EXCHANGE:
                self.handshake(payload)
                continue
            else:
                raise ConnectionError(f"未知帧类型: {frame_type}")

    def write(self, frame_type: int, stream_id: int, payload: bytearray) -> None:
        if self.state == ESTABLISHED_MUX:
            payload = self.encrypt_func(payload)

        frame_type = struct.pack("!B", frame_type)
        length = struct.pack("!I", len(payload))
        stream_id = struct.pack("!I", stream_id)

        frame = bytearray()
        frame.extend(frame_type)
        frame.extend(length)
        frame.extend(stream_id)
        frame.extend(payload)
        if(len(self.write_buffer) + len(frame) > ClientConnection.buffer_size):
            raise ConnectionError("write_buffer 过大，疑似 vps_server 端卡住导致 vps_conn 写不进去卡在 write_buffer")
        self.write_buffer.extend(frame)

    def close(self) -> None:
        try:
            self.sock.close()
            logger.info("ClientConnection 已关闭：addr=%s", self.addr)
        except Exception as e:
            logger.warning("关闭 ClientConnection 失败：addr=%s，error=%s", self.addr, e, exc_info=True)
        ClientConnections.discard(self)
        self.read_buffer.clear()
        self.write_buffer.clear()

        for target_conn in list(self.TargetConnections):
            target_conn.close()


class TargetConnection:
    clear_threshold = 1024 * 1024
    buffer_size = 1024 * 1024 * 4
    timeout = 60 * 5

    __slots__ = (
        'sock', 
        'target_host', 'target_port',
        'state',
        'id',
        'write_buffer','write_offset',
        'client_conn',
        'last_active_time'
    )

    def __init__(self, client_conn, stream_id, socks5_request: bytearray):
        self.client_conn = client_conn
        self.id = stream_id
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(False)
        self.state = CONNECTING

        self.write_buffer = bytearray()
        self.write_offset = 0

        self.target_host = None
        self.target_port = None

        if not self.read_socks5_request(socks5_request):
            self.close()
            logger.warning("读取 SOCKS5 请求失败：stream_id=%s", self.id)

        self.client_conn.Connection_by_socket[self.sock] = self
        self.client_conn.TargetConnection_by_id[self.id] = self
        self.client_conn.TargetConnections.add(self)

        self.last_active_time = time.time()

        try:
            self.sock.connect((self.target_host, self.target_port))
        except BlockingIOError as e:
            if e.errno in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                pass
            else:
                logger.error("连接 target 失败：error=%s", e, exc_info=True)
                self.close()
        except Exception as e:
            logger.error("连接 target 失败：error=%s", e, exc_info=True)
            self.close()
                

    def check_connect(self) -> bool:
        if self.state != CONNECTING:
            return True

        _, writable, _ = select.select([], [self.sock], [], 0)
        if not writable:
            return False
        
        err = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            raise OSError(err, f"连接目标网站失败: {err}")

        self.state = ESTABLISHED
        logger.info("TargetConnection 已建立：stream_id=%s，target_host=%s，target_port=%s", self.id, self.target_host, self.target_port)
        response = b"\x05\x00\x00\x03" + bytes([len(self.target_host)]) + self.target_host.encode() + struct.pack("!H", self.target_port)
        self.client_conn.write(SOCKS5_HANDSHAKE, self.id, bytearray(response))
        return True

    def write_clear(self) -> None:
        if self.write_offset == len(self.write_buffer):
            self.write_buffer.clear()
            self.write_offset = 0
        elif self.write_offset > TargetConnection.clear_threshold:
            self.write_buffer = self.write_buffer[self.write_offset:]
            self.write_offset = 0

    def recv(self):
        while True:
            try:
                data = self.sock.recv(4096)
            except BlockingIOError:
                return
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    return
                raise

            if not data:
                raise ConnectionError("目标连接已关闭")

            self.client_conn.write(TCP_STREAM, self.id, bytearray(data))
            self.last_active_time = time.time()
            self.client_conn.last_active_time = time.time()

    def send(self) -> None:
        total_len = len(self.write_buffer)
        
        while self.write_offset < total_len:
            try:
                n = self.sock.send(memoryview(self.write_buffer)[self.write_offset:])
            except BlockingIOError:
                return

            self.write_offset += n
            if n == 0:
                raise ConnectionError("向用户端发送失败")
            else:
                self.last_active_time = time.time()
                self.client_conn.last_active_time = time.time()
        
        self.write_clear()

    @property
    def size_to_write(self):
        return len(self.write_buffer) - self.write_offset


    def read_socks5_request(self, data: bytearray) -> bool:
        if len(data) < 4:
            return 0

        view = memoryview(data)
        ver, cmd, _, addr_type = struct.unpack_from("!BBBB", view, 0)

        if ver != 5:
            raise ConnectionError(f"非 SOCKS5 协议: {ver}")
        if cmd != 1:
            raise ConnectionError(f"不支持的命令: {cmd}")
        if addr_type == 3:
            if len(data) < 5:
                return 0
            domain_length = view[4]
            if len(data) < 5 + domain_length + 2:
                return 0
        else:
            raise ConnectionError(f"不支持的地址类型: {addr_type}")

        addr_bytes = view[5:5 + domain_length]
        port_bytes = view[5 + domain_length:5 + domain_length + 2]
        self.target_host = addr_bytes.tobytes().decode()
        self.target_port = struct.unpack("!H", port_bytes)[0]
        del addr_bytes
        del port_bytes
        del view

        return 1   

    def write(self, data: bytes):
        if len(self.write_buffer) + len(data) > TargetConnection.buffer_size:
            raise ConnectionError("write_buffer 过大，向网站的写入卡住了")
        self.write_buffer.extend(data)

    def close(self) -> None:
        if self.state == CONNECTING:
            # todo 这里格式不对？应该用 bytearray 和 extend？
            try:
                if self.target_host is not None and self.target_port is not None:
                    response = b"\x05\x05\x00\x03" + bytes([len(self.target_host)]) + self.target_host.encode() + struct.pack("!H", self.target_port)
                else:
                    response = b"\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00"
                self.client_conn.write(SOCKS5_HANDSHAKE, self.id, bytearray(response))
            except Exception as e:
                logger.error("发送 SOCKS5 握手响应失败：error=%s", e, exc_info=True)

        try:
            self.sock.close()
            logger.info("TargetConnection 已关闭：stream_id=%s", self.id)
        except Exception as e:
            logger.warning("关闭 TargetConnection 失败：stream_id=%s，error=%s", self.id, e, exc_info=True)
        if self.id in self.client_conn.TargetConnection_by_id:
            del self.client_conn.TargetConnection_by_id[self.id]
        if self.sock in self.client_conn.Connection_by_socket:
            del self.client_conn.Connection_by_socket[self.sock]
        self.client_conn.TargetConnections.discard(self)
        self.write_buffer.clear()


def main():
    listener = ListenerConnection()
    client = None

    logger.info("server 已开始监听：LISTEN_HOST=%s，LISTEN_PORT=%s", LISTEN_HOST, LISTEN_PORT)

    while True:
        try:
            client = listener.read()
            if client:
                logger.info("client 连接已建立：addr=%s", client.addr)
        except Exception as e:
            logger.error("接收 client 连接失败：error=%s", e, exc_info=True)

        for client in list(ClientConnections):
            if time.time() - client.last_active_time > ClientConnection.timeout:
                logger.info("client 连接已因超时关闭：addr=%s", client.addr)
                client.close()
                continue

            read_list = [client.sock]
            write_list = []
            if client.size_to_write > 0:
                write_list.append(client.sock)
            for target_conn in list(client.TargetConnections):
                if time.time() - target_conn.last_active_time > TargetConnection.timeout:
                    logger.info("target_conn 已因超时关闭：target_host=%s，target_port=%s", target_conn.target_host, target_conn.target_port)
                    target_conn.close()
                    continue
                if client.size_to_write < ClientConnection.high_watermark:
                    read_list.append(target_conn.sock)
                if target_conn.size_to_write > 0 or target_conn.state == CONNECTING:
                    write_list.append(target_conn.sock)

            try:
                readable, writable, _ = select.select(read_list, write_list, [], 0)
            except (OSError, ValueError) as e:
                logger.error("调用 select 失败：error=%s", e, exc_info=True)
                client.close()
                continue

            for sock in writable:
                conn = client.Connection_by_socket.get(sock)
                if conn is None:
                    continue
                if isinstance(conn, TargetConnection):
                    if conn.state == CONNECTING:
                        try:
                            conn.check_connect()
                        except Exception as e:
                            logger.error("连接 target 失败：target_host=%s，target_port=%s，error=%s", conn.target_host, conn.target_port, e, exc_info=True)
                            conn.close()
                            continue
                    if conn.state == ESTABLISHED:
                        try:
                            conn.send()
                        except Exception as e:
                            logger.error("向 target_conn 写入数据失败：target_host=%s，target_port=%s，error=%s", conn.target_host, conn.target_port, e, exc_info=True)
                            conn.close()
                else:
                    try:
                        conn.send()
                    except Exception as e:
                        logger.error("向 client 写入数据失败：addr=%s，error=%s", conn.addr, e, exc_info=True)
                        conn.close()

            for sock in readable:
                conn = client.Connection_by_socket.get(sock)
                if conn is None:
                    continue
                if isinstance(conn, TargetConnection):
                    if conn.state == CONNECTING:
                        logger.warning("target_conn 仍处于 CONNECTING 状态却被判定为可读：target_host=%s，target_port=%s", conn.target_host, conn.target_port)
                    if conn.state == ESTABLISHED:
                        try:
                            conn.recv()
                            # conn.read()
                        except Exception as e:
                            logger.error("从 target_conn 读取数据失败：target_host=%s，target_port=%s，error=%s", conn.target_host, conn.target_port, e, exc_info=True)
                            conn.close()
                else:
                    try:
                        conn.recv()
                        conn.read()
                    except Exception as e:
                        logger.error("从 client 读取数据失败：addr=%s，error=%s", conn.addr, e, exc_info=True)
                        conn.close()
            

            


if __name__ == "__main__":
    main()