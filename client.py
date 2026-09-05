import errno
import os
import socket
import struct
import select
import time

from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey,
    X25519PublicKey,
)

from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes

from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305

VPS_HOST = "47.80.16.59"
VPS_PORT = 443

LISTEN_HOST = "127.0.0.1"
LISTEN_PORT = 1080

LISTENING = 1

HANDSHAKING_SOCKS5 = 2
REQUESTING_SOCKS5 = 3
ESTABLISHED = 4

CONNECTING = 5
HANDSHAKING_TLS = 6
ESTABLISHED_MUX = 7

KEY_EXCHANGE = 1
SOCKS5_HANDSHAKE = 2
TCP_STREAM = 3

UserConnection_id_counter = 0
UserConnection_by_id:dict[int, 'UserConnection'] = {}
Connection_by_socket:dict[socket.socket, 'UserConnection'] = {}
UserConnections:set['UserConnection'] = set()

def alloc_connection_id():
    global UserConnection_id_counter
    cid = UserConnection_id_counter
    UserConnection_id_counter += 1
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

        Connection_by_socket[self.sock] = self

    def read(self, vps_conn) -> None:
        try:
            conn, addr = self.sock.accept()
        except BlockingIOError:
            return None

        return UserConnection(conn, vps_conn)

    def close(self):
        print("监听连接关闭")
        try:
            self.sock.close()
        except Exception:
            pass
        if self.sock in Connection_by_socket:
            del Connection_by_socket[self.sock]


class VPSConnection:
    #todo 似乎也需要超时管理
    #原则上应该发心跳包和重连
    #但断了的话UserConnection也会断
    #而且实现起来很复杂，懒了，就这样吧，基于人工重启算了
    clear_threshold = 1024 * 1024 * 4
    buffer_size = 1024 * 1024 * 4 * 4
    high_watermark = 1024 * 1024 * 4 * 3

    __slots__ = (
        'sock', 
        'host', 'port',
        'state',

        'read_buffer', 'write_buffer',
        'read_offset', 'write_offset',

        'cipher',
        'private_key', 'public_key', 'public_key_bytes',
        'peer_public_key', 'shared_secret',
        'session_key'
    )

    def __init__(self, host: str = VPS_HOST, port: int = VPS_PORT):
        self.host = host
        self.port = port

        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setblocking(False)

        self.state = CONNECTING

        self.read_buffer = bytearray()
        self.read_offset = 0
        self.write_buffer = bytearray()
        self.write_offset = 0

        try:
            self.sock.connect((self.host, self.port))
        except BlockingIOError as e:
            if e.errno in (errno.EINPROGRESS, errno.EWOULDBLOCK):
                pass
            else:
                raise

        Connection_by_socket[self.sock] = self

        self.private_key = X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
        self.public_key_bytes = self.public_key.public_bytes_raw()

    def check_connect(self) -> bool:
        if self.state != CONNECTING:
            return True

        _, writable, _ = select.select([], [self.sock], [], 0)
        if not writable:
            return False
        
        err = self.sock.getsockopt(socket.SOL_SOCKET, socket.SO_ERROR)
        if err != 0:
            raise OSError(err, f"连接 VPS 失败: {err}")

        self.state = HANDSHAKING_TLS
        self.write(KEY_EXCHANGE, 0, self.public_key_bytes)
        return True

    def handshake(self, data) -> None:
        if self.state != HANDSHAKING_TLS:
            raise ConnectionError("VPSConnection 未处于 HANDSHAKING_TLS 状态却收到 KEY_EXCHANGE 帧")

        self.peer_public_key = X25519PublicKey.from_public_bytes(bytes(data))
        self.shared_secret = self.private_key.exchange(self.peer_public_key)

        self.session_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b"handshake data",
        ).derive(self.shared_secret)

        self.cipher = ChaCha20Poly1305(self.session_key)

        self.state = ESTABLISHED_MUX
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

    def read_clear(self) -> None:
        if self.read_offset == len(self.read_buffer):
            self.read_buffer.clear()
            self.read_offset = 0
        elif self.read_offset > VPSConnection.clear_threshold:
            self.read_buffer = self.read_buffer[self.read_offset:]
            self.read_offset = 0

    def write_clear(self) -> None:
        if self.write_offset == len(self.write_buffer):
            self.write_buffer.clear()
            self.write_offset = 0
        elif self.write_offset > VPSConnection.clear_threshold:
            self.write_buffer = self.write_buffer[self.write_offset:]
            self.write_offset = 0

    def recv(self) -> None:
        while True:
            if(len(self.read_buffer) > UserConnection.buffer_size):
                raise ConnectionError("read_buffer 过大，疑似 user 端卡住导致 user_conn 端写不进去，write_buffer 爆满，然后卡在 vps_conn 的 read_buffer")
            try:
                data = self.sock.recv(4096)
            except BlockingIOError:
                break
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                raise

            if not data:
                raise ConnectionError("vps 端关闭连接")
            self.read_buffer.extend(data)

    def send(self) -> None:
        total_len = len(self.write_buffer)
        
        while self.write_offset < total_len:
            try:
                n = self.sock.send(memoryview(self.write_buffer)[self.write_offset:])
            except BlockingIOError:
                return

            self.write_offset += n
            if n == 0:
                raise ConnectionError("向 vps 发送失败")
        
        self.write_clear()

    @property
    def size_to_write(self):
        return len(self.write_buffer) - self.write_offset

    @property
    def size_to_read(self):
        return len(self.read_buffer) - self.read_offset

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
            length += 12
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
        user_conn = UserConnection_by_id.get(stream_id)
        if user_conn is None:
            raise ConnectionError(f"收到未知 stream_id 的帧: {stream_id}")
        user_conn.write(payload)

    def read(self) -> None:
        while True:
            frame = self.read_frame()
            if frame is None:
                break
            frame_type, stream_id, payload = frame
            if frame_type == KEY_EXCHANGE:
                self.handshake(payload)
                pass
            elif frame_type in (SOCKS5_HANDSHAKE, TCP_STREAM):
                self.dispatch_frame(frame_type, stream_id, payload)
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
        if(len(self.write_buffer) + len(frame) > VPSConnection.buffer_size):
            raise ConnectionError("write_buffer 过大，疑似 vps_server 端卡住导致 vps_conn 写不进去卡在 write_buffer")
        self.write_buffer.extend(frame)

    def close(self) -> None:
        print("VPS 连接关闭")
        try:
            self.sock.close()
        except Exception:
            pass

        for user_conn in list(UserConnections):
            user_conn.close()

        if self.sock in Connection_by_socket:
            del Connection_by_socket[self.sock]
        self.read_buffer.clear()
        self.write_buffer.clear()


class UserConnection:
    clear_threshold = 1024 * 1024
    buffer_size = 1024 * 1024 * 8
    timeout = 60 * 5

    __slots__ = (
        'sock', 
        'state',
        'id',
        'read_buffer', 'write_buffer',
        'read_offset', 'write_offset',
        'vps_conn',
        'last_active_time'
    )

    def __init__(self, sock, vps_conn):
        self.sock = sock
        self.sock.setblocking(False)

        self.state = HANDSHAKING_SOCKS5
        self.id = alloc_connection_id()

        UserConnection_by_id[self.id] = self
        Connection_by_socket[self.sock] = self
        UserConnections.add(self)
        self.vps_conn = vps_conn

        self.read_buffer = bytearray()
        self.read_offset = 0
        self.write_buffer = bytearray()
        self.write_offset = 0

        self.last_active_time = time.time()

    def read_clear(self) -> None:
        if self.read_offset == len(self.read_buffer):
            self.read_buffer.clear()
            self.read_offset = 0
        elif self.read_offset > UserConnection.clear_threshold:
            self.read_buffer = self.read_buffer[self.read_offset:]
            self.read_offset = 0

    def write_clear(self) -> None:
        if self.write_offset == len(self.write_buffer):
            self.write_buffer.clear()
            self.write_offset = 0
        elif self.write_offset > UserConnection.clear_threshold:
            self.write_buffer = self.write_buffer[self.write_offset:]
            self.write_offset = 0

    def recv(self) -> None:
        while True:
            if(len(self.read_buffer) > UserConnection.buffer_size):
                raise ConnectionError("read_buffer 过大，疑似 vps 端卡住导致 user 端写不进去卡在 read_buffer")
            try:
                data = self.sock.recv(4096)
            except BlockingIOError:
                break
            except OSError as e:
                if e.errno in (errno.EAGAIN, errno.EWOULDBLOCK):
                    break
                raise

            if not data:
                raise ConnectionError("用户端关闭连接 (EOF)")
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
                raise ConnectionError("向用户端发送失败")
            else:
                self.last_active_time = time.time()
        
        self.write_clear()

    @property
    def size_to_write(self):
        return len(self.write_buffer) - self.write_offset

    @property
    def size_to_read(self):
        return len(self.read_buffer) - self.read_offset

    # 下面这俩函数仅就检验而言并不必要，对面也会检查 SOCKS5 格式
    # 但是，需要维护当前 conn 的状态
    # 因此，需要在这里取出整包
    def read_socks5_handshake(self) -> bool:
        if self.size_to_read < 2:
            return False
        
        view = memoryview(self.read_buffer)
        ver = view[self.read_offset]
        nmethods = view[self.read_offset + 1]
        del view

        if ver != 5:
            raise ConnectionError(f"非 SOCKS5 协议: {ver}")
        if self.size_to_read < 2 + nmethods:
            return False
        # 忽略 methods
        self.write(bytearray(b'\x05\x00'))
        self.read_offset += 2 + nmethods

        self.read_clear()
        return True

    def read_socks5_request(self) -> bytearray | None:
        if self.size_to_read < 4:
            return None
        
        view = memoryview(self.read_buffer)
        ver, cmd, _, addr_type = struct.unpack_from("!BBBB", view, self.read_offset)

        if ver != 5:
            raise ConnectionError(f"非 SOCKS5 协议: {ver}")
        if cmd != 1:
            raise ConnectionError(f"不支持的命令: {cmd}")
        if addr_type == 3:
            if self.size_to_read < 5:
                return None
            domain_length = view[self.read_offset + 4]
            if self.size_to_read < 5 + domain_length + 2:
                return None
        else:
            raise ConnectionError(f"不支持的地址类型: {addr_type}")
        # todo 如果解析失败，应该返回错误给用户端，而不是直接关闭连接 
        # 但是仅就我们的使用情景而言，未必用得上

        ret = view[self.read_offset:self.read_offset + 5 + domain_length + 2]
        self.read_offset += 5 + domain_length + 2

        ret = bytearray(ret)
        del view

        self.read_clear()
        return ret

    def read(self) -> None:
        if self.size_to_read == 0:
            print("read_buffer 为空的 UserConnection 被认为可读")
            return 

        if self.state == HANDSHAKING_SOCKS5:
            if not self.read_socks5_handshake():
                return
            self.state = REQUESTING_SOCKS5
        elif self.state == REQUESTING_SOCKS5:
            request = self.read_socks5_request()
            if request is None:
                return
            self.state = ESTABLISHED
            self.vps_conn.write(SOCKS5_HANDSHAKE, self.id, request)
        else:
            data = memoryview(self.read_buffer)[self.read_offset:]
            self.vps_conn.write(TCP_STREAM, self.id, bytearray(data))
            self.read_offset += len(data)
            del data
            self.read_clear()

        return

    def write(self, data: bytearray) -> None:
        if(len(self.write_buffer) + len(data) > UserConnection.buffer_size):
            raise ConnectionError("write_buffer 过大，本机用户端发生了奇怪事情")
        self.write_buffer.extend(data)

    def close(self) -> None:
        try:
            self.sock.close()
        except Exception:
            pass
        if self.id in UserConnection_by_id:
            del UserConnection_by_id[self.id]
        if self.sock in Connection_by_socket:
            del Connection_by_socket[self.sock]
        UserConnections.discard(self)
        self.read_buffer.clear()
        self.write_buffer.clear()

    def timeout_close(self) -> None:
        print(f"用户连接 {self.id} 超时关闭")
        self.close()


def main():
    listen_conn = ListenerConnection()
    vps_conn = VPSConnection()

    while True:
        if not vps_conn.check_connect():
            time.sleep(0.1)
        else:
            # do the handshake
            break

    while True:
        read_list = [listen_conn.sock, vps_conn.sock]
        write_list = []
        for user_conn in list(UserConnections):
            if time.time() - user_conn.last_active_time > UserConnection.timeout:
                user_conn.timeout_close()
                continue

            if vps_conn.size_to_write < VPSConnection.high_watermark:
                read_list.append(user_conn.sock)
            if user_conn.size_to_write > 0:
                write_list.append(user_conn.sock)
        if vps_conn.size_to_write > 0:
            write_list.append(vps_conn.sock)

        try:
            readable, writable, _ = select.select(read_list, write_list, [], 0)
        except (OSError, ValueError) as e:
            print(f"select error: {e}")
            vps_conn.close()
            listen_conn.close()
            break

        for sock in readable:
            conn = Connection_by_socket.get(sock)
            if conn is None:
                continue
            if isinstance(conn, ListenerConnection):
                try:
                    user_conn = conn.read(vps_conn)
                    if user_conn is not None:
                        print(f"新用户连接: {user_conn.id} 来自 {user_conn.sock.getpeername()}")
                except Exception as e:
                    print(f"监听连接错误: {e}")
            elif isinstance(conn, VPSConnection):
                try:
                    conn.recv()
                    conn.read()
                except Exception as e:
                    print(f"VPS 连接错误: {e}")
                    conn.close()
                    return
                    break
            elif isinstance(conn, UserConnection):
                try:
                    conn.recv()
                    conn.read()
                except Exception as e:
                    print(f"用户连接 {conn.id} 错误: {e}")
                    conn.close()

        for sock in writable:
            conn = Connection_by_socket.get(sock)
            if conn is None:
                continue
            try:
                conn.send()
            except Exception as e:
                print(f"发送数据错误: {e}")
                conn.close()

if __name__ == "__main__":
    main()

'''
listener 有读端口，读新 user
vps 有读写端口，读端口读 server 发来的数据，写端口写数据给 server
user 有读写端口，读端口读用户发来的数据，写端口写数据给用户

recv 和 send 是无阻塞的包装
read 和 write 是裸的读写

有少许问题，例如 socks5_requset 可能失败，此时用户侧的行为未被捕捉
'''