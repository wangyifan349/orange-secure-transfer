#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Project: https://github.com/wangyifan349/orange-secure-transfer
"""中文加密聊天与校验文件传输；依赖：pip install PyQt6 cryptography pycryptodome"""

import hashlib
import os
import pathlib
import queue
import socket
import struct
import sys
import threading
import time
import uuid
import math
from typing import BinaryIO, Dict, Optional, Tuple

from PyQt6.QtCore import QObject, Qt, QTimer, pyqtSignal
from PyQt6.QtGui import QCloseEvent, QKeyEvent, QPalette, QColor
from PyQt6.QtWidgets import (
    QApplication,
    QDialog,
    QFileDialog,
    QFrame,
    QHBoxLayout,
    QLabel,
    QLineEdit,
    QMainWindow,
    QPushButton,
    QProgressBar,
    QScrollArea,
    QSpinBox,
    QTextEdit,
    QToolButton,
    QVBoxLayout,
    QWidget,
)

from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Cipher import ChaCha20_Poly1305


#---------- Encrypted transfer protocol ----------
TCP_PORT = 5555
FILE_CHUNK_SIZE = 64 * 1024
NONCE_SIZE = 12
TAG_SIZE = 16
TRANSFER_ID_SIZE = 16

MSG_TEXT = 0x01
MSG_FILE_META = 0x02
MSG_FILE_CHUNK = 0x03
MSG_CLOSE = 0x04
MSG_FILE_RESULT = 0x05


def send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack(">I", len(data)) + data)


def recv_exact(sock: socket.socket, size: int) -> bytes:
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise EOFError("connection closed")
        buffer.extend(chunk)
    return bytes(buffer)


def recv_frame(sock: socket.socket) -> bytes:
    frame_size = struct.unpack(">I", recv_exact(sock, 4))[0]
    return recv_exact(sock, frame_size)


def derive_key(shared_secret: bytes) -> bytes:
    derivation = HKDF(
        algorithm=hashes.SHA256(),
        length=32,
        salt=None,
        info=b"SecureTransfer",
    )
    return derivation.derive(shared_secret)


def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext


def decrypt(key: bytes, packet: bytes) -> bytes:
    nonce = packet[:NONCE_SIZE]
    tag = packet[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = packet[NONCE_SIZE + TAG_SIZE:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)


def perform_handshake(sock: socket.socket, is_server: bool) -> bytes:
    private_key = X25519PrivateKey.generate()
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw,
    )
    if is_server:
        peer_public_bytes = recv_frame(sock)
        send_frame(sock, public_bytes)
    else:
        send_frame(sock, public_bytes)
        peer_public_bytes = recv_frame(sock)
    peer_key = X25519PublicKey.from_public_bytes(peer_public_bytes)
    return derive_key(private_key.exchange(peer_key))


APP_NAME = "橘信传输"
DEFAULT_DOWNLOAD_DIR = pathlib.Path.home() / "Downloads" / "SecureTransfer"


#---------- Interface text ----------
def ui_text(value: str) -> str:
    return value


def human_size(size: int) -> str:
    value = float(size)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{size} B"


def unique_target(directory: pathlib.Path, file_name: str) -> pathlib.Path:
    """Return a non-existing receive path without trusting the peer's directories."""
    safe_name = pathlib.PurePath(file_name.replace("\\", "/")).name
    if not safe_name or safe_name in (".", ".."):
        raise ValueError(ui_text("文件名无效"))
    candidate = directory / safe_name
    index = 1
    while candidate.exists():
        candidate = directory / f"{pathlib.Path(safe_name).stem} ({index}){pathlib.Path(safe_name).suffix}"
        index += 1
    return candidate


#---------- Background transfer engine ----------
class TransferEngine(QObject):
    """Threaded network engine. No socket or file I/O runs on the GUI thread."""

    connected = pyqtSignal(str)
    status_changed = pyqtSignal(str)
    disconnected = pyqtSignal(str)
    message_received = pyqtSignal(str)
    message_failed = pyqtSignal(str)
    file_changed = pyqtSignal(object)

    def __init__(self) -> None:
        super().__init__()
        self._stop = threading.Event()
        self._ready = threading.Event()
        self._sock: Optional[socket.socket] = None
        self._listen_sock: Optional[socket.socket] = None
        self._key: Optional[bytes] = None
        self._send_lock = threading.Lock()
        self._state_lock = threading.Lock()
        self._disconnect_emitted = False
        self._text_queue: queue.Queue[Optional[str]] = queue.Queue()
        self._file_queue: queue.Queue[Optional[Tuple[str, str]]] = queue.Queue()
        self._pending: Dict[bytes, Dict[str, object]] = {}
        self._pending_lock = threading.Lock()
        self._incoming: Optional[
            Tuple[bytes, str, pathlib.Path, int, int, BinaryIO, object, bytes]
        ] = None
        self._last_receive_emit = 0.0
        self._download_dir = DEFAULT_DOWNLOAD_DIR

    def start(self, role: str, host: str, port: int) -> None:
        threading.Thread(
            target=self._connect_worker,
            args=(role, host, port),
            daemon=True,
            name="connection-worker",
        ).start()

    def send_text(self, text: str) -> None:
        self._text_queue.put(text)

    def queue_file(self, path: str) -> str:
        ui_id = uuid.uuid4().hex
        self._file_queue.put((ui_id, path))
        return ui_id

    def stop(self) -> None:
        self._stop.set()
        self._text_queue.put(None)
        self._file_queue.put(None)
        threading.Thread(target=self._shutdown_sockets, daemon=True).start()

    def _connect_worker(self, role: str, host: str, port: int) -> None:
        try:
            if role == "server":
                self.status_changed.emit(f"{ui_text('正在监听')} 0.0.0.0:{port}")
                listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                self._listen_sock = listen_sock
                listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                listen_sock.bind(("0.0.0.0", port))
                listen_sock.listen(1)
                listen_sock.settimeout(0.5)
                while not self._stop.is_set():
                    try:
                        sock, address = listen_sock.accept()
                        peer_label = f"{address[0]}:{address[1]}"
                        break
                    except socket.timeout:
                        continue
                else:
                    return
            else:
                self.status_changed.emit(f"{ui_text('正在连接')} {host}:{port}")
                sock = socket.create_connection((host, port), timeout=10)
                sock.settimeout(None)
                peer_label = f"{host}:{port}"

            self.status_changed.emit(ui_text("正在建立加密会话"))
            key = perform_handshake(sock, is_server=(role == "server"))
            with self._state_lock:
                self._sock = sock
                self._key = key
            self._ready.set()
            self.connected.emit(peer_label)

            threading.Thread(target=self._text_send_worker, daemon=True, name="text-sender").start()
            threading.Thread(target=self._file_send_worker, daemon=True, name="file-sender").start()
            self._receive_worker()
        except (OSError, EOFError, ValueError) as exc:
            if not self._stop.is_set():
                self._emit_disconnected(f"{ui_text('连接失败')}：{exc}")
        finally:
            self._stop.set()
            self._ready.clear()
            self._close_incoming(ui_text("连接已中断，文件不完整"))
            self._shutdown_sockets()

    def _text_send_worker(self) -> None:
        while not self._stop.is_set():
            try:
                text = self._text_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if text is None:
                return
            try:
                self._send(MSG_TEXT, text.encode("utf-8"))
            except (OSError, EOFError, ValueError) as exc:
                self.message_failed.emit(str(exc))
                self._connection_lost(f"{ui_text('消息发送失败')}：{exc}")
                return

    def _file_send_worker(self) -> None:
        while not self._stop.is_set():
            try:
                item = self._file_queue.get(timeout=0.25)
            except queue.Empty:
                continue
            if item is None:
                return
            ui_id, path = item
            try:
                self._send_file(ui_id, pathlib.Path(path))
            except (OSError, EOFError, ValueError) as exc:
                self.file_changed.emit({
                    "id": ui_id,
                    "direction": "out",
                    "state": "failed",
                    "detail": f"{ui_text('发送失败')}：{exc}",
                })

    def _send_file(self, ui_id: str, path: pathlib.Path) -> None:
        if not path.is_file():
            raise ValueError(ui_text("文件不存在或不是普通文件"))
        file_size = path.stat().st_size
        file_name_bytes = path.name.encode("utf-8")
        if len(file_name_bytes) > 0xFFFF:
            raise ValueError(ui_text("文件名过长"))

        self.file_changed.emit({
            "id": ui_id, "direction": "out", "state": "hashing",
            "name": path.name, "size": file_size, "detail": ui_text("正在计算 SHA-256"),
        })
        digest_state = hashlib.sha256()
        hashed = 0
        last_emit = 0.0
        with path.open("rb") as handle:
            for chunk in iter(lambda: handle.read(FILE_CHUNK_SIZE), b""):
                if self._stop.is_set():
                    raise EOFError(ui_text("连接已关闭"))
                digest_state.update(chunk)
                hashed += len(chunk)
                now = time.monotonic()
                if now - last_emit >= 0.1:
                    self.file_changed.emit({
                        "id": ui_id, "direction": "out", "state": "hashing",
                        "progress": 100 if file_size == 0 else int(hashed * 100 / file_size),
                    })
                    last_emit = now
        digest = digest_state.digest()
        transfer_id = os.urandom(TRANSFER_ID_SIZE)
        meta = (
            transfer_id
            + struct.pack(">H", len(file_name_bytes))
            + struct.pack(">Q", file_size)
            + digest
            + file_name_bytes
        )
        with self._pending_lock:
            self._pending[transfer_id] = {
                "id": ui_id,
                "name": path.name,
                "size": file_size,
                "digest": digest,
            }
        try:
            self._send(MSG_FILE_META, meta)
            sent = 0
            last_emit = 0.0
            with path.open("rb") as handle:
                for chunk in iter(lambda: handle.read(FILE_CHUNK_SIZE), b""):
                    if self._stop.is_set():
                        raise EOFError(ui_text("连接已关闭"))
                    self._send(MSG_FILE_CHUNK, transfer_id + chunk)
                    time.sleep(0)
                    sent += len(chunk)
                    now = time.monotonic()
                    if now - last_emit >= 0.1 or sent == file_size:
                        self.file_changed.emit({
                            "id": ui_id, "direction": "out", "state": "sending",
                            "progress": 100 if file_size == 0 else int(sent * 100 / file_size),
                            "detail": f"{ui_text('发送中')} {human_size(sent)} / {human_size(file_size)}",
                            "hash": digest.hex(),
                        })
                        last_emit = now
            self.file_changed.emit({
                "id": ui_id, "direction": "out", "state": "verifying",
                "progress": 100, "hash": digest.hex(),
                "detail": ui_text("等待对端 SHA-256 校验"),
            })
        except Exception:
            with self._pending_lock:
                self._pending.pop(transfer_id, None)
            raise

    def _receive_worker(self) -> None:
        while not self._stop.is_set():
            try:
                sock = self._get_socket()
                frame = recv_frame(sock)
                key = self._key
                if key is None:
                    raise EOFError(ui_text("加密会话未建立"))
                plaintext = decrypt(key, frame)
                self._dispatch(plaintext)
            except (OSError, EOFError, ValueError, IndexError) as exc:
                if not self._stop.is_set():
                    self._connection_lost(f"{ui_text('连接已断开')}：{exc}")
                return

    def _dispatch(self, plaintext: bytes) -> None:
        if not plaintext:
            raise ValueError(ui_text("收到空数据帧"))
        msg_type, body = plaintext[0], plaintext[1:]
        if msg_type == MSG_TEXT:
            self.message_received.emit(body.decode("utf-8", errors="replace"))
        elif msg_type == MSG_FILE_META:
            self._begin_receive(body)
        elif msg_type == MSG_FILE_CHUNK:
            self._receive_chunk(body)
        elif msg_type == MSG_FILE_RESULT:
            self._receive_result(body)
        elif msg_type == MSG_CLOSE:
            self._connection_lost(ui_text("对方已结束连接"))
        else:
            raise ValueError(f"{ui_text('未知消息类型')} {msg_type}")

    def _begin_receive(self, payload: bytes) -> None:
        if len(payload) < TRANSFER_ID_SIZE + 42:
            raise ValueError(ui_text("文件元数据不完整"))
        if self._incoming is not None:
            raise ValueError(ui_text("前一个文件尚未接收完成"))
        transfer_id = payload[:16]
        name_len = struct.unpack(">H", payload[16:18])[0]
        total_size = struct.unpack(">Q", payload[18:26])[0]
        expected_digest = payload[26:58]
        if len(payload) != 58 + name_len:
            raise ValueError(ui_text("文件元数据长度错误"))
        file_name = payload[58:].decode("utf-8")
        self._download_dir.mkdir(parents=True, exist_ok=True)
        target = unique_target(self._download_dir, file_name)
        ui_id = transfer_id.hex()
        handle = target.open("wb")
        self._incoming = (
            transfer_id, ui_id, target, total_size, 0, handle,
            hashlib.sha256(), expected_digest,
        )
        self._last_receive_emit = 0.0
        self.file_changed.emit({
            "id": ui_id, "direction": "in", "state": "receiving",
            "name": target.name, "size": total_size, "progress": 0,
            "detail": f"{ui_text('正在接收至')} {target}", "hash": expected_digest.hex(),
        })
        if total_size == 0:
            self._finish_receive()

    def _receive_chunk(self, payload: bytes) -> None:
        if self._incoming is None or len(payload) < TRANSFER_ID_SIZE:
            raise ValueError(ui_text("收到意外的文件数据"))
        chunk_id, chunk = payload[:16], payload[16:]
        transfer_id, ui_id, target, total, received, handle, digest, expected = self._incoming
        if chunk_id != transfer_id:
            raise ValueError(ui_text("文件传输 ID 不匹配"))
        if len(chunk) > total - received:
            raise ValueError(ui_text("文件数据超过声明大小"))
        handle.write(chunk)
        digest.update(chunk)
        received += len(chunk)
        self._incoming = (
            transfer_id, ui_id, target, total, received, handle, digest, expected,
        )
        now = time.monotonic()
        if now - self._last_receive_emit >= 0.1 or received == total:
            self.file_changed.emit({
                "id": ui_id, "direction": "in", "state": "receiving",
                "progress": 100 if total == 0 else int(received * 100 / total),
                "detail": f"{ui_text('接收中')} {human_size(received)} / {human_size(total)}",
            })
            self._last_receive_emit = now
        if received == total:
            self._finish_receive()

    def _finish_receive(self) -> None:
        if self._incoming is None:
            return
        transfer_id, ui_id, target, total, received, handle, digest, expected = self._incoming
        handle.close()
        actual = digest.digest()
        verified = received == total and actual == expected
        self._incoming = None
        self._send(MSG_FILE_RESULT, transfer_id + bytes([verified]) + actual)
        self.file_changed.emit({
            "id": ui_id, "direction": "in",
            "state": "complete" if verified else "failed",
            "progress": 100,
            "hash": actual.hex(),
            "detail": (
                f"{ui_text('SHA-256 校验成功')} · {ui_text('已保存到')} {target}"
                if verified else
                f"{ui_text('SHA-256 校验失败')} · {ui_text('期望')} {expected.hex()} · "
                f"{ui_text('实际')} {actual.hex()}"
            ),
        })

    def _receive_result(self, payload: bytes) -> None:
        if len(payload) != TRANSFER_ID_SIZE + 1 + 32:
            raise ValueError(ui_text("文件校验回执无效"))
        transfer_id = payload[:16]
        flag = payload[16]
        actual = payload[17:]
        if flag not in (0, 1):
            raise ValueError(ui_text("文件校验状态无效"))
        with self._pending_lock:
            pending = self._pending.pop(transfer_id, None)
        if pending is None:
            raise ValueError(ui_text("收到未知文件的校验回执"))
        expected = pending["digest"]
        verified = flag == 1 and actual == expected
        self.file_changed.emit({
            "id": pending["id"], "direction": "out",
            "state": "complete" if verified else "failed",
            "progress": 100, "hash": actual.hex(),
            "detail": (
                ui_text("对端 SHA-256 校验成功，传输完成")
                if verified else
                f"{ui_text('对端校验失败')} · {ui_text('期望')} {expected.hex()} · "
                f"{ui_text('对端')} {actual.hex()}"
            ),
        })

    def _send(self, msg_type: int, payload: bytes) -> None:
        if self._stop.is_set() or not self._ready.is_set():
            raise EOFError(ui_text("当前未连接"))
        key = self._key
        if key is None:
            raise EOFError(ui_text("加密会话未建立"))
        packet = encrypt(key, bytes([msg_type]) + payload)
        with self._send_lock:
            send_frame(self._get_socket(), packet)

    def _get_socket(self) -> socket.socket:
        with self._state_lock:
            if self._sock is None:
                raise EOFError(ui_text("连接不可用"))
            return self._sock

    def _connection_lost(self, reason: str) -> None:
        self._stop.set()
        self._ready.clear()
        self._fail_outgoing(reason)
        self._emit_disconnected(reason)
        self._shutdown_sockets()

    def _fail_outgoing(self, reason: str) -> None:
        """Resolve queued and acknowledgment-pending bubbles after disconnect."""
        failed_ids = set()
        with self._pending_lock:
            pending_items = list(self._pending.values())
            self._pending.clear()
        for pending in pending_items:
            ui_id = str(pending["id"])
            failed_ids.add(ui_id)
            self.file_changed.emit({
                "id": ui_id,
                "direction": "out",
                "state": "failed",
                "detail": reason,
            })
        while True:
            try:
                item = self._file_queue.get_nowait()
            except queue.Empty:
                break
            if item is None:
                continue
            ui_id, _ = item
            if ui_id not in failed_ids:
                self.file_changed.emit({
                    "id": ui_id,
                    "direction": "out",
                    "state": "failed",
                    "detail": reason,
                })

    def _emit_disconnected(self, reason: str) -> None:
        with self._state_lock:
            if self._disconnect_emitted:
                return
            self._disconnect_emitted = True
        self.disconnected.emit(reason)

    def _close_incoming(self, detail: str) -> None:
        if self._incoming is None:
            return
        _, ui_id, _, _, _, handle, _, _ = self._incoming
        handle.close()
        self._incoming = None
        self.file_changed.emit({
            "id": ui_id, "direction": "in", "state": "failed", "detail": detail,
        })

    def _shutdown_sockets(self) -> None:
        with self._state_lock:
            sockets = (self._sock, self._listen_sock)
            self._sock = None
            self._listen_sock = None
        for sock in sockets:
            if sock is None:
                continue
            try:
                sock.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                sock.close()
            except OSError:
                pass


#---------- Connection dialog ----------
class StartDialog(QDialog):
    def __init__(self) -> None:
        super().__init__()
        self.role = "server"
        self.setWindowTitle(ui_text(APP_NAME))
        self.setModal(True)
        self.setFixedSize(440, 390)

        root = QVBoxLayout(self)
        root.setContentsMargins(36, 32, 36, 30)
        root.setSpacing(18)
        mark = QLabel(ui_text("橘"))
        mark.setObjectName("brandMark")
        mark.setAlignment(Qt.AlignmentFlag.AlignCenter)
        title = QLabel(ui_text("选择运行方式"))
        title.setObjectName("dialogTitle")
        title.setAlignment(Qt.AlignmentFlag.AlignCenter)
        subtitle = QLabel(ui_text("端到端加密聊天与文件传输"))
        subtitle.setObjectName("muted")
        subtitle.setAlignment(Qt.AlignmentFlag.AlignCenter)
        root.addWidget(mark, 0, Qt.AlignmentFlag.AlignCenter)
        root.addWidget(title)
        root.addWidget(subtitle)

        choices = QHBoxLayout()
        self.server_button = QPushButton(ui_text("作为服务器"))
        self.client_button = QPushButton(ui_text("作为客户端"))
        for button in (self.server_button, self.client_button):
            button.setCheckable(True)
            button.setMinimumHeight(42)
        self.server_button.setChecked(True)
        self.server_button.clicked.connect(lambda: self._set_role("server"))
        self.client_button.clicked.connect(lambda: self._set_role("client"))
        choices.addWidget(self.server_button)
        choices.addWidget(self.client_button)
        root.addLayout(choices)

        self.host_input = QLineEdit("127.0.0.1")
        self.host_input.setPlaceholderText(ui_text("服务器 IP 或域名"))
        self.host_input.setEnabled(False)
        self.port_input = QSpinBox()
        self.port_input.setRange(1, 65535)
        self.port_input.setValue(TCP_PORT)
        self.port_input.setButtonSymbols(QSpinBox.ButtonSymbols.NoButtons)
        form = QHBoxLayout()
        form.addWidget(self.host_input, 3)
        form.addWidget(self.port_input, 1)
        root.addLayout(form)
        root.addStretch()

        self.start_button = QPushButton(ui_text("开始监听"))
        self.start_button.setObjectName("primaryButton")
        self.start_button.setMinimumHeight(44)
        self.start_button.clicked.connect(self._accept_checked)
        root.addWidget(self.start_button)

    def _set_role(self, role: str) -> None:
        self.role = role
        is_client = role == "client"
        self.server_button.setChecked(not is_client)
        self.client_button.setChecked(is_client)
        self.host_input.setEnabled(is_client)
        self.start_button.setText(
            ui_text("连接服务器") if is_client else ui_text("开始监听")
        )

    def _accept_checked(self) -> None:
        if self.role == "client" and not self.host_input.text().strip():
            self.host_input.setFocus()
            return
        self.accept()

    def values(self) -> Tuple[str, str, int]:
        return self.role, self.host_input.text().strip(), self.port_input.value()


#---------- Chat widgets ----------
class Composer(QTextEdit):
    send_requested = pyqtSignal()

    def __init__(self) -> None:
        super().__init__()
        self._minimum_editor_height = 42
        self._maximum_editor_height = 132
        self.setAcceptRichText(False)
        self.setFixedHeight(self._minimum_editor_height)
        self.document().documentLayout().documentSizeChanged.connect(
            lambda _size: self._adjust_height()
        )
        QTimer.singleShot(0, self._adjust_height)

    def _adjust_height(self) -> None:
        content_height = math.ceil(self.document().documentLayout().documentSize().height())
        desired_height = content_height + 18
        height = max(
            self._minimum_editor_height,
            min(self._maximum_editor_height, desired_height),
        )
        if self.height() != height:
            self.setMinimumHeight(height)
            self.setMaximumHeight(height)
        policy = (
            Qt.ScrollBarPolicy.ScrollBarAsNeeded
            if desired_height > self._maximum_editor_height
            else Qt.ScrollBarPolicy.ScrollBarAlwaysOff
        )
        self.setVerticalScrollBarPolicy(policy)

    def resizeEvent(self, event) -> None:
        super().resizeEvent(event)
        QTimer.singleShot(0, self._adjust_height)

    def keyPressEvent(self, event: QKeyEvent) -> None:
        if (
            event.key() in (Qt.Key.Key_Return, Qt.Key.Key_Enter)
            and event.modifiers() & Qt.KeyboardModifier.ControlModifier
        ):
            self.send_requested.emit()
            event.accept()
            return
        super().keyPressEvent(event)


class ClickableBubble(QFrame):
    def __init__(self, own: bool) -> None:
        super().__init__()
        self.own = own
        self.copy_text = ""
        self.setObjectName("ownBubble" if own else "peerBubble")
        self.setCursor(Qt.CursorShape.PointingHandCursor)
        self.setToolTip(ui_text("点击复制全部信息"))
        self.setMaximumWidth(620)

    def mousePressEvent(self, event) -> None:
        if event.button() == Qt.MouseButton.LeftButton:
            QApplication.clipboard().setText(self.copy_text)
            old_tip = self.toolTip()
            self.setToolTip(ui_text("已复制"))
            QTimer.singleShot(900, lambda: self.setToolTip(old_tip))
        super().mousePressEvent(event)


class TextBubble(ClickableBubble):
    def __init__(self, text: str, own: bool) -> None:
        super().__init__(own)
        layout = QVBoxLayout(self)
        layout.setContentsMargins(14, 10, 14, 10)
        label = QLabel(text)
        label.setWordWrap(True)
        label.setTextInteractionFlags(Qt.TextInteractionFlag.NoTextInteraction)
        label.setObjectName("bubbleText")
        layout.addWidget(label)
        self.copy_text = text


class FileBubble(ClickableBubble):
    def __init__(self, name: str, own: bool, size: Optional[int] = None) -> None:
        super().__init__(own)
        self.name = name
        self.size = size
        self.terminal = False
        layout = QVBoxLayout(self)
        layout.setContentsMargins(11, 9, 11, 9)
        layout.setSpacing(5)
        heading = QHBoxLayout()
        heading.setSpacing(8)
        icon = QLabel("FILE")
        icon.setObjectName("fileIcon")
        self.name_label = QLabel(name)
        self.name_label.setObjectName("fileName")
        self.name_label.setWordWrap(True)
        self.size_label = QLabel(human_size(size) if size is not None else "")
        self.size_label.setObjectName("fileSize")
        heading.addWidget(icon)
        heading.addWidget(self.name_label, 1)
        heading.addWidget(self.size_label)
        layout.addLayout(heading)
        self.progress = QProgressBar()
        self.progress.setRange(0, 100)
        self.progress.setValue(0)
        self.progress.setTextVisible(False)
        self.progress.setFixedHeight(3)
        layout.addWidget(self.progress)
        self._refresh_copy_text()

    def update_info(self, event: Dict[str, object]) -> None:
        state = event.get("state")
        if self.terminal and state not in ("complete", "failed"):
            return
        if "name" in event:
            self.name = str(event["name"])
            self.name_label.setText(self.name)
        if "size" in event:
            self.size = int(event["size"])
            self.size_label.setText(human_size(self.size))
        if "progress" in event:
            self.progress.setValue(int(event["progress"]))
        if state == "complete":
            self.terminal = True
            self.setProperty("transferState", "complete")
        elif state == "failed":
            self.terminal = True
            self.setProperty("transferState", "failed")
        self.style().unpolish(self)
        self.style().polish(self)
        self._refresh_copy_text()

    def _refresh_copy_text(self) -> None:
        lines = [self.name]
        if self.size is not None:
            size_label = "大小"
            lines.append(f"{size_label}: {human_size(self.size)} ({self.size} bytes)")
        self.copy_text = "\n".join(lines)


class DropChatArea(QScrollArea):
    files_dropped = pyqtSignal(list)

    def __init__(self) -> None:
        super().__init__()
        self.setAcceptDrops(True)

    def dragEnterEvent(self, event) -> None:
        if event.mimeData().hasUrls() and any(url.isLocalFile() for url in event.mimeData().urls()):
            event.acceptProposedAction()

    def dragMoveEvent(self, event) -> None:
        if event.mimeData().hasUrls():
            event.acceptProposedAction()

    def dropEvent(self, event) -> None:
        paths = []
        for url in event.mimeData().urls():
            if url.isLocalFile():
                paths.append(url.toLocalFile())
        if paths:
            self.files_dropped.emit(paths)
            event.acceptProposedAction()


#---------- Main chat window ----------
class MainWindow(QMainWindow):
    def __init__(self, role: str, host: str, port: int) -> None:
        super().__init__()
        self.setWindowTitle(ui_text(APP_NAME))
        self.resize(980, 720)
        self.setMinimumSize(700, 540)
        self.engine = TransferEngine()
        self.file_bubbles: Dict[str, FileBubble] = {}
        self.is_connected = False
        self._build_ui()
        self._connect_engine()
        self.engine.start(role, host, port)

    def _build_ui(self) -> None:
        central = QWidget()
        central.setObjectName("window")
        self.setCentralWidget(central)
        root = QVBoxLayout(central)
        root.setContentsMargins(0, 0, 0, 0)
        root.setSpacing(0)

        self.chat = DropChatArea()
        self.chat.setWidgetResizable(True)
        self.chat.setHorizontalScrollBarPolicy(Qt.ScrollBarPolicy.ScrollBarAlwaysOff)
        self.chat.setFrameShape(QFrame.Shape.NoFrame)
        self.chat.files_dropped.connect(self._queue_files)
        chat_content = QWidget()
        chat_content.setObjectName("chatContent")
        self.messages = QVBoxLayout(chat_content)
        self.messages.setContentsMargins(28, 24, 28, 24)
        self.messages.setSpacing(12)
        self.messages.addStretch()
        self.chat.setWidget(chat_content)
        root.addWidget(self.chat, 1)

        composer_frame = QFrame()
        composer_frame.setObjectName("composerFrame")
        composer_layout = QHBoxLayout(composer_frame)
        composer_layout.setContentsMargins(22, 13, 22, 16)
        composer_layout.setSpacing(10)
        self.attach_button = QToolButton()
        self.attach_button.setText("+")
        self.attach_button.setToolTip(ui_text("选择多个文件"))
        self.attach_button.setFixedSize(34, 34)
        self.attach_button.clicked.connect(self._choose_files)
        self.composer = Composer()
        self.composer.setPlaceholderText(
            ui_text("输入消息；Shift+Enter 换行，Ctrl+Enter 发送")
        )
        self.composer.send_requested.connect(self._send_message)
        self.send_button = QPushButton(ui_text("发送"))
        self.send_button.setObjectName("sendButton")
        self.send_button.setFixedSize(62, 34)
        self.send_button.clicked.connect(self._send_message)
        composer_layout.addWidget(self.attach_button, 0, Qt.AlignmentFlag.AlignBottom)
        composer_layout.addWidget(self.composer, 1)
        composer_layout.addWidget(self.send_button, 0, Qt.AlignmentFlag.AlignBottom)
        root.addWidget(composer_frame)

        self._set_controls_enabled(False)

    #---------- Engine signals ----------
    def _connect_engine(self) -> None:
        self.engine.connected.connect(self._on_connected)
        self.engine.status_changed.connect(self._add_system_message)
        self.engine.disconnected.connect(self._on_disconnected)
        self.engine.message_received.connect(lambda text: self._add_text(text, False))
        self.engine.message_failed.connect(
            lambda reason: self._add_system_message(
                f"{ui_text('消息发送失败')}：{reason}"
            )
        )
        self.engine.file_changed.connect(self._on_file_changed)

    def _on_connected(self, peer: str) -> None:
        self.is_connected = True
        self._set_controls_enabled(True)
        self.composer.setFocus()

    def _on_disconnected(self, reason: str) -> None:
        self.is_connected = False
        self._set_controls_enabled(False)
        self._add_system_message(reason)

    def _set_controls_enabled(self, enabled: bool) -> None:
        self.composer.setEnabled(enabled)
        self.send_button.setEnabled(enabled)
        self.attach_button.setEnabled(enabled)

    def _send_message(self) -> None:
        text = self.composer.toPlainText()
        if not self.is_connected or not text.strip():
            return
        self.composer.clear()
        self._add_text(text, True)
        self.engine.send_text(text)

    def _choose_files(self) -> None:
        paths, _ = QFileDialog.getOpenFileNames(self, ui_text("选择要发送的文件"))
        self._queue_files(paths)

    def _queue_files(self, paths: list) -> None:
        if not self.is_connected:
            self._add_system_message(ui_text("尚未连接，无法发送文件"))
            return
        for path in paths:
            name = pathlib.Path(path).name or path
            bubble = FileBubble(name, True)
            ui_id = self.engine.queue_file(path)
            self.file_bubbles[ui_id] = bubble
            self._add_bubble(bubble, True)

    def _on_file_changed(self, event: Dict[str, object]) -> None:
        ui_id = str(event["id"])
        bubble = self.file_bubbles.get(ui_id)
        if bubble is None:
            bubble = FileBubble(
                str(event.get("name", ui_text("接收文件"))),
                event.get("direction") == "out",
                int(event["size"]) if "size" in event else None,
            )
            self.file_bubbles[ui_id] = bubble
            self._add_bubble(bubble, event.get("direction") == "out")
        bubble.update_info(event)
        self._scroll_to_bottom()

    def _add_text(self, text: str, own: bool) -> None:
        self._add_bubble(TextBubble(text, own), own)

    def _add_bubble(self, bubble: QWidget, own: bool) -> None:
        row = QWidget()
        row_layout = QHBoxLayout(row)
        row_layout.setContentsMargins(0, 0, 0, 0)
        if own:
            row_layout.addStretch()
            row_layout.addWidget(bubble)
        else:
            row_layout.addWidget(bubble)
            row_layout.addStretch()
        self.messages.insertWidget(self.messages.count() - 1, row)
        self._scroll_to_bottom()

    def _add_system_message(self, text: str) -> None:
        label = QLabel(text)
        label.setObjectName("systemMessage")
        label.setAlignment(Qt.AlignmentFlag.AlignCenter)
        label.setWordWrap(True)
        self.messages.insertWidget(self.messages.count() - 1, label)
        self._scroll_to_bottom()

    def _scroll_to_bottom(self) -> None:
        QTimer.singleShot(
            0,
            lambda: self.chat.verticalScrollBar().setValue(
                self.chat.verticalScrollBar().maximum()
            ),
        )

    def closeEvent(self, event: QCloseEvent) -> None:
        self.engine.stop()
        event.accept()


#---------- Zero-blue-channel theme ----------
STYLE = """
* {
    font-family: "Microsoft YaHei UI", "Noto Sans CJK SC", sans-serif;
    font-size: 14px;
    color: #2b2100;
}
QWidget#window, QWidget#chatContent { background: #f7f400; }
QDialog { background: #f7f400; }
QFrame#composerFrame {
    background: #fffd00;
    border-top: 1px solid #e8dd00;
}
QLabel#brandMark {
    color: #ffff00;
    background: #e84d00;
    font-weight: 800;
    border-radius: 8px;
}
QLabel#brandMark { font-size: 25px; min-width: 58px; min-height: 58px; }
QLabel#dialogTitle { font-size: 23px; font-weight: 750; }
QLabel#muted { color: #8b7500; font-size: 12px; }
QPushButton, QToolButton {
    background: #fffd00;
    border: 1px solid #d9c900;
    border-radius: 6px;
    padding: 7px 12px;
}
QPushButton:hover, QToolButton:hover { border-color: #e84d00; color: #c93c00; }
QPushButton:checked, QPushButton#primaryButton, QPushButton#sendButton {
    color: #ffff00;
    background: #e84d00;
    border-color: #e84d00;
}
QPushButton#primaryButton:hover, QPushButton#sendButton:hover { background: #cf3f00; }
QPushButton:disabled, QToolButton:disabled { color: #bcae00; background: #eee800; }
QLineEdit, QSpinBox, QTextEdit {
    background: #ffff00;
    border: 1px solid #d9c900;
    border-radius: 7px;
    padding: 9px;
    selection-background-color: #e84d00;
    selection-color: #ffff00;
}
QLineEdit:focus, QSpinBox:focus, QTextEdit:focus { border: 1px solid #e84d00; }
QLineEdit:disabled { background: #eee800; color: #a69600; }
QScrollArea { background: #f7f400; border: none; }
QScrollBar:vertical { width: 8px; background: transparent; margin: 2px; }
QScrollBar::handle:vertical { background: #cdbe00; min-height: 28px; border-radius: 4px; }
QScrollBar::add-line:vertical, QScrollBar::sub-line:vertical { height: 0; }
QFrame#ownBubble, QFrame#peerBubble {
    border: 1px solid #eade00;
    border-radius: 8px;
}
QFrame#ownBubble { background: #f05a00; border-color: #f05a00; }
QFrame#peerBubble { background: #fffd00; }
QFrame#ownBubble QLabel { color: #ffff00; background: transparent; }
QFrame#peerBubble QLabel { color: #2b2100; background: transparent; }
QLabel#bubbleText { font-size: 14px; }
QLabel#fileIcon {
    font-size: 10px;
    font-weight: 800;
    padding: 4px 5px;
    border: 1px solid #e2cf00;
    border-radius: 4px;
}
QLabel#fileName { font-weight: 700; }
QLabel#fileSize { font-size: 11px; }
QFrame#ownBubble QLabel#fileSize { color: #fff100; }
QFrame#peerBubble QLabel#fileSize { color: #806b00; }
QFrame[transferState="failed"] { border: 2px solid #a82400; }
QFrame[transferState="complete"] { border: 2px solid #c84600; }
QProgressBar { border: none; background: #eade00; border-radius: 2px; }
QProgressBar::chunk { background: #8d2600; border-radius: 2px; }
QFrame#peerBubble QProgressBar::chunk { background: #e84d00; }
QLabel#systemMessage { color: #927c00; font-size: 11px; padding: 4px; }
QToolTip { color: #ffff00; background: #4a3100; border: none; padding: 5px; }
"""


#---------- Program entry ----------
def main() -> int:
    app = QApplication(sys.argv)
    app.setApplicationName(ui_text(APP_NAME))
    app.setStyle("Fusion")
    palette = app.palette()
    palette.setColor(QPalette.ColorRole.Window, QColor("#f7f400"))
    palette.setColor(QPalette.ColorRole.WindowText, QColor("#2b2100"))
    palette.setColor(QPalette.ColorRole.Base, QColor("#ffff00"))
    palette.setColor(QPalette.ColorRole.AlternateBase, QColor("#fffd00"))
    palette.setColor(QPalette.ColorRole.ToolTipBase, QColor("#4a3100"))
    palette.setColor(QPalette.ColorRole.ToolTipText, QColor("#ffff00"))
    palette.setColor(QPalette.ColorRole.Text, QColor("#2b2100"))
    palette.setColor(QPalette.ColorRole.Button, QColor("#fffd00"))
    palette.setColor(QPalette.ColorRole.ButtonText, QColor("#2b2100"))
    palette.setColor(QPalette.ColorRole.BrightText, QColor("#ffff00"))
    palette.setColor(QPalette.ColorRole.Highlight, QColor("#e84d00"))
    palette.setColor(QPalette.ColorRole.HighlightedText, QColor("#ffff00"))
    palette.setColor(QPalette.ColorRole.Link, QColor("#c93c00"))
    palette.setColor(QPalette.ColorRole.LinkVisited, QColor("#8d2600"))
    palette.setColor(QPalette.ColorRole.PlaceholderText, QColor("#8b7500"))
    app.setPalette(palette)
    app.setStyleSheet(STYLE)

    dialog = StartDialog()
    if dialog.exec() != QDialog.DialogCode.Accepted:
        return 0
    window = MainWindow(*dialog.values())
    window.show()
    return app.exec()


if __name__ == "__main__":
    sys.exit(main())
