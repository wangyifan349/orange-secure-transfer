#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# SPDX-License-Identifier: AGPL-3.0-or-later
# Project: https://github.com/wangyifan349/orange-secure-transfer
"""Independent encrypted CLI chat and verified file transfer; install: pip install cryptography pycryptodome

secure_transfer.py
=====================================================================
  Overview
---------------------------------------------------------------------
This script implements a full-featured, production-ready secure TCP
file and message transfer tool in a single Python file.

---------------------------------------------------------------------
  Structure
---------------------------------------------------------------------
1. Imports (standard + third party)
2. Constants/Protocol type definitions
3. Utility functions (framing, crypto, key derivation)
4. SecureConnection class: Handles encrypted send/recv, file transfer
5. Handshake (key agreement) logic
6. Interactive CLI (command-line interaction)
7. Server and client main entry
8. __main__ section (mode selection by argv)

---------------------------------------------------------------------
  Protocol Specification (Wire Format)
---------------------------------------------------------------------
Port:
    5555 (default; changeable)

Handshake:
    - Each side generates X25519 keypair
    - Each sends its raw 32-byte public key (client first)
    - Shared secret: private.exchange(peer)
    - Session key: 32 bytes via HKDF-SHA256(info='SecureTransfer')

Encrypted frame (all traffic after handshake):
    [4-byte big-endian length prefix]
    [12-byte ChaCha20 nonce][16-byte tag][ciphertext]

Decrypted Frame Payload Format:
    [1 byte type][payload...]
        0x01: Text       [utf-8 encoded text]
        0x02: FileMeta   [16-byte id|2-byte fnameLen|8-byte size|32-byte digest|filename]
        0x03: FileChunk  [16-byte id|raw bytes, <=64KiB]
        0x04: Close conn [empty payload]
        0x05: FileResult [16-byte id|1-byte success|32-byte receiver digest]

File integrity:
    - Sender: precomputes SHA-256, places in FILE_META
    - Receiver: streams SHA-256, verifies at file end
    - Receiver returns its result and calculated digest to the sender

---------------------------------------------------------------------
  Features
---------------------------------------------------------------------
- X25519 key exchange (ECDH)
- HKDF SHA-256 for session key
- ChaCha20-Poly1305 (PyCryptodome) AEAD encryption
- Threaded non-blocking send/recv
- Plaintext message and large file transfer (with integrity, chunked)
- Protocol and file integrity detailed above

=====================================================================
"""

#---------- Imports (Standard Library) ----------
import os                           # File I/O, randomness
import sys                          # Argument parsing
import socket                       # TCP sockets
import struct                       # Binary packing
import threading                    # For background recv
import pathlib                      # Path utilities
import hashlib                      # SHA-256 for files
import queue                        # Background file send queue
from typing import Dict, List, Optional, Tuple, BinaryIO # Type hints

#---------- Imports (Third Party) ----------
from cryptography.hazmat.primitives.asymmetric.x25519 import (
    X25519PrivateKey, X25519PublicKey)         # X25519 key exchange
from cryptography.hazmat.primitives.kdf.hkdf import HKDF  # HKDF
from cryptography.hazmat.primitives import hashes          # Hashing
from cryptography.hazmat.primitives import serialization   # For .public_bytes()
from Crypto.Cipher import ChaCha20_Poly1305               # AEAD encryption

#---------- Protocol / Format Constants ----------
TCP_PORT: int = 8000                                    # Default port number

FILE_CHUNK_SIZE: int = 64 * 1024                        # 64 KiB file chunks
NONCE_SIZE: int = 12                                    # ChaCha20 nonce size
TAG_SIZE: int = 16                                      # ChaCha20 MAC size

MSG_TEXT: int = 0x01                                    # Text message type
MSG_FILE_META: int = 0x02                               # File meta info
MSG_FILE_CHUNK: int = 0x03                              # File content chunk
MSG_CLOSE: int = 0x04                                   # Close signal
MSG_FILE_RESULT: int = 0x05                             # Receiver hash result

TRANSFER_ID_SIZE: int = 16                              # Random per-file identifier

#---------- Low-level Framing and Crypto Functions ----------
def send_frame(sock: socket.socket, data: bytes) -> None:
    sock.sendall(struct.pack('>I', len(data)) + data)      # Send with len prefix

def recv_frame(sock: socket.socket) -> bytes:
    length_prefix = recv_exact(sock, 4)
    frame_len: int = struct.unpack('>I', length_prefix)[0] # Length as int
    return recv_exact(sock, frame_len)

def recv_exact(sock: socket.socket, size: int) -> bytes:
    """Receive exactly size bytes or report a closed connection."""
    buffer = bytearray()
    while len(buffer) < size:
        chunk = sock.recv(size - len(buffer))
        if not chunk:
            raise EOFError('connection closed')
        buffer.extend(chunk)
    return bytes(buffer)

def parse_file_paths(value: str) -> List[str]:
    """Split paths while preserving Windows backslashes and removing quotes."""
    paths: List[str] = []
    current: List[str] = []
    quote: Optional[str] = None
    for char in value:
        if quote is not None:
            if char == quote:
                quote = None
            else:
                current.append(char)
        elif char in ('"', "'"):
            quote = char
        elif char.isspace():
            if current:
                paths.append(''.join(current))
                current = []
        else:
            current.append(char)
    if quote is not None:
        raise ValueError(f'unclosed {quote} quote')
    if current:
        paths.append(''.join(current))
    return paths

def derive_key(shared_secret: bytes) -> bytes:
    hkdf = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b'SecureTransfer')
    return hkdf.derive(shared_secret)                     # 32 bytes session key

def encrypt(key: bytes, plaintext: bytes) -> bytes:
    nonce = os.urandom(NONCE_SIZE)                        # Unique per frame
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ciphertext, tag = cipher.encrypt_and_digest(plaintext)
    return nonce + tag + ciphertext                       # [nonce|tag|ciphertext]

def decrypt(key: bytes, packet: bytes) -> bytes:
    nonce = packet[:NONCE_SIZE]
    tag = packet[NONCE_SIZE:NONCE_SIZE + TAG_SIZE]
    ciphertext = packet[NONCE_SIZE + TAG_SIZE:]
    cipher = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return cipher.decrypt_and_verify(ciphertext, tag)     # Exception on tamper

#---------- SecureConnection: Threaded Encrypted Socket + File Transfer ----------
class SecureConnection:
    """
    Secure TCP connection with completed handshake.
    All data sent/received is encrypted and authenticated.
    Runs a background thread for receiving.
    Provides high-level API: send_text(), send_file(), close().
    """
    def __init__(self, sock: socket.socket, key: bytes) -> None:
        self.sock: socket.socket = sock                          # Underlying TCP socket
        self.key: bytes = key                                    # Session key
        self.alive: bool = True                                  # Life flag for threads
        self.send_lock = threading.Lock()                        # Thread safety for send
        self.incoming_file: Optional[
            Tuple[bytes, str, int, int, BinaryIO, hashlib._Hash, bytes]
        ] = None                                                 # Receiving file state
        self.pending_files: Dict[bytes, Tuple[str, int, str]] = {} # Awaiting hash result
        self.pending_lock = threading.Lock()
        self.file_queue: queue.Queue[Optional[str]] = queue.Queue()
        self.recv_thread = threading.Thread(target=self._recv_loop,daemon=True)
        self.recv_thread.start()                                 # Start receiver
        self.send_thread = threading.Thread(target=self._file_send_loop, daemon=True)
        self.send_thread.start()                                 # Send files without blocking CLI

    def send_text(self, text: str) -> None:
        """Send UTF-8 text message."""
        self._send(MSG_TEXT, text.encode())

    def send_file(self, path: str) -> None:
        """Queue one file for background transfer."""
        path_obj = pathlib.Path(path)                                            # Path object for file
        if not path_obj.is_file():
            print(f'!! File not found: {path}')
            return
        self.file_queue.put(str(path_obj))
        print(f'[*] Queued file: {path_obj}')

    def send_files(self, paths: List[str]) -> None:
        """Queue multiple files in command order."""
        for path in paths:
            self.send_file(path)

    def _file_send_loop(self) -> None:
        """Background worker: hash and send queued files one at a time."""
        while self.alive:
            path = self.file_queue.get()
            if path is None:
                break
            try:
                self._send_file(path)
            except (OSError, EOFError, ValueError) as exc:
                print(f'\n!! File send failed: {path}: {exc}')
            finally:
                self.file_queue.task_done()

    def _send_file(self, path: str) -> None:
        """Hash and send one file; completion is reported after peer verification."""
        path_obj = pathlib.Path(path)
        if not path_obj.is_file():
            print(f'\n!! File not found: {path}')
            return
        file_size = path_obj.stat().st_size                                     # File size in bytes
        file_name_bytes = path_obj.name.encode()                                # File name (bytes)
        if len(file_name_bytes) > 0xffff:
            print(f'\n!! File name is too long: {path_obj.name}')
            return
        sha256 = hashlib.sha256()                                               # For integrity
        with path_obj.open('rb') as f:
            for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''):
                sha256.update(chunk)
        digest = sha256.digest()                                                # SHA-256 digest
        transfer_id = os.urandom(TRANSFER_ID_SIZE)

        meta_payload = (transfer_id +
                        struct.pack('>H', len(file_name_bytes)) +
                        struct.pack('>Q', file_size) +
                        digest +
                        file_name_bytes)
        with self.pending_lock:
            self.pending_files[transfer_id] = (path_obj.name, file_size, digest.hex())
        print(f'\n[*] Sending file: {path_obj.name} ({file_size} bytes, '
              f'SHA-256: {digest.hex()})')
        try:
            self._send(MSG_FILE_META, meta_payload)                             # Send file meta

            with path_obj.open('rb') as f:
                for chunk in iter(lambda: f.read(FILE_CHUNK_SIZE), b''):
                    if not self.alive:
                        raise EOFError('connection closed')
                    self._send(MSG_FILE_CHUNK, transfer_id + chunk)             # Send content chunks
        except Exception:
            with self.pending_lock:
                self.pending_files.pop(transfer_id, None)
            raise

    def close(self) -> None:
        """Send close signal and close socket."""
        was_alive = self.alive
        self.alive = False
        if was_alive:
            try:
                self._send(MSG_CLOSE, b'')
            except OSError:
                pass
        self.file_queue.put(None)
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        self.sock.close()

    def _send(self, msg_type: int, payload: bytes) -> None:
        plaintext = struct.pack('B', msg_type) + payload                        # 1 byte type + payload
        encrypted = encrypt(self.key, plaintext)
        with self.send_lock:
            send_frame(self.sock, encrypted)                                    # Encrypted frame

    def _recv_loop(self) -> None:
        """Background: receive, decrypt, dispatch frames."""
        try:
            while self.alive:
                frame = recv_frame(self.sock)
                plaintext = decrypt(self.key, frame)
                self._dispatch(plaintext)
        except (EOFError, OSError, ValueError, IndexError) as exc:
            if self.alive:
                print(f'[*] Connection closed or protocol error: {exc}')
        finally:
            self.alive = False
            if self.incoming_file is not None:
                target_name = self.incoming_file[1]
                received = self.incoming_file[3]
                total_size = self.incoming_file[2]
                self.incoming_file[4].close()
                self.incoming_file = None
                print(f'\n!! Incomplete file: {target_name} ({received}/{total_size} bytes)')
            try:
                self.sock.close()
            except OSError:
                pass

    def _dispatch(self, plaintext: bytes) -> None:
        if not plaintext:
            raise ValueError('empty message')
        msg_type = plaintext[0]
        body = plaintext[1:]
        if msg_type == MSG_TEXT:
            print(f'\n[Peer] {body.decode(errors="replace")}')
        elif msg_type == MSG_FILE_META:
            self._init_file_reception(body)
        elif msg_type == MSG_FILE_CHUNK:
            self._handle_file_chunk(body)
        elif msg_type == MSG_FILE_RESULT:
            self._handle_file_result(body)
        elif msg_type == MSG_CLOSE:
            print('[*] Peer closed connection')
            self.alive = False
        else:
            print(f'!! Unknown message type {msg_type}')

    def _init_file_reception(self, payload: bytes) -> None:
        if len(payload) < TRANSFER_ID_SIZE + 42:
            raise ValueError('invalid file metadata')
        transfer_id = payload[:TRANSFER_ID_SIZE]
        name_len = struct.unpack('>H', payload[16:18])[0]                    # Filename length
        total_size = struct.unpack('>Q', payload[18:26])[0]                  # File size
        expected_digest = payload[26:58]                                     # Sender's SHA-256
        if len(payload) != 58 + name_len:
            raise ValueError('invalid file metadata length')
        file_name = payload[58:].decode()                                    # Original filename
        file_name = pathlib.PurePath(file_name.replace('\\', '/')).name
        if not file_name:
            raise ValueError('empty file name')
        if self.incoming_file is not None:
            raise ValueError('received new file metadata before current file completed')
        target_name = f'received_{file_name}'                                # Output with prefix
        f_handle = open(target_name, 'wb')
        sha256 = hashlib.sha256()
        self.incoming_file = (
            transfer_id, target_name, total_size, 0, f_handle, sha256, expected_digest
        )
        print(f'\n[*] Receiving file: {file_name} -> {target_name} ({total_size} bytes)')
        if total_size == 0:
            self._finish_file_reception()

    def _handle_file_chunk(self, chunk: bytes) -> None:
        if self.incoming_file is None:
            print('!! Unexpected file chunk (no meta)')
            return
        if len(chunk) < TRANSFER_ID_SIZE:
            raise ValueError('invalid file chunk')
        chunk_transfer_id = chunk[:TRANSFER_ID_SIZE]
        chunk_data = chunk[TRANSFER_ID_SIZE:]
        transfer_id, target_name, total_size, received, f_handle, sha256, exp_digest = self.incoming_file
        if chunk_transfer_id != transfer_id:
            raise ValueError('file chunk transfer ID mismatch')
        if len(chunk_data) > total_size - received:
            raise ValueError('file contains more data than declared')
        f_handle.write(chunk_data)
        sha256.update(chunk_data)
        received += len(chunk_data)
        self.incoming_file = (
            transfer_id, target_name, total_size, received, f_handle, sha256, exp_digest
        )
        percent = received / total_size * 100
        print(f'\r    Progress: {percent:6.2f} %', end='', flush=True)
        if received == total_size:
            self._finish_file_reception()

    def _finish_file_reception(self) -> None:
        """Close, verify, and acknowledge the current incoming file."""
        if self.incoming_file is None:
            return
        transfer_id, target_name, total_size, received, f_handle, sha256, exp_digest = self.incoming_file
        f_handle.close()
        calc_digest = sha256.digest()
        verified = received == total_size and calc_digest == exp_digest
        self.incoming_file = None
        self._send(MSG_FILE_RESULT, transfer_id + bytes([verified]) + calc_digest)
        status = 'OK' if verified else 'FAILED'
        print(f'\n[*] File received: {target_name} '
              f'(SHA-256 {status}: {calc_digest.hex()})')

    def _handle_file_result(self, payload: bytes) -> None:
        """Print completion only after the receiver reports its calculated hash."""
        if len(payload) != TRANSFER_ID_SIZE + 1 + 32:
            raise ValueError('invalid file result')
        transfer_id = payload[:TRANSFER_ID_SIZE]
        result_flag = payload[TRANSFER_ID_SIZE]
        if result_flag not in (0, 1):
            raise ValueError('invalid file result flag')
        verified = result_flag == 1
        peer_digest = payload[TRANSFER_ID_SIZE + 1:]
        with self.pending_lock:
            pending = self.pending_files.pop(transfer_id, None)
        if pending is None:
            print('\n!! Received result for unknown file transfer')
            return
        file_name, file_size, expected_hex = pending
        digest_matches = peer_digest.hex() == expected_hex
        if verified and digest_matches:
            print(f'\n[*] File transfer complete: {file_name} ({file_size} bytes, '
                  f'SHA-256 OK: {expected_hex})')
        else:
            print(f'\n!! File transfer verification FAILED: {file_name} '
                  f'(expected {expected_hex}, peer calculated {peer_digest.hex()})')

#---------- Handshake (X25519 key exchange + HKDF) ----------
def perform_handshake(sock: socket.socket, is_server: bool) -> bytes:
    """
    Exchange X25519 public keys, compute session key (32 bytes).
    Returns: session key
    """
    private_key = X25519PrivateKey.generate()                        # Generate new keypair
    public_bytes = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.Raw,
        format=serialization.PublicFormat.Raw
    )                                                               # 32-byte wire public
    if is_server:
        peer_pub = recv_frame(sock)                                 # Server receives first
        send_frame(sock, public_bytes)
    else:
        send_frame(sock, public_bytes)                              # Client sends first
        peer_pub = recv_frame(sock)
    peer_key = X25519PublicKey.from_public_bytes(peer_pub)          # Peer public key
    shared_secret = private_key.exchange(peer_key)                  # X25519 exchange
    session_key = derive_key(shared_secret)                         # HKDF → 32B session key
    print('[*] Key exchange complete')
    return session_key

#---------- Command-line User Interface ----------
def cli_loop(conn: SecureConnection) -> None:
    """
    Interactive CLI:
    - <text>                    : Send text message
    - /send <path> [path ...]   : Send one or more files
    - /file <path> [path ...]   : Send one or more files
    - /q                        : Quit
    """
    try:
        while conn.alive:
            user_in = input('> ').strip()
            if not user_in:
                continue
            if user_in == '/q':
                conn.close(); break
            command, separator, arguments = user_in.partition(' ')
            if command.lower() in ('/send', '/file'):
                if not separator or not arguments.strip():
                    print('!! Usage: /send <path> [path ...]')
                    continue
                try:
                    paths = parse_file_paths(arguments)
                except ValueError as exc:
                    print(f'!! Invalid file path list: {exc}')
                    continue
                if not paths:
                    print('!! No file paths supplied')
                    continue
                conn.send_files(paths)
                continue
            conn.send_text(user_in)
    except (KeyboardInterrupt, EOFError):
        conn.close()

#---------- Server Main ----------
def run_server(bind_host: str, port: int) -> None:
    listen_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listen_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    listen_sock.bind((bind_host, port))
    listen_sock.listen(1)
    print(f"[*] Listening on {bind_host}:{port}")
    conn_sock, address = listen_sock.accept()
    listen_sock.close()
    print(f"[*] Connected from {address[0]}:{address[1]}")
    key = perform_handshake(conn_sock, is_server=True)
    cli_loop(SecureConnection(conn_sock, key))


#---------- Client ----------
def run_client(server_host: str, port: int) -> None:
    conn_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    conn_sock.connect((server_host, port))
    print(f"[*] Connected to {server_host}:{port}")
    key = perform_handshake(conn_sock, is_server=False)
    cli_loop(SecureConnection(conn_sock, key))


#---------- Arguments ----------
def parse_runtime_args(arguments: List[str]) -> Tuple[str, str, int]:
    role = "server"
    for argument in arguments:
        if "client" in argument.lstrip("-").lower():
            role = "client"
            break

    host = "127.0.0.1" if role == "client" else "0.0.0.0"
    port = TCP_PORT
    for argument in arguments:
        normalized = argument.lstrip("-").lower()
        if normalized in ("client", "server"):
            continue
        try:
            candidate_port = int(argument)
        except ValueError:
            host = argument
            continue
        if not 1 <= candidate_port <= 65535:
            raise ValueError(f"invalid port: {candidate_port}")
        port = candidate_port
    return role, host, port


#---------- Program entry ----------
def main() -> int:
    try:
        role, host, port = parse_runtime_args(sys.argv[1:])
        if role == "client":
            run_client(host, port)
        else:
            run_server(host, port)
    except (OSError, ValueError) as exc:
        print(f"!! {exc}")
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
