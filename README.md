# 🍊 Orange Secure Transfer

**English** | [简体中文](README_ZH.md)

![Python](https://img.shields.io/badge/Python-3.10%2B-f2a900?style=flat-square&logo=python&logoColor=000000)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-e85d04?style=flat-square)
![License](https://img.shields.io/badge/license-AGPL--3.0-e85d04?style=flat-square)
![Security](https://img.shields.io/badge/transport-encrypted-2b2100?style=flat-square)

[GitHub repository](https://github.com/wangyifan349/orange-secure-transfer)

Orange Secure Transfer is an end-to-end encrypted chat and file transfer tool written in Python. It is designed for peer-to-peer communication on local or trusted networks. The project includes a Chinese GUI, an English GUI, and a headless command-line version. Each program is a completely independent, single-file application and does not import another local module.

The protocol negotiates a session key with X25519, derives the encryption key with HKDF-SHA256, and encrypts every application frame with ChaCha20-Poly1305. Files are transferred in chunks and verified by the receiver with SHA-256. A transfer is reported as complete only after the sender receives a successful verification response from the peer.

## ✨ Features

- 🔐 X25519 key exchange and HKDF-SHA256 session-key derivation
- 🛡️ ChaCha20-Poly1305 encryption, authentication, and tamper detection
- 💬 Text chat remains responsive during large or multiple file transfers
- 📦 Multi-file send queue with Windows and Linux path support
- 🧾 Receiver-side SHA-256 verification and acknowledgment
- 🖱️ Drag-and-drop sending of multiple files in the GUI
- 🪟 Chinese PyQt6 GUI: `secure_transfer_gui_cn.py`
- 🌍 English PyQt6 GUI: `secure_transfer_gui_en.py`
- ⌨️ Headless CLI: `secure_transfer_cli.py`
- 🧵 File I/O, hashing, and network operations run outside the GUI thread
- 🎨 Orange-red interface with the blue channel of every configured color set to `00`

## 📥 Installation

Python 3.10 or newer is recommended. Clone the repository, enter the project directory, install the dependencies, and start the Chinese GUI:

```bash
git clone https://github.com/wangyifan349/orange-secure-transfer.git
cd orange-secure-transfer
python -m pip install --upgrade pip
python -m pip install PyQt6 cryptography pycryptodome
python secure_transfer_gui_cn.py
```

The CLI does not require PyQt6:

```bash
python -m pip install cryptography pycryptodome
```

## ▶️ Running

### GUI

```bash
cd orange-secure-transfer
python secure_transfer_gui_cn.py
python secure_transfer_gui_en.py
```

Choose server or client mode in the startup dialog. In client mode, enter the server IP address and port. The GUI default port is `5555`. The message editor supports multiple lines: press `Shift+Enter` for a newline and `Ctrl+Enter` to send. Select files with the attachment button or drag multiple files directly into the chat area.

### CLI

With no arguments, the CLI starts a server on `0.0.0.0:8000`:

```bash
cd orange-secure-transfer
python secure_transfer_cli.py
```

Explicit server examples:

```bash
python secure_transfer_cli.py server
python secure_transfer_cli.py --server 0.0.0.0 8000
python secure_transfer_cli.py server 0.0.0.0 9000
```

Client examples:

```bash
python secure_transfer_cli.py client 192.168.1.10 8000
python secure_transfer_cli.py --client 192.168.1.10 8000
```

Client mode takes priority whenever a role argument contains the word `client`, so this form is also accepted:

```bash
python secure_transfer_cli.py my-client-mode 192.168.1.10 8000
```

CLI commands:

```text
Type text and press Enter    Send a text message
/send file1 file2           Send one or more files
/file file1 file2           Send one or more files
/q                          Quit
```

Paths containing spaces may use single or double quotes:

```text
/send "C:\Program Files\example.bin" '/home/user/my file.txt'
```

## 🧠 How It Works

### 1. Session establishment

After the TCP connection is established, the client and server each generate an ephemeral X25519 key pair. Only the raw 32-byte public keys are exchanged; private keys are never transmitted. Both peers independently calculate the same shared secret using their private key and the peer's public key:

```text
shared_secret = X25519(private_key, peer_public_key)
```

The shared secret is passed through HKDF-SHA256 to derive a 32-byte session key:

```text
session_key = HKDF-SHA256(shared_secret, info="SecureTransfer")
```

A new ephemeral key pair is generated every time the program runs, so session keys are not directly reused.

### 2. Encrypted frames

After the handshake, all application data is sent in encrypted frames. Each frame has a length prefix and uses a fresh random 12-byte nonce:

```text
[4-byte frame length]
[12-byte nonce][16-byte authentication tag][ciphertext]
```

ChaCha20-Poly1305 provides confidentiality and authentication. During decryption, the receiver verifies the authentication tag. A modified frame or an incorrect key causes verification to fail and the frame to be rejected.

### 3. Message types

The first byte of the encrypted plaintext identifies the message type:

```text
0x01  Text        UTF-8 text
0x02  FileMeta    Transfer ID, file name, size, and sender SHA-256
0x03  FileChunk   Transfer ID and a file chunk of up to 64 KiB
0x04  Close       Connection close signal
0x05  FileResult  Receiver verification status and calculated SHA-256
```

### 4. File verification

Before sending metadata, the sender calculates the file's SHA-256 digest. The file is then sent in chunks. The receiver calculates its own SHA-256 digest while writing the chunks and verifies that the number of received bytes matches the declared file size. When the transfer ends, the receiver returns:

```text
transfer_id + success_flag + receiver_digest
```

The sender reports success only when `success_flag == 1` and `receiver_digest` exactly matches its own digest. A damaged or incomplete file is never reported as successfully transferred.

### 5. Threading model

The GUI thread handles only Qt widgets and signals. Connection setup, key exchange, socket reception, text sending, file sending, hashing, and disk writes run in background threads. The file sender releases the send lock after every file chunk, allowing the text sender to transmit messages while large files are in progress.

## 🗂️ Project Files

```text
secure_transfer_gui_cn.py   Independent Chinese GUI
secure_transfer_gui_en.py   Independent English GUI
secure_transfer_cli.py      Independent command-line version
README.md                   Default English documentation
README_ZH.md                Simplified Chinese documentation
LICENSE                     GNU AGPL-3.0 license notice
```

## ⚠️ Security Notes

This project provides encrypted transport and file-integrity verification, but it does not include identity authentication, a certificate infrastructure, or public-key fingerprint confirmation. On first connection, it cannot automatically prove the peer's real identity. Use it on a trusted network and verify the server address and environment through a separate channel.

The program supports one connection at a time. Multi-user chat, identity authentication, transfer resumption, persistent messages, and public Internet deployment require additional authentication and server-side session management.

## 📄 License

This project is licensed under the GNU Affero General Public License v3.0 or later. See [LICENSE](LICENSE) for the license notice and the link to the complete official terms.

## ₿ Support the Project

If this project is useful to you, you can support its development with Bitcoin:

```text
bc1qevgpfgmy3al2v8anu7n4zrgem8045dkvu3ulrh7rjyd4jv3dsgwswkq6tj
```
