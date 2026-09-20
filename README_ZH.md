# 🍊 Orange Secure Transfer

[English](README.md) | **简体中文**

![Python](https://img.shields.io/badge/Python-3.10%2B-f2a900?style=flat-square&logo=python&logoColor=000000)
![PyQt6](https://img.shields.io/badge/GUI-PyQt6-e85d04?style=flat-square)
![License](https://img.shields.io/badge/license-AGPL--3.0-e85d04?style=flat-square)
![Security](https://img.shields.io/badge/transport-encrypted-2b2100?style=flat-square)

[GitHub 项目主页](https://github.com/wangyifan349/orange-secure-transfer)

一个基于 Python 的端到端加密聊天和文件传输工具，适合局域网或可信网络中的点对点通信。项目提供中文 GUI、英文 GUI 和无 GUI 命令行版本，三个程序均为**完全独立的单文件程序**，不互相导入本地模块。

通信内容使用 X25519 协商会话密钥，使用 HKDF-SHA256 派生密钥，再使用 ChaCha20-Poly1305 加密和认证。文件采用分块传输，接收端重新计算 SHA-256，并将校验结果返回发送端。只有发送端收到对端校验成功的回执后，文件才会被报告为传输完成。

## ✨ 功能

- 🔐 X25519 密钥交换和 HKDF-SHA256 会话密钥派生
- 🛡️ ChaCha20-Poly1305 加密、完整性保护和篡改检测
- 💬 文本聊天和大文件传输可以同时进行
- 📦 多文件队列发送，支持 Windows/Linux 路径
- 🧾 文件接收端 SHA-256 校验和回执确认
- 🖱️ GUI 支持多个文件拖拽发送
- 🪟 中文 PyQt6 GUI：`secure_transfer_gui_cn.py`
- 🌍 English PyQt6 GUI：`secure_transfer_gui_en.py`
- ⌨️ 无 GUI CLI：`secure_transfer_cli.py`
- 🧵 文件读取、哈希、网络收发不占用 GUI 主线程
- 🎨 GUI 使用橘红色视觉风格，颜色蓝色通道统一为 `00`

## 📥 安装

需要 Python 3.10 或更高版本。进入项目目录后执行：

```bash
git clone https://github.com/wangyifan349/orange-secure-transfer.git
cd orange-secure-transfer
python -m pip install --upgrade pip
python -m pip install PyQt6 cryptography pycryptodome
python secure_transfer_gui_cn.py
```

CLI 不需要 PyQt6，只需要：

```bash
python -m pip install cryptography pycryptodome
```

## ▶️ 运行

### GUI

```bash
cd orange-secure-transfer
python secure_transfer_gui_cn.py
python secure_transfer_gui_en.py
```

启动后选择服务器或客户端。客户端填写服务器 IP 和端口，默认端口是 `5555`。GUI 底部输入框支持多行文本：`Shift+Enter` 换行，`Ctrl+Enter` 发送；可以点击文件按钮或把多个文件直接拖进聊天区域。

### CLI

CLI 默认无参数启动服务器，监听 `0.0.0.0:8000`：

```bash
cd orange-secure-transfer
python secure_transfer_cli.py
```

服务器也可以显式指定：

```bash
python secure_transfer_cli.py server
python secure_transfer_cli.py --server 0.0.0.0 8000
python secure_transfer_cli.py server 0.0.0.0 9000
```

客户端示例：

```bash
python secure_transfer_cli.py client 192.168.1.10 8000
python secure_transfer_cli.py --client 192.168.1.10 8000
```

只要参数中出现包含 `client` 的值，就会使用客户端模式，因此下面的写法也能识别为客户端：

```bash
python secure_transfer_cli.py my-client-mode 192.168.1.10 8000
```

CLI 交互命令：

```text
直接输入文字并回车       发送文字
/send file1 file2        发送一个或多个文件
/file file1 file2        发送一个或多个文件
/q                       退出
```

带空格的路径可以使用单引号或双引号：

```text
/send "C:\Program Files\example.bin" '/home/user/my file.txt'
```

## 🧠 工作原理

### 1. 建立会话

客户端和服务器连接后，各自生成临时 X25519 密钥对。双方只交换 32 字节原始公钥，不传输私钥。双方使用自己的私钥和对方公钥计算相同的共享秘密：

```text
shared_secret = X25519(private_key, peer_public_key)
```

共享秘密随后通过 HKDF-SHA256 派生 32 字节会话密钥：

```text
session_key = HKDF-SHA256(shared_secret, info="SecureTransfer")
```

每次程序运行都会生成新的临时密钥对，因此不会直接复用长期密钥。

### 2. 加密帧

握手完成后，所有应用数据都通过加密帧发送。每个帧包含长度前缀，帧内部使用新的随机 12 字节 nonce：

```text
[4-byte frame length]
[12-byte nonce][16-byte authentication tag][ciphertext]
```

ChaCha20-Poly1305 同时提供机密性和认证能力。接收端解密时会验证 authentication tag，数据被篡改或密钥不匹配时，帧会被拒绝。

### 3. 消息类型

加密后的消息第一个字节表示类型：

```text
0x01  Text        UTF-8 文本
0x02  FileMeta    传输 ID、文件名、大小和发送端 SHA-256
0x03  FileChunk   传输 ID 和文件块，单块不超过 64 KiB
0x04  Close       关闭连接
0x05  FileResult  接收端校验状态和计算出的 SHA-256
```

### 4. 文件校验

发送端发送文件元数据前计算 SHA-256，然后分块发送文件。接收端边写入文件边计算自己的 SHA-256，并检查实际接收长度是否等于元数据声明的大小。传输结束后，接收端回传：

```text
transfer_id + success_flag + receiver_digest
```

发送端只有在 `success_flag == 1` 且 `receiver_digest` 与自己的摘要完全一致时，才显示成功。文件内容不通过校验时不会被误报为完成。

### 5. 线程模型

GUI 主线程只处理 Qt 控件和界面信号。连接、握手、socket 接收、文本发送、文件发送、文件哈希和文件落盘都在后台线程执行。文件发送线程每发送一个文件块就释放发送锁，文本发送线程可以在大文件传输期间继续发送消息，避免大文件阻塞正常聊天。

## 🗂️ 项目文件

```text
secure_transfer_gui_cn.py   中文 GUI，独立运行
secure_transfer_gui_en.py   English GUI，独立运行
secure_transfer_cli.py      CLI，独立运行
README.md                   默认英文项目说明
README_ZH.md                简体中文项目说明
LICENSE                     GNU AGPL-3.0 许可证
```

## ⚠️ 安全说明

本项目提供加密传输和完整性校验，但没有内置身份认证、证书体系或公钥指纹确认。首次连接时无法自动确认对方真实身份。请在可信网络中使用，并通过独立渠道确认服务器地址和运行环境。

项目默认只支持一个连接。若需要多人聊天室、身份认证、断点续传、持久化消息或公网部署，应在此协议基础上增加认证和服务端会话管理。

## 📄 许可证

本项目使用 GNU Affero General Public License v3.0。完整条款见 [LICENSE](LICENSE)。

## ₿ 支持项目

如果这个项目对你有帮助，可以使用 Bitcoin 支持：

```text
bc1qevgpfgmy3al2v8anu7n4zrgem8045dkvu3ulrh7rjyd4jv3dsgwswkq6tj
```
