# ChatCLI - Secure LAN Chat Application

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

A feature-rich, secure LAN-only chat application for real-time messaging, file sharing, and image broadcasting on local networks.

## ✨ Features

- **🔐 End-to-End Encryption**: RSA key exchange + AES encryption for all messages
- **📁 Secure File Transfer**: Send files with explicit user acceptance required
- **🖼️ Image Broadcasting**: Share images with all users on the network
- **👥 Auto Peer Discovery**: Automatically find users on the same network
- **💬 Real-time Messaging**: Instant message delivery with read receipts
- **🌐 Web Dashboard**: Beautiful web interface for monitoring chats
- **🛡️ Security Features**:
  - File type whitelist
  - Size limits (Files: 100MB, Images: 10MB)
  - Rate limiting to prevent spam
  - Input validation and sanitization
- **📊 Status Indicators**: Set your status (online/away/busy)
- **💾 Chat History**: Save conversations to file
- **🎨 Modern UI**: Colorful CLI with emoji support

## 📋 Requirements

- Python 3.8 or higher
- Windows, macOS, or Linux
- Same Wi-Fi network for all users

## 🚀 Installation

### Quick Install

```bash
# Clone the repository
git clone https://github.com/yourusername/chatcli.git
cd chatcli

# Install dependencies
pip install -r requirements.txt

# Run ChatCLI
python -m chatcli.main -n YourName
```

### Install as Package

```bash
pip install -e .

# Run from anywhere
chatcli -n YourName
```

## 💻 Usage

### Basic Commands

```bash
# Start with custom nickname
chatcli -n Alice

# Use custom port
chatcli -n Bob -p 5556

# Custom web dashboard port
chatcli -n Charlie -w 8081
```

### In-App Commands

| Command | Description |
|---------|-------------|
| `/list` | List all discovered peers |
| `/chat <number>` | Start chatting with a peer |
| `/msg <number> <text>` | Send quick message |
| `/send <number> <file>` | Send file (requires acceptance) |
| `/sendimg <file>` | Broadcast image to all |
| `/broadcast <text>` | Broadcast message to all |
| `/accept` | Accept pending file transfer |
| `/decline` | Decline file transfer |
| `/downloads` | Show downloads directory |
| `/web` | Start web dashboard |
| `/status <type>` | Set status (online/away/busy) |
| `/help` | Show all commands |
| `/exit` | Exit ChatCLI |

## 📖 Examples

### Example 1: Basic Chat

```bash
# Terminal 1 (Alice)
chatcli -n Alice

# Terminal 2 (Bob)
chatcli -n Bob

# In Alice's terminal
Alice> /list
Alice> /chat 1
Alice> Hello Bob!

# In Bob's terminal
Bob> Hi Alice!
```

### Example 2: File Transfer

```bash
# Alice sends a file to Bob
Alice> /send 1 document.pdf

# Bob receives notification and accepts
Bob> /accept

# File is transferred and saved to ~/ChatCLI_Downloads/
```

### Example 3: Image Broadcasting

```bash
# Alice broadcasts an image to everyone
Alice> /sendimg vacation.jpg

# All users receive the image in their downloads folder
```

### Example 4: Web Dashboard

```bash
# Start web dashboard
Alice> /web

# Open browser to http://localhost:8080
# View real-time messages, peers, and file transfers
```

## 🔒 Security

ChatCLI implements multiple security layers:

1. **Encryption**: All messages encrypted with RSA-2048 + AES
2. **File Validation**: Only whitelisted file types allowed
3. **User Consent**: File transfers require explicit acceptance
4. **Rate Limiting**: Prevents spam and abuse
5. **Input Sanitization**: All inputs validated and sanitized
6. **LAN-Only**: No internet connection required or used

### Allowed File Types

Documents: `.txt`, `.pdf`, `.doc`, `.docx`, `.xls`, `.xlsx`, `.ppt`, `.pptx`  
Images: `.jpg`, `.jpeg`, `.png`, `.gif`, `.webp`, `.bmp`  
Archives: `.zip`, `.tar`, `.gz`, `.7z`  
Code: `.py`, `.js`, `.html`, `.css`, `.json`, `.xml`  
And more...

## 🌐 Web Dashboard

Access the beautiful web dashboard at `http://localhost:8080` (or your custom port).

Features:
- Real-time message updates
- Active peer list with status indicators
- File transfer history
- Message statistics
- Responsive design for mobile and desktop

## 📁 File Structure

```
chat-cli/
├── chatcli/
│   ├── __init__.py       # Package initialization
│   ├── main.py           # Main application
│   ├── config.py         # Configuration settings
│   └── downloads/        # Downloaded files (created at runtime)
├── requirements.txt      # Python dependencies
├── setup.py             # Package setup
├── README.md            # This file
└── LICENSE              # MIT License
```

## 🛠️ Configuration

Edit `chatcli/config.py` to customize:

- File size limits
- Allowed file types
- Rate limiting parameters
- Encryption settings
- Download directory location

## 🐛 Troubleshooting

### Port Already in Use

```bash
# Use a different port
chatcli -n Alice -p 5556
```

### Peers Not Discovered

- Ensure all users are on the same Wi-Fi network
- Check firewall settings (allow UDP/TCP on chosen port)
- Wait a few seconds for discovery to complete

### File Transfer Fails

- Check file size (max 100MB for files, 10MB for images)
- Verify file type is in whitelist
- Ensure recipient has accepted the transfer

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 👏 Acknowledgments

- Built with Python and love ❤️
- Uses `cryptography` for encryption
- Uses `Pillow` for image processing

## 📞 Support

For issues, questions, or suggestions:
- Open an issue on GitHub
- Email: contact@chatcli.dev

## 🎯 Roadmap

- [ ] Voice messaging
- [ ] Video calls
- [ ] Group chats
- [ ] Message reactions
- [ ] File preview in web dashboard
- [ ] Mobile app

---

**Made with ❤️ by the ChatCLI Team**
