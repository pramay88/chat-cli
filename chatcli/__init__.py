# chatcli/__init__.py
"""
ChatCLI - A feature-rich LAN chat application for command-line
=================================================================

ChatCLI is a cross-platform CLI tool for instant messaging over local networks.
Perfect for teams, offices, or home networks without internet.

Features:
    - Auto peer discovery
    - Direct messaging & broadcasts
    - Message delivery status
    - Web dashboard
    - Chat history export
    - Encryption ready
    - Multi-user support

Quick Start:
    >>> from chatcli import ChatCLI
    >>> app = ChatCLI(nickname="Alice")
    >>> app.start()
    >>> app.interactive_menu()

Command-line usage:
    $ chatcli -n Alice
    $ chatcli --help

For more information, visit: https://github.com/yourusername/chatcli
"""

__version__ = "1.0.0"
__author__ = "ChatCLI Team"
__email__ = "contact@chatcli.dev"
__license__ = "MIT"
__url__ = "https://github.com/yourusername/chatcli"

from .main import ChatCLI, main

__all__ = ['ChatCLI', 'main', '__version__']