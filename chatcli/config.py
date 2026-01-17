#!/usr/bin/env python3
"""
ChatCLI Configuration
"""

import os
from pathlib import Path

class Config:
    """Configuration settings for ChatCLI"""
    
    # Network settings
    DEFAULT_PORT = 5555
    DEFAULT_WEB_PORT = 8080
    BROADCAST_INTERVAL = 5  # seconds
    PEER_TIMEOUT = 30  # seconds
    
    # File transfer settings
    MAX_FILE_SIZE = 100 * 1024 * 1024  # 100MB
    CHUNK_SIZE = 1024 * 1024  # 1MB chunks
    MAX_TRANSFER_RETRIES = 3
    TRANSFER_TIMEOUT = 300  # 5 minutes
    
    # Image settings
    MAX_IMAGE_SIZE = 10 * 1024 * 1024  # 10MB
    IMAGE_COMPRESSION_THRESHOLD = 5 * 1024 * 1024  # 5MB
    IMAGE_COMPRESSION_QUALITY = 85
    ALLOWED_IMAGE_FORMATS = {'.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp'}
    
    # File type whitelist
    ALLOWED_FILE_EXTENSIONS = {
        # Documents
        '.txt', '.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx',
        '.odt', '.ods', '.odp', '.rtf', '.csv',
        # Images
        '.jpg', '.jpeg', '.png', '.gif', '.webp', '.bmp', '.svg', '.ico',
        # Archives
        '.zip', '.tar', '.gz', '.7z', '.rar',
        # Code
        '.py', '.js', '.html', '.css', '.json', '.xml', '.yaml', '.yml',
        '.c', '.cpp', '.h', '.java', '.go', '.rs', '.sh', '.bat',
        # Media
        '.mp3', '.mp4', '.avi', '.mkv', '.wav', '.flac',
        # Other
        '.md', '.log', '.sql', '.db'
    }
    
    # Security settings
    ENABLE_ENCRYPTION = True
    MESSAGE_RATE_LIMIT = 100  # messages per minute
    BROADCAST_RATE_LIMIT = 10  # broadcasts per minute
    
    # Directories
    @staticmethod
    def get_downloads_dir():
        """Get or create downloads directory"""
        downloads = Path.home() / 'ChatCLI_Downloads'
        downloads.mkdir(exist_ok=True)
        return downloads
    
    @staticmethod
    def get_temp_dir():
        """Get or create temporary directory for partial transfers"""
        temp = Path.home() / 'ChatCLI_Downloads' / '.temp'
        temp.mkdir(parents=True, exist_ok=True)
        return temp
    
    # Logging
    LOG_FILE = 'chatcli.log'
    LOG_LEVEL = 'INFO'
    
    # Web dashboard
    WEB_REFRESH_INTERVAL = 2000  # milliseconds
    WEB_MAX_MESSAGES = 100
    WEB_MAX_FILES = 50
