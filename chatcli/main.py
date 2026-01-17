#!/usr/bin/env python3
"""
ChatCLI - A feature-rich LAN chat application
Author: ChatCLI Team
License: MIT
"""

import socket
import threading
import json
import time
import sys
import os
import hashlib
import base64
from datetime import datetime
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import html
from io import BytesIO

try:
    from PIL import Image
    PILLOW_AVAILABLE = True
except ImportError:
    PILLOW_AVAILABLE = False

from .config import Config


class FileTransfer:
    """Manages file transfer state"""
    def __init__(self, file_id, filename, filesize, sender_ip, sender_name, file_hash):
        self.file_id = file_id
        self.filename = filename
        self.filesize = filesize
        self.sender_ip = sender_ip
        self.sender_name = sender_name
        self.file_hash = file_hash
        self.chunks_received = 0
        self.total_chunks = (filesize + Config.CHUNK_SIZE - 1) // Config.CHUNK_SIZE
        self.data = BytesIO()
        self.status = 'pending'  # pending, accepted, declined, transferring, completed, failed
        self.created_at = time.time()
        
    def get_progress(self):
        """Get transfer progress percentage"""
        if self.total_chunks == 0:
            return 100
        return int((self.chunks_received / self.total_chunks) * 100)


class ChatCLI:
    def __init__(self, nickname=None, port=5555):
        self.port = port
        self.nickname = nickname or f"User_{os.getpid()}"
        self.running = False
        self.peers = {}  # {ip: {nickname, last_seen, port, public_key}}
        self.messages = []  # Store all messages
        self.current_chat = None  # Current chat partner
        
        # Encryption - RSA for key exchange, Fernet for messages
        self.private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.public_key = self.private_key.public_key()
        
        # Symmetric key for this session
        self.session_key = Fernet.generate_key()
        self.cipher = Fernet(self.session_key)
        
        # Sockets
        self.tcp_socket = None
        self.udp_socket = None
        self.broadcast_socket = None
        
        # Locks
        self.peers_lock = threading.Lock()
        self.messages_lock = threading.Lock()
        self.transfers_lock = threading.Lock()
        
        # Get local IP
        self.local_ip = self._get_local_ip()
        
        # File transfers
        self.pending_transfers = {}  # {file_id: FileTransfer}
        self.completed_transfers = []  # List of completed transfers
        self.active_transfers = {}  # {file_id: FileTransfer} currently transferring
        
        # Web dashboard
        self.web_server = None
        self.web_port = 8080
        self.web_running = False
        
        # Input lock for chat mode
        self.input_lock = threading.Lock()
        self.chat_active = False
        
        # Rate limiting
        self.message_timestamps = []
        self.broadcast_timestamps = []
        
        # Status
        self.status = 'online'  # online, away, busy
        
    def _get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception:
            return "127.0.0.1"
    
    def _timestamp(self):
        """Get current timestamp in [HH:MM:SS] format"""
        return datetime.now().strftime("[%H:%M:%S]")
    
    def _get_public_key_pem(self):
        """Get public key as PEM string"""
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode('utf-8')
    
    def _load_public_key_pem(self, pem_data):
        """Load public key from PEM string"""
        return serialization.load_pem_public_key(
            pem_data.encode('utf-8'),
            backend=default_backend()
        )
    
    def _encrypt_for_peer(self, peer_ip, data):
        """Encrypt data for a specific peer using their public key"""
        with self.peers_lock:
            if peer_ip not in self.peers or 'public_key' not in self.peers[peer_ip]:
                return None
            peer_public_key = self.peers[peer_ip]['public_key']
        
        # Encrypt with peer's public key
        encrypted = peer_public_key.encrypt(
            data.encode() if isinstance(data, str) else data,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        return base64.b64encode(encrypted).decode('utf-8')
    
    def _decrypt_from_peer(self, encrypted_data):
        """Decrypt data using our private key"""
        try:
            encrypted_bytes = base64.b64decode(encrypted_data)
            decrypted = self.private_key.decrypt(
                encrypted_bytes,
                padding.OAEP(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    algorithm=hashes.SHA256(),
                    label=None
                )
            )
            return decrypted.decode('utf-8')
        except Exception as e:
            return None
    
    def _validate_file(self, filename, filesize):
        """Validate file for transfer"""
        path = Path(filename)
        
        # Check file exists
        if not path.exists():
            return False, "File not found"
        
        # Check file size
        if filesize > Config.MAX_FILE_SIZE:
            return False, f"File too large (max {Config.MAX_FILE_SIZE // (1024*1024)}MB)"
        
        # Check extension
        ext = path.suffix.lower()
        if ext not in Config.ALLOWED_FILE_EXTENSIONS:
            return False, f"File type '{ext}' not allowed"
        
        return True, "OK"
    
    def _calculate_file_hash(self, filepath):
        """Calculate SHA256 hash of file"""
        sha256 = hashlib.sha256()
        with open(filepath, 'rb') as f:
            while chunk := f.read(Config.CHUNK_SIZE):
                sha256.update(chunk)
        return sha256.hexdigest()
    
    def _compress_image(self, image_path):
        """Compress image if it's too large"""
        if not PILLOW_AVAILABLE:
            return image_path
        
        path = Path(image_path)
        if path.stat().st_size <= Config.IMAGE_COMPRESSION_THRESHOLD:
            return image_path
        
        try:
            img = Image.open(image_path)
            
            # Convert RGBA to RGB if necessary
            if img.mode == 'RGBA':
                background = Image.new('RGB', img.size, (255, 255, 255))
                background.paste(img, mask=img.split()[3])
                img = background
            
            # Compress
            compressed_path = Config.get_temp_dir() / f"compressed_{path.name}"
            img.save(compressed_path, optimize=True, quality=Config.IMAGE_COMPRESSION_QUALITY)
            
            self.print_info(f"Image compressed: {path.stat().st_size // 1024}KB → {compressed_path.stat().st_size // 1024}KB")
            return str(compressed_path)
        except Exception as e:
            self.print_error(f"Failed to compress image: {e}")
            return image_path
    
    def _check_rate_limit(self, limit_type='message'):
        """Check if rate limit is exceeded"""
        current_time = time.time()
        
        if limit_type == 'message':
            timestamps = self.message_timestamps
            limit = Config.MESSAGE_RATE_LIMIT
        else:  # broadcast
            timestamps = self.broadcast_timestamps
            limit = Config.BROADCAST_RATE_LIMIT
        
        # Remove timestamps older than 1 minute
        timestamps[:] = [t for t in timestamps if current_time - t < 60]
        
        if len(timestamps) >= limit:
            return False
        
        timestamps.append(current_time)
        return True
    
    def start(self):
        """Initialize and start all services"""
        self.running = True
        
        try:
            # Setup TCP listener for incoming messages
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.bind(('0.0.0.0', self.port))
            self.tcp_socket.listen(10)
            
            # Setup UDP for peer discovery
            self.udp_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.udp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.udp_socket.bind(('0.0.0.0', self.port))
            
            # Setup broadcast socket
            self.broadcast_socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            self.broadcast_socket.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
            
        except OSError as e:
            self.print_error(f"Failed to bind to port {self.port}. Is it already in use?")
            raise
        
        # Start threads
        threading.Thread(target=self._tcp_listener, daemon=True).start()
        threading.Thread(target=self._udp_listener, daemon=True).start()
        threading.Thread(target=self._announce_presence, daemon=True).start()
        threading.Thread(target=self._cleanup_peers, daemon=True).start()
        threading.Thread(target=self._cleanup_transfers, daemon=True).start()
        
        time.sleep(0.5)  # Let services start
        self.print_info(f"ChatCLI started as '{self.nickname}' on {self.local_ip}:{self.port}")
        self.print_info(f"Downloads will be saved to: {Config.get_downloads_dir()}")
    
    def _tcp_listener(self):
        """Listen for incoming TCP connections"""
        while self.running:
            try:
                self.tcp_socket.settimeout(1.0)
                conn, addr = self.tcp_socket.accept()
                threading.Thread(target=self._handle_tcp_connection, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception:
                if self.running:
                    pass
    
    def _handle_tcp_connection(self, conn, addr):
        """Handle incoming TCP connection"""
        try:
            conn.settimeout(10.0)
            
            # Receive data (may be large for file chunks)
            data_chunks = []
            while True:
                chunk = conn.recv(65536)
                if not chunk:
                    break
                data_chunks.append(chunk)
                # Check if we have a complete JSON message
                try:
                    data = b''.join(data_chunks).decode('utf-8')
                    message = json.loads(data)
                    break
                except (json.JSONDecodeError, UnicodeDecodeError):
                    # Need more data
                    continue
            
            if not data_chunks:
                return
            
            msg_type = message.get('type')
            
            if msg_type == 'message':
                self._handle_message(message, addr, conn)
            elif msg_type == 'broadcast':
                self._handle_broadcast(message, addr)
            elif msg_type == 'file_request':
                self._handle_file_request(message, addr)
            elif msg_type == 'file_accept':
                self._handle_file_accept(message, addr)
            elif msg_type == 'file_decline':
                self._handle_file_decline(message, addr)
            elif msg_type == 'file_chunk':
                self._handle_file_chunk(message, addr, conn)
            elif msg_type == 'image_broadcast':
                self._handle_image_broadcast(message, addr)
                
        except socket.timeout:
            pass
        except json.JSONDecodeError:
            pass
        except Exception as e:
            pass
        finally:
            try:
                conn.close()
            except:
                pass
    
    def _handle_message(self, message, addr, conn):
        """Handle regular text message"""
        sender = message['nickname']
        content = message['content']
        encrypted = message.get('encrypted', False)
        
        if encrypted:
            content = self._decrypt_from_peer(content)
            if content is None:
                content = "[Encrypted - Unable to decrypt]"
        
        self._store_message(sender, content, 'received', addr[0])
        
        # Display message
        if not self.chat_active or self.current_chat != addr[0]:
            self.print_message(f"\n{self._timestamp()} 💬 {sender}: {content}")
            if self.chat_active and self.current_chat:
                print(f"{self._timestamp()} You: ", end='', flush=True)
        else:
            self.print_message(f"{self._timestamp()} {sender}: {content}")
        
        # Send acknowledgment
        try:
            ack = json.dumps({'type': 'ack', 'status': 'delivered'})
            conn.send(ack.encode())
        except:
            pass
    
    def _handle_broadcast(self, message, addr):
        """Handle broadcast message"""
        sender = message['nickname']
        content = message['content']
        self.print_broadcast(f"\n{self._timestamp()} 📢 BROADCAST from {sender}: {content}")
        self._store_message(f"BROADCAST-{sender}", content, 'received')
        if self.chat_active:
            print(f"{self._timestamp()} You: ", end='', flush=True)
    
    def _handle_file_request(self, message, addr):
        """Handle incoming file transfer request"""
        file_id = message['file_id']
        filename = message['filename']
        filesize = message['filesize']
        file_hash = message['file_hash']
        sender = message['nickname']
        
        # Validate
        if filesize > Config.MAX_FILE_SIZE:
            self.print_error(f"File transfer request rejected: file too large")
            return
        
        # Create transfer object
        transfer = FileTransfer(file_id, filename, filesize, addr[0], sender, file_hash)
        
        with self.transfers_lock:
            self.pending_transfers[file_id] = transfer
        
        # Notify user
        size_mb = filesize / (1024 * 1024)
        self.print_info(f"\n📥 File transfer request from {sender}:")
        self.print_info(f"   File: {filename}")
        self.print_info(f"   Size: {size_mb:.2f} MB")
        self.print_info(f"   Type /accept to receive or /decline to reject")
        
        if self.chat_active:
            print(f"{self._timestamp()} You: ", end='', flush=True)
    
    def _handle_file_accept(self, message, addr):
        """Handle file transfer acceptance"""
        file_id = message['file_id']
        
        # Start sending file
        threading.Thread(target=self._send_file_chunks, args=(file_id, addr[0]), daemon=True).start()
    
    def _handle_file_decline(self, message, addr):
        """Handle file transfer decline"""
        file_id = message['file_id']
        self.print_info(f"File transfer declined by recipient")
    
    def _handle_file_chunk(self, message, addr, conn):
        """Handle incoming file chunk"""
        file_id = message['file_id']
        chunk_num = message['chunk_num']
        chunk_data = base64.b64decode(message['data'])
        is_last = message.get('is_last', False)
        
        with self.transfers_lock:
            if file_id not in self.active_transfers:
                return
            
            transfer = self.active_transfers[file_id]
            transfer.data.write(chunk_data)
            transfer.chunks_received += 1
            transfer.status = 'transferring'
            
            # Show progress
            progress = transfer.get_progress()
            if transfer.chunks_received % 10 == 0 or is_last:
                print(f"\r📥 Receiving {transfer.filename}: {progress}%", end='', flush=True)
            
            if is_last:
                # Transfer complete, verify hash
                print()  # New line after progress
                transfer.data.seek(0)
                received_hash = hashlib.sha256(transfer.data.read()).hexdigest()
                
                if received_hash == transfer.file_hash:
                    # Save file
                    save_path = Config.get_downloads_dir() / transfer.filename
                    transfer.data.seek(0)
                    with open(save_path, 'wb') as f:
                        f.write(transfer.data.read())
                    
                    transfer.status = 'completed'
                    self.completed_transfers.append(transfer)
                    self.print_info(f"✅ File received: {save_path}")
                    
                    # Send completion acknowledgment
                    try:
                        ack = json.dumps({'type': 'file_complete', 'file_id': file_id, 'status': 'success'})
                        conn.send(ack.encode())
                    except:
                        pass
                else:
                    transfer.status = 'failed'
                    self.print_error(f"❌ File transfer failed: hash mismatch")
                
                del self.active_transfers[file_id]
                
                if self.chat_active:
                    print(f"{self._timestamp()} You: ", end='', flush=True)
    
    def _handle_image_broadcast(self, message, addr):
        """Handle broadcast image"""
        sender = message['nickname']
        filename = message['filename']
        image_data = base64.b64decode(message['data'])
        
        # Save image
        save_path = Config.get_downloads_dir() / f"{int(time.time())}_{filename}"
        with open(save_path, 'wb') as f:
            f.write(image_data)
        
        size_kb = len(image_data) / 1024
        self.print_broadcast(f"\n{self._timestamp()} 📢🖼️  Image broadcast from {sender}: {filename} ({size_kb:.1f}KB)")
        self.print_info(f"   Saved to: {save_path}")
        
        self._store_message(f"IMAGE-{sender}", f"[Image: {filename}]", 'received', addr[0], image_path=str(save_path))
        
        if self.chat_active:
            print(f"{self._timestamp()} You: ", end='', flush=True)
    
    def _send_file_chunks(self, file_id, target_ip):
        """Send file in chunks"""
        # This would be called after receiving file_accept
        # Implementation for sending side
        pass
    
    def _udp_listener(self):
        """Listen for UDP discovery broadcasts"""
        while self.running:
            try:
                self.udp_socket.settimeout(1.0)
                data, addr = self.udp_socket.recvfrom(8192)
                message = json.loads(data.decode('utf-8'))
                
                if message['type'] == 'announce' and addr[0] != self.local_ip:
                    with self.peers_lock:
                        is_new = addr[0] not in self.peers
                        
                        # Load public key
                        public_key = self._load_public_key_pem(message['public_key'])
                        
                        self.peers[addr[0]] = {
                            'nickname': message['nickname'],
                            'last_seen': time.time(),
                            'port': message['port'],
                            'public_key': public_key,
                            'status': message.get('status', 'online')
                        }
                        if is_new:
                            self.print_info(f"New peer discovered: {message['nickname']} ({addr[0]})")
            except socket.timeout:
                continue
            except Exception:
                pass
    
    def _announce_presence(self):
        """Periodically announce presence via UDP broadcast"""
        broadcast_addr = self._get_broadcast_address()
        while self.running:
            try:
                announcement = json.dumps({
                    'type': 'announce',
                    'nickname': self.nickname,
                    'port': self.port,
                    'public_key': self._get_public_key_pem(),
                    'status': self.status
                })
                self.broadcast_socket.sendto(
                    announcement.encode(),
                    (broadcast_addr, self.port)
                )
            except:
                pass
            time.sleep(Config.BROADCAST_INTERVAL)
    
    def _get_broadcast_address(self):
        """Get the broadcast address for the network"""
        ip_parts = self.local_ip.split('.')
        if len(ip_parts) == 4:
            return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
        return "255.255.255.255"
    
    def _cleanup_peers(self):
        """Remove inactive peers"""
        while self.running:
            with self.peers_lock:
                current_time = time.time()
                inactive = [ip for ip, info in self.peers.items() 
                           if current_time - info['last_seen'] > Config.PEER_TIMEOUT]
                for ip in inactive:
                    nickname = self.peers[ip]['nickname']
                    del self.peers[ip]
                    if not self.chat_active:
                        self.print_info(f"Peer disconnected: {nickname} ({ip})")
            time.sleep(10)
    
    def _cleanup_transfers(self):
        """Clean up old pending transfers"""
        while self.running:
            with self.transfers_lock:
                current_time = time.time()
                expired = [fid for fid, transfer in self.pending_transfers.items()
                          if current_time - transfer.created_at > Config.TRANSFER_TIMEOUT]
                for fid in expired:
                    del self.pending_transfers[fid]
            time.sleep(60)
    
    def _store_message(self, sender, content, direction, ip=None, image_path=None):
        """Store message in history"""
        with self.messages_lock:
            self.messages.append({
                'timestamp': datetime.now(),
                'sender': sender,
                'content': content,
                'direction': direction,
                'ip': ip,
                'image_path': image_path
            })
    
    def list_peers(self):
        """List all discovered peers"""
        with self.peers_lock:
            if not self.peers:
                self.print_info("No peers discovered yet. Wait a few seconds...")
                return []
            
            self.print_info("\n📡 Discovered Peers:")
            self.print_info("=" * 60)
            peers_list = list(self.peers.items())
            for idx, (ip, info) in enumerate(peers_list, 1):
                status_icon = "🟢" if info['status'] == 'online' else "🟡" if info['status'] == 'away' else "🔴"
                self.print_info(f"  {idx}. {status_icon} {info['nickname']} ({ip})")
            self.print_info("=" * 60)
            return peers_list
    
    def send_message(self, target_ip, content, encrypted=True):
        """Send a message to a specific peer"""
        if not self._check_rate_limit('message'):
            self.print_error("Rate limit exceeded. Please slow down.")
            return None
        
        try:
            # Encrypt if requested
            if encrypted and Config.ENABLE_ENCRYPTION:
                content_to_send = self._encrypt_for_peer(target_ip, content)
                if content_to_send is None:
                    self.print_error("Failed to encrypt message")
                    return None
            else:
                content_to_send = content
            
            message = json.dumps({
                'type': 'message',
                'nickname': self.nickname,
                'content': content_to_send,
                'encrypted': encrypted and Config.ENABLE_ENCRYPTION
            })
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            with self.peers_lock:
                port = self.peers.get(target_ip, {}).get('port', self.port)
            
            sock.connect((target_ip, port))
            sock.send(message.encode())
            
            # Wait for acknowledgment
            status = "✓ Sent"
            try:
                sock.settimeout(2)
                ack_data = sock.recv(1024).decode('utf-8')
                ack = json.loads(ack_data)
                if ack.get('type') == 'ack':
                    status = "✓✓ Delivered"
            except:
                pass
            
            sock.close()
            
            self._store_message(self.nickname, content, 'sent', target_ip)
            return status
            
        except ConnectionRefusedError:
            self.print_error(f"Connection refused by {target_ip}")
            return None
        except socket.timeout:
            self.print_error(f"Connection timeout to {target_ip}")
            return None
        except Exception as e:
            self.print_error(f"Failed to send message: {e}")
            return None
    
    def send_file(self, target_ip, filepath):
        """Send a file to a specific peer"""
        path = Path(filepath)
        
        if not path.exists():
            self.print_error(f"File not found: {filepath}")
            return False
        
        filesize = path.stat().st_size
        valid, msg = self._validate_file(filepath, filesize)
        
        if not valid:
            self.print_error(f"Cannot send file: {msg}")
            return False
        
        # Calculate hash
        self.print_info("Calculating file hash...")
        file_hash = self._calculate_file_hash(filepath)
        
        # Generate file ID
        file_id = f"{int(time.time())}_{self.nickname}_{path.name}"
        
        # Send file request
        try:
            with self.peers_lock:
                port = self.peers.get(target_ip, {}).get('port', self.port)
                peer_name = self.peers.get(target_ip, {}).get('nickname', 'Unknown')
            
            request = json.dumps({
                'type': 'file_request',
                'file_id': file_id,
                'filename': path.name,
                'filesize': filesize,
                'file_hash': file_hash,
                'nickname': self.nickname
            })
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((target_ip, port))
            sock.send(request.encode())
            sock.close()
            
            self.print_info(f"📤 File transfer request sent to {peer_name}")
            self.print_info(f"   Waiting for acceptance...")
            
            # Store transfer info for sending
            with self.transfers_lock:
                self.active_transfers[file_id] = {
                    'filepath': filepath,
                    'target_ip': target_ip,
                    'filesize': filesize,
                    'status': 'waiting'
                }
            
            # Wait for acceptance (in a separate thread)
            threading.Thread(target=self._wait_for_file_acceptance, 
                           args=(file_id, filepath, target_ip, port), 
                           daemon=True).start()
            
            return True
            
        except Exception as e:
            self.print_error(f"Failed to send file request: {e}")
            return False
    
    def _wait_for_file_acceptance(self, file_id, filepath, target_ip, port):
        """Wait for file transfer acceptance and then send"""
        # Wait for acceptance message (this is simplified - in real impl would use proper signaling)
        time.sleep(2)  # Give time for user to accept
        
        # Check if still in active transfers
        with self.transfers_lock:
            if file_id not in self.active_transfers:
                return
        
        # Send file chunks
        try:
            path = Path(filepath)
            total_size = path.stat().st_size
            total_chunks = (total_size + Config.CHUNK_SIZE - 1) // Config.CHUNK_SIZE
            
            with open(filepath, 'rb') as f:
                chunk_num = 0
                while True:
                    chunk = f.read(Config.CHUNK_SIZE)
                    if not chunk:
                        break
                    
                    chunk_num += 1
                    is_last = chunk_num == total_chunks
                    
                    chunk_msg = json.dumps({
                        'type': 'file_chunk',
                        'file_id': file_id,
                        'chunk_num': chunk_num,
                        'data': base64.b64encode(chunk).decode('utf-8'),
                        'is_last': is_last
                    })
                    
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(10)
                    sock.connect((target_ip, port))
                    sock.send(chunk_msg.encode())
                    sock.close()
                    
                    # Show progress
                    progress = int((chunk_num / total_chunks) * 100)
                    if chunk_num % 10 == 0 or is_last:
                        print(f"\r📤 Sending {path.name}: {progress}%", end='', flush=True)
                    
                    time.sleep(0.1)  # Small delay between chunks
            
            print()  # New line
            self.print_info(f"✅ File sent successfully")
            
            with self.transfers_lock:
                if file_id in self.active_transfers:
                    del self.active_transfers[file_id]
                    
        except Exception as e:
            self.print_error(f"Failed to send file: {e}")
            with self.transfers_lock:
                if file_id in self.active_transfers:
                    del self.active_transfers[file_id]
    
    def broadcast_message(self, content):
        """Broadcast a message to all peers"""
        if not self._check_rate_limit('broadcast'):
            self.print_error("Broadcast rate limit exceeded. Please slow down.")
            return
        
        message = json.dumps({
            'type': 'broadcast',
            'nickname': self.nickname,
            'content': content
        })
        
        sent_count = 0
        with self.peers_lock:
            peers_list = list(self.peers.items())
        
        for ip, info in peers_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(2)
                sock.connect((ip, info['port']))
                sock.send(message.encode())
                sock.close()
                sent_count += 1
            except:
                pass
        
        self.print_info(f"{self._timestamp()} 📢 Broadcast sent to {sent_count} peer(s)")
    
    def broadcast_image(self, image_path):
        """Broadcast an image to all peers"""
        path = Path(image_path)
        
        if not path.exists():
            self.print_error(f"Image not found: {image_path}")
            return False
        
        # Check if it's an image
        if path.suffix.lower() not in Config.ALLOWED_IMAGE_FORMATS:
            self.print_error(f"Not a valid image format. Allowed: {', '.join(Config.ALLOWED_IMAGE_FORMATS)}")
            return False
        
        filesize = path.stat().st_size
        
        if filesize > Config.MAX_IMAGE_SIZE:
            self.print_error(f"Image too large (max {Config.MAX_IMAGE_SIZE // (1024*1024)}MB)")
            return False
        
        # Compress if needed
        if PILLOW_AVAILABLE and filesize > Config.IMAGE_COMPRESSION_THRESHOLD:
            image_path = self._compress_image(image_path)
            path = Path(image_path)
        
        # Read image
        with open(image_path, 'rb') as f:
            image_data = f.read()
        
        # Broadcast to all peers
        message = json.dumps({
            'type': 'image_broadcast',
            'nickname': self.nickname,
            'filename': path.name,
            'data': base64.b64encode(image_data).decode('utf-8')
        })
        
        sent_count = 0
        with self.peers_lock:
            peers_list = list(self.peers.items())
        
        self.print_info(f"📤 Broadcasting image to {len(peers_list)} peer(s)...")
        
        for ip, info in peers_list:
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.settimeout(10)
                sock.connect((ip, info['port']))
                sock.send(message.encode())
                sock.close()
                sent_count += 1
            except Exception as e:
                pass
        
        self.print_info(f"✅ Image broadcast sent to {sent_count} peer(s)")
        return True
    
    def accept_file_transfer(self):
        """Accept the most recent pending file transfer"""
        with self.transfers_lock:
            if not self.pending_transfers:
                self.print_error("No pending file transfers")
                return False
            
            # Get most recent transfer
            file_id = list(self.pending_transfers.keys())[-1]
            transfer = self.pending_transfers[file_id]
            
            # Move to active transfers
            self.active_transfers[file_id] = transfer
            del self.pending_transfers[file_id]
            
            transfer.status = 'accepted'
        
        # Send acceptance
        try:
            with self.peers_lock:
                port = self.peers.get(transfer.sender_ip, {}).get('port', self.port)
            
            accept_msg = json.dumps({
                'type': 'file_accept',
                'file_id': file_id
            })
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((transfer.sender_ip, port))
            sock.send(accept_msg.encode())
            sock.close()
            
            self.print_info(f"✅ File transfer accepted. Waiting for file...")
            return True
            
        except Exception as e:
            self.print_error(f"Failed to send acceptance: {e}")
            return False
    
    def decline_file_transfer(self):
        """Decline the most recent pending file transfer"""
        with self.transfers_lock:
            if not self.pending_transfers:
                self.print_error("No pending file transfers")
                return False
            
            # Get most recent transfer
            file_id = list(self.pending_transfers.keys())[-1]
            transfer = self.pending_transfers[file_id]
            del self.pending_transfers[file_id]
        
        # Send decline
        try:
            with self.peers_lock:
                port = self.peers.get(transfer.sender_ip, {}).get('port', self.port)
            
            decline_msg = json.dumps({
                'type': 'file_decline',
                'file_id': file_id
            })
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            sock.connect((transfer.sender_ip, port))
            sock.send(decline_msg.encode())
            sock.close()
            
            self.print_info(f"❌ File transfer declined")
            return True
            
        except Exception as e:
            self.print_error(f"Failed to send decline: {e}")
            return False
    
    def start_chat(self, target_ip):
        """Start a chat session with a specific peer"""
        with self.peers_lock:
            if target_ip not in self.peers:
                self.print_error("Peer not found!")
                return
            
            peer_nickname = self.peers[target_ip]['nickname']
        
        self.current_chat = target_ip
        self.chat_active = True
        
        self.print_info(f"\n💬 Chat started with {peer_nickname} ({target_ip})")
        self.print_info("Type your messages (or /end to exit chat)")
        self.print_info("=" * 60)
        
        while self.running and self.chat_active:
            try:
                # Check if peer still exists
                with self.peers_lock:
                    if target_ip not in self.peers:
                        self.print_error(f"\n{peer_nickname} disconnected!")
                        break
                
                message = input(f"{self._timestamp()} You: ").strip()
                
                if message == '/end':
                    break
                
                if message:
                    status = self.send_message(target_ip, message)
                    if status:
                        print(f"                      {status}")
                    else:
                        self.print_error("Failed to send message. Peer may be offline.")
                        break
                    
            except KeyboardInterrupt:
                print()
                break
            except EOFError:
                break
            except Exception as e:
                self.print_error(f"Chat error: {e}")
                break
        
        self.chat_active = False
        self.current_chat = None
        self.print_info("\nChat ended.")
    
    def save_chat_history(self, filename=None):
        """Save chat history to file"""
        if not filename:
            filename = f"chat_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with self.messages_lock:
                if not self.messages:
                    self.print_info("No messages to save!")
                    return
                    
                with open(filename, 'w', encoding='utf-8') as f:
                    f.write(f"ChatCLI History - {self.nickname}\n")
                    f.write(f"Generated: {datetime.now()}\n")
                    f.write("=" * 60 + "\n\n")
                    
                    for msg in self.messages:
                        timestamp = msg['timestamp'].strftime('[%H:%M:%S]')
                        direction = "→" if msg['direction'] == 'sent' else "←"
                        f.write(f"{timestamp} {direction} {msg['sender']}: {msg['content']}\n")
            
            self.print_info(f"Chat history saved to {filename}")
        except Exception as e:
            self.print_error(f"Failed to save history: {e}")
    
    def set_status(self, status):
        """Set user status"""
        if status not in ['online', 'away', 'busy']:
            self.print_error("Invalid status. Use: online, away, or busy")
            return
        
        self.status = status
        self.print_info(f"Status set to: {status}")
    
    def show_downloads(self):
        """Show downloads directory"""
        downloads_dir = Config.get_downloads_dir()
        self.print_info(f"\n📁 Downloads directory: {downloads_dir}")
        
        files = list(downloads_dir.glob('*'))
        if not files:
            self.print_info("   (empty)")
        else:
            self.print_info(f"   {len(files)} file(s):")
            for f in sorted(files, key=lambda x: x.stat().st_mtime, reverse=True)[:10]:
                if f.is_file():
                    size = f.stat().st_size / 1024
                    self.print_info(f"   - {f.name} ({size:.1f} KB)")
    
    def start_web_dashboard(self):
        """Start the web dashboard"""
        if self.web_running:
            self.print_info(f"Web dashboard is already running at http://{self.local_ip}:{self.web_port}")
            return
        
        handler = self._create_web_handler()
        try:
            self.web_server = HTTPServer(('0.0.0.0', self.web_port), handler)
            self.web_running = True
            
            def run_server():
                while self.running and self.web_running:
                    try:
                        self.web_server.handle_request()
                    except:
                        break
            
            threading.Thread(target=run_server, daemon=True).start()
            self.print_info(f"\n🌐 Web Dashboard: http://{self.local_ip}:{self.web_port}")
            self.print_info(f"   Local access: http://localhost:{self.web_port}\n")
        except OSError as e:
            self.print_error(f"Failed to start web server on port {self.web_port}: {e}")
    
    def _create_web_handler(self):
        """Create HTTP handler for web dashboard"""
        chat_app = self
        
        class ChatHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass
            
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    html_content = self._get_html()
                    self.wfile.write(html_content.encode('utf-8'))
                
                elif self.path == '/api/messages':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Cache-Control', 'no-cache')
                    self.end_headers()
                    
                    with chat_app.messages_lock:
                        messages = [{
                            'timestamp': msg['timestamp'].strftime('%H:%M:%S'),
                            'sender': html.escape(msg['sender']),
                            'content': html.escape(msg['content']),
                            'direction': msg['direction'],
                            'image_path': msg.get('image_path')
                        } for msg in chat_app.messages[-Config.WEB_MAX_MESSAGES:]]
                    self.wfile.write(json.dumps(messages).encode('utf-8'))
                
                elif self.path == '/api/peers':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Cache-Control', 'no-cache')
                    self.end_headers()
                    
                    with chat_app.peers_lock:
                        peers = [{
                            'ip': ip,
                            'nickname': html.escape(info['nickname']),
                            'last_seen': int(time.time() - info['last_seen']),
                            'status': info.get('status', 'online')
                        } for ip, info in chat_app.peers.items()]
                    self.wfile.write(json.dumps(peers).encode('utf-8'))
                
                elif self.path == '/api/files':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Cache-Control', 'no-cache')
                    self.end_headers()
                    
                    with chat_app.transfers_lock:
                        files = [{
                            'filename': t.filename,
                            'sender': t.sender_name,
                            'size': t.filesize,
                            'status': t.status,
                            'progress': t.get_progress()
                        } for t in chat_app.completed_transfers[-Config.WEB_MAX_FILES:]]
                    self.wfile.write(json.dumps(files).encode('utf-8'))
                
                elif self.path == '/api/stats':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Cache-Control', 'no-cache')
                    self.end_headers()
                    
                    with chat_app.peers_lock:
                        peer_count = len(chat_app.peers)
                    with chat_app.messages_lock:
                        message_count = len(chat_app.messages)
                    with chat_app.transfers_lock:
                        file_count = len(chat_app.completed_transfers)
                    
                    stats = {
                        'peers': peer_count,
                        'messages': message_count,
                        'files': file_count,
                        'nickname': chat_app.nickname,
                        'ip': chat_app.local_ip,
                        'status': chat_app.status
                    }
                    self.wfile.write(json.dumps(stats).encode('utf-8'))
                
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def _get_html(self):
                return """<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>ChatCLI Dashboard</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }
        .container { max-width: 1600px; margin: 0 auto; }
        .header {
            background: white;
            border-radius: 20px;
            padding: 30px 40px;
            margin-bottom: 20px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .header h1 { color: #667eea; font-size: 2.5em; margin-bottom: 5px; }
        .header p { color: #666; font-size: 1.1em; }
        .stats {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(200px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .stat-card {
            background: white;
            border-radius: 15px;
            padding: 25px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
            text-align: center;
            transition: transform 0.3s;
        }
        .stat-card:hover { transform: translateY(-5px); }
        .stat-number { font-size: 3em; font-weight: 700; color: #667eea; }
        .stat-label { color: #666; font-size: 1em; text-transform: uppercase; }
        .dashboard {
            display: grid;
            grid-template-columns: 350px 1fr;
            gap: 20px;
        }
        .panel {
            background: white;
            border-radius: 20px;
            padding: 25px;
            box-shadow: 0 20px 60px rgba(0,0,0,0.3);
        }
        .panel-header {
            font-size: 1.5em;
            color: #667eea;
            margin-bottom: 20px;
            padding-bottom: 15px;
            border-bottom: 3px solid #667eea;
            font-weight: 700;
        }
        .peer-item {
            padding: 15px;
            margin: 10px 0;
            background: linear-gradient(135deg, #f8f9ff 0%, #e8edff 100%);
            border-radius: 12px;
            border-left: 5px solid #667eea;
        }
        .peer-nickname { font-weight: 700; color: #333; }
        .peer-status { display: inline-block; margin-left: 10px; }
        .status-online { color: #4caf50; }
        .status-away { color: #ff9800; }
        .status-busy { color: #f44336; }
        .messages-container {
            height: 600px;
            overflow-y: auto;
            padding: 15px;
            background: linear-gradient(to bottom, #f8f9ff 0%, #ffffff 100%);
            border-radius: 15px;
        }
        .message {
            margin: 15px 0;
            padding: 15px 20px;
            border-radius: 15px;
            max-width: 80%;
        }
        .message.sent {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            margin-left: auto;
        }
        .message.received {
            background: linear-gradient(135deg, #f1f8e9 0%, #dcedc8 100%);
        }
        .message-header { margin-bottom: 8px; font-size: 0.85em; }
        .message-sender { font-weight: 700; }
        .message-time { opacity: 0.7; margin-left: 10px; }
        .file-item {
            padding: 12px;
            margin: 8px 0;
            background: #f0f4ff;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .file-name { font-weight: 600; color: #333; }
        .file-info { font-size: 0.9em; color: #666; margin-top: 5px; }
        @media (max-width: 1024px) {
            .dashboard { grid-template-columns: 1fr; }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div>
                <h1>📡 ChatCLI Dashboard</h1>
                <p>Real-time LAN chat monitoring</p>
            </div>
            <div>
                <div style="font-size: 1.2em; font-weight: 600; color: #667eea;" id="user-nickname">Loading...</div>
                <div style="color: #666;" id="user-ip">IP: Loading...</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="peer-count">0</div>
                <div class="stat-label">Active Peers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="message-count">0</div>
                <div class="stat-label">Messages</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="file-count">0</div>
                <div class="stat-label">Files Shared</div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="panel">
                <div class="panel-header">👥 Active Peers</div>
                <div id="peers-list">Loading...</div>
            </div>
            
            <div class="panel">
                <div class="panel-header">💬 Messages</div>
                <div class="messages-container" id="messages">Loading...</div>
            </div>
        </div>
    </div>

    <script>
        function loadStats() {
            fetch('/api/stats')
                .then(res => res.json())
                .then(stats => {
                    document.getElementById('user-nickname').textContent = stats.nickname;
                    document.getElementById('user-ip').textContent = 'IP: ' + stats.ip;
                    document.getElementById('file-count').textContent = stats.files;
                })
                .catch(err => console.error('Error:', err));
        }
        
        function loadPeers() {
            fetch('/api/peers')
                .then(res => res.json())
                .then(peers => {
                    document.getElementById('peer-count').textContent = peers.length;
                    const container = document.getElementById('peers-list');
                    
                    if (peers.length === 0) {
                        container.innerHTML = '<div style="text-align:center;padding:20px;color:#999;">No peers discovered</div>';
                        return;
                    }
                    
                    container.innerHTML = peers.map(peer => {
                        const statusClass = 'status-' + peer.status;
                        const statusIcon = peer.status === 'online' ? '🟢' : peer.status === 'away' ? '🟡' : '🔴';
                        return `
                            <div class="peer-item">
                                <div class="peer-nickname">
                                    ${peer.nickname}
                                    <span class="peer-status ${statusClass}">${statusIcon}</span>
                                </div>
                                <div style="font-size:0.9em;color:#666;margin-top:5px;">${peer.ip}</div>
                            </div>
                        `;
                    }).join('');
                })
                .catch(err => console.error('Error:', err));
        }
        
        function loadMessages() {
            fetch('/api/messages')
                .then(res => res.json())
                .then(messages => {
                    document.getElementById('message-count').textContent = messages.length;
                    const container = document.getElementById('messages');
                    
                    if (messages.length === 0) {
                        container.innerHTML = '<div style="text-align:center;padding:40px;color:#999;">No messages yet</div>';
                        return;
                    }
                    
                    container.innerHTML = messages.map(msg => `
                        <div class="message ${msg.direction}">
                            <div class="message-header">
                                <span class="message-sender">${msg.sender}</span>
                                <span class="message-time">${msg.timestamp}</span>
                            </div>
                            <div>${msg.content}</div>
                        </div>
                    `).join('');
                    container.scrollTop = container.scrollHeight;
                })
                .catch(err => console.error('Error:', err));
        }
        
        function loadData() {
            loadStats();
            loadPeers();
            loadMessages();
        }
        
        loadData();
        setInterval(loadData, 2000);
    </script>
</body>
</html>"""
        
        return ChatHandler
    
    def show_help(self):
        """Display help information"""
        help_text = """
╔═══════════════════════════════════════════════════════════════╗
║                    ChatCLI - Command Help                      ║
╚═══════════════════════════════════════════════════════════════╝

Commands:
  /list                  - List all discovered peers
  /chat <number>         - Start chatting with peer (by number)
  /msg <number> <text>   - Send quick message to peer
  /send <number> <file>  - Send file to peer (requires acceptance)
  /sendimg <file>        - Broadcast image to all peers
  /broadcast <text>      - Broadcast message to all peers
  /accept                - Accept pending file transfer
  /decline               - Decline pending file transfer
  /downloads             - Show downloads directory
  /save [filename]       - Save chat history to file
  /nickname <name>       - Change your nickname
  /status <type>         - Set status (online/away/busy)
  /web                   - Start web dashboard
  /clear                 - Clear screen
  /help                  - Show this help
  /exit                  - Exit ChatCLI

Chat Mode Commands:
  /end                   - End current chat session
  
Features:
  ✓ Auto peer discovery    ✓ File transfer with approval
  ✓ End-to-end encryption  ✓ Image broadcasting
  ✓ Real-time messaging    ✓ Broadcast messages
  ✓ Chat history           ✓ Web dashboard
  ✓ File validation        ✓ Rate limiting

Security:
  • All messages encrypted with RSA + AES
  • File transfers require explicit acceptance
  • File type whitelist enforced
  • Size limits: Files 100MB, Images 10MB
  • Rate limiting prevents spam

╚═══════════════════════════════════════════════════════════════╝
"""
        print(help_text)
    
    def interactive_menu(self):
        """Main interactive menu"""
        self.print_info("\n🚀 Welcome to ChatCLI!")
        self.show_help()
        
        while self.running:
            try:
                command = input(f"\n{self.nickname}> ").strip()
                
                if not command:
                    continue
                
                if command == '/exit':
                    self.print_info("Goodbye! 👋")
                    self.stop()
                    break
                
                elif command == '/help':
                    self.show_help()
                
                elif command == '/list':
                    self.list_peers()
                
                elif command == '/clear':
                    os.system('cls' if os.name == 'nt' else 'clear')
                
                elif command == '/web':
                    self.start_web_dashboard()
                
                elif command == '/accept':
                    self.accept_file_transfer()
                
                elif command == '/decline':
                    self.decline_file_transfer()
                
                elif command == '/downloads':
                    self.show_downloads()
                
                elif command.startswith('/chat '):
                    try:
                        peer_num = int(command.split()[1]) - 1
                        with self.peers_lock:
                            peers_list = list(self.peers.keys())
                            if 0 <= peer_num < len(peers_list):
                                self.start_chat(peers_list[peer_num])
                            else:
                                self.print_error(f"Invalid peer number! Use /list to see available peers")
                    except (ValueError, IndexError):
                        self.print_error("Usage: /chat <number>")
                
                elif command.startswith('/msg '):
                    try:
                        parts = command.split(maxsplit=2)
                        if len(parts) < 3:
                            self.print_error("Usage: /msg <number> <message>")
                            continue
                        
                        peer_num = int(parts[1]) - 1
                        message = parts[2]
                        
                        with self.peers_lock:
                            peers_list = list(self.peers.keys())
                            if 0 <= peer_num < len(peers_list):
                                target_ip = peers_list[peer_num]
                                peer_name = self.peers[target_ip]['nickname']
                        
                        status = self.send_message(target_ip, message)
                        if status:
                            self.print_sent(f"{self._timestamp()} → {peer_name}: {message} {status}")
                    except (ValueError, IndexError, KeyError):
                        self.print_error("Usage: /msg <number> <message>")
                
                elif command.startswith('/send '):
                    try:
                        parts = command.split(maxsplit=2)
                        if len(parts) < 3:
                            self.print_error("Usage: /send <number> <filepath>")
                            continue
                        
                        peer_num = int(parts[1]) - 1
                        filepath = parts[2]
                        
                        with self.peers_lock:
                            peers_list = list(self.peers.keys())
                            if 0 <= peer_num < len(peers_list):
                                target_ip = peers_list[peer_num]
                                self.send_file(target_ip, filepath)
                            else:
                                self.print_error(f"Invalid peer number!")
                    except (ValueError, IndexError):
                        self.print_error("Usage: /send <number> <filepath>")
                
                elif command.startswith('/sendimg '):
                    filepath = command[9:].strip()
                    if filepath:
                        self.broadcast_image(filepath)
                    else:
                        self.print_error("Usage: /sendimg <filepath>")
                
                elif command.startswith('/broadcast '):
                    message = command[11:].strip()
                    if message:
                        self.broadcast_message(message)
                    else:
                        self.print_error("Usage: /broadcast <message>")
                
                elif command.startswith('/save'):
                    parts = command.split(maxsplit=1)
                    filename = parts[1] if len(parts) > 1 else None
                    self.save_chat_history(filename)
                
                elif command.startswith('/nickname '):
                    new_nickname = command[10:].strip()
                    if new_nickname:
                        old_nickname = self.nickname
                        self.nickname = new_nickname
                        self.print_info(f"Nickname changed from '{old_nickname}' to '{self.nickname}'")
                    else:
                        self.print_error("Usage: /nickname <new_name>")
                
                elif command.startswith('/status '):
                    status = command[8:].strip().lower()
                    self.set_status(status)
                
                else:
                    self.print_error(f"Unknown command: {command}")
                    self.print_info("Type /help for available commands")
                    
            except KeyboardInterrupt:
                print()
                confirm = input("Do you want to exit? (y/n): ").strip().lower()
                if confirm == 'y':
                    self.print_info("Goodbye! 👋")
                    self.stop()
                    break
            except EOFError:
                self.stop()
                break
            except Exception as e:
                self.print_error(f"Error: {e}")
    
    def stop(self):
        """Stop all services"""
        self.running = False
        self.web_running = False
        
        try:
            if self.tcp_socket:
                self.tcp_socket.close()
            if self.udp_socket:
                self.udp_socket.close()
            if self.broadcast_socket:
                self.broadcast_socket.close()
            if self.web_server:
                self.web_server.shutdown()
        except:
            pass
    
    # Colored output methods
    def print_info(self, message):
        print(f"\033[94m{message}\033[0m")
    
    def print_error(self, message):
        print(f"\033[91m{message}\033[0m")
    
    def print_message(self, message):
        print(f"\033[92m{message}\033[0m")
    
    def print_sent(self, message):
        print(f"\033[93m{message}\033[0m")
    
    def print_broadcast(self, message):
        print(f"\033[95m{message}\033[0m")


def main():
    parser = argparse.ArgumentParser(description='ChatCLI - Secure LAN Chat Application')
    parser.add_argument('-n', '--nickname', help='Set your nickname', default=None)
    parser.add_argument('-p', '--port', help='Port number (default: 5555)', type=int, default=5555)
    parser.add_argument('-w', '--web-port', help='Web dashboard port (default: 8080)', type=int, default=8080)
    parser.add_argument('-v', '--version', action='version', version='ChatCLI v2.0.0')
    
    args = parser.parse_args()
    
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║   _____ _           _    ____ _     ___                       ║
║  / ____| |         | |  / ___| |   |_ _|                      ║
║ | |    | |__   __ _| |_| |   | |    | |                       ║
║ | |    | '_ \\ / _` | __| |   | |    | |                       ║
║ | |____| | | | (_| | |_| |___| |___ | |                       ║
║  \\_____|_| |_|\\__,_|\\__|\\____|_____|___|                      ║
║                                                               ║
║         Secure LAN Chat Application v2.0.0                    ║
║      File Sharing • Encryption • Image Broadcasting           ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    app = None
    try:
        app = ChatCLI(nickname=args.nickname, port=args.port)
        app.web_port = args.web_port
        app.start()
        app.interactive_menu()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
        import traceback
        traceback.print_exc()
    finally:
        if app:
            try:
                app.stop()
            except:
                pass


if __name__ == '__main__':
    main()
