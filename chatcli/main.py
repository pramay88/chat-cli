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
from datetime import datetime
from cryptography.fernet import Fernet
import argparse
from http.server import HTTPServer, BaseHTTPRequestHandler
import html

class ChatCLI:
    def __init__(self, nickname=None, port=5555):
        self.port = port
        self.nickname = nickname or f"User_{os.getpid()}"
        self.running = False
        self.peers = {}  # {ip: {nickname, last_seen, port}}
        self.messages = []  # Store all messages
        self.current_chat = None  # Current chat partner
        self.encryption_key = Fernet.generate_key()
        self.cipher = Fernet(self.encryption_key)
        
        # Sockets
        self.tcp_socket = None
        self.udp_socket = None
        self.broadcast_socket = None
        
        # Locks
        self.peers_lock = threading.Lock()
        self.messages_lock = threading.Lock()
        
        # Get local IP
        self.local_ip = self._get_local_ip()
        
        # Message status tracking
        self.message_status = {}  # {msg_id: {status, timestamp}}
        
        # Web dashboard
        self.web_server = None
        self.web_port = 8080
        self.web_running = False
        
        # Input lock for chat mode
        self.input_lock = threading.Lock()
        self.chat_active = False
        
    def _get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.settimeout(1)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except Exception as e:
            return "127.0.0.1"
    
    def _timestamp(self):
        """Get current timestamp in [HH:MM:SS] format"""
        return datetime.now().strftime("[%H:%M:%S]")
    
    def start(self):
        """Initialize and start all services"""
        self.running = True
        
        try:
            # Setup TCP listener for incoming messages
            self.tcp_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.tcp_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self.tcp_socket.bind(('0.0.0.0', self.port))
            self.tcp_socket.listen(5)
            
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
        
        time.sleep(0.5)  # Let services start
        self.print_info(f"ChatCLI started as '{self.nickname}' on {self.local_ip}:{self.port}")
        
    def _tcp_listener(self):
        """Listen for incoming TCP connections"""
        while self.running:
            try:
                self.tcp_socket.settimeout(1.0)
                conn, addr = self.tcp_socket.accept()
                threading.Thread(target=self._handle_tcp_connection, args=(conn, addr), daemon=True).start()
            except socket.timeout:
                continue
            except Exception as e:
                if self.running:
                    pass  # Suppress errors during shutdown
    
    def _handle_tcp_connection(self, conn, addr):
        """Handle incoming TCP connection"""
        try:
            conn.settimeout(5.0)
            data = conn.recv(8192).decode('utf-8')
            if not data:
                return
                
            message = json.loads(data)
            
            if message['type'] == 'message':
                sender = message['nickname']
                content = message['content']
                encrypted = message.get('encrypted', False)
                msg_id = message.get('msg_id', '')
                
                if encrypted:
                    try:
                        content = self.cipher.decrypt(content.encode()).decode()
                    except:
                        content = "[Encrypted - Unable to decrypt]"
                
                self._store_message(sender, content, 'received', addr[0])
                
                # Only print if not in active chat with this peer or in chat mode
                if not self.chat_active or self.current_chat != addr[0]:
                    self.print_message(f"\n{self._timestamp()} 💬 {sender}: {content}")
                    if self.chat_active and self.current_chat:
                        # Reprint prompt
                        print(f"{self._timestamp()} You: ", end='', flush=True)
                else:
                    # In chat with this peer, show message
                    self.print_message(f"{self._timestamp()} {sender}: {content}")
                
                # Send delivery confirmation
                ack = json.dumps({
                    'type': 'ack',
                    'msg_id': msg_id,
                    'status': 'delivered'
                })
                conn.send(ack.encode())
                
            elif message['type'] == 'ack':
                msg_id = message.get('msg_id')
                if msg_id in self.message_status:
                    self.message_status[msg_id]['status'] = 'delivered'
                    
            elif message['type'] == 'broadcast':
                sender = message['nickname']
                content = message['content']
                self.print_broadcast(f"\n{self._timestamp()} 📢 BROADCAST from {sender}: {content}")
                self._store_message(f"BROADCAST-{sender}", content, 'received')
                if self.chat_active:
                    print(f"{self._timestamp()} You: ", end='', flush=True)
                
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
    
    def _udp_listener(self):
        """Listen for UDP discovery broadcasts"""
        while self.running:
            try:
                self.udp_socket.settimeout(1.0)
                data, addr = self.udp_socket.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                
                if message['type'] == 'announce' and addr[0] != self.local_ip:
                    with self.peers_lock:
                        is_new = addr[0] not in self.peers
                        self.peers[addr[0]] = {
                            'nickname': message['nickname'],
                            'last_seen': time.time(),
                            'port': message['port']
                        }
                        if is_new:
                            self.print_info(f"New peer discovered: {message['nickname']} ({addr[0]})")
            except socket.timeout:
                continue
            except:
                pass
    
    def _announce_presence(self):
        """Periodically announce presence via UDP broadcast"""
        broadcast_addr = self._get_broadcast_address()
        while self.running:
            try:
                announcement = json.dumps({
                    'type': 'announce',
                    'nickname': self.nickname,
                    'port': self.port
                })
                self.broadcast_socket.sendto(
                    announcement.encode(),
                    (broadcast_addr, self.port)
                )
            except:
                pass
            time.sleep(5)
    
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
                           if current_time - info['last_seen'] > 15]
                for ip in inactive:
                    nickname = self.peers[ip]['nickname']
                    del self.peers[ip]
                    if not self.chat_active:
                        self.print_info(f"Peer disconnected: {nickname} ({ip})")
            time.sleep(10)
    
    def _store_message(self, sender, content, direction, ip=None):
        """Store message in history"""
        with self.messages_lock:
            self.messages.append({
                'timestamp': datetime.now(),
                'sender': sender,
                'content': content,
                'direction': direction,
                'ip': ip
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
                self.print_info(f"  {idx}. {info['nickname']} ({ip})")
            self.print_info("=" * 60)
            return peers_list
    
    def send_message(self, target_ip, content, encrypted=False):
        """Send a message to a specific peer"""
        try:
            msg_id = f"{time.time()}_{self.nickname}"
            
            if encrypted:
                content_to_send = self.cipher.encrypt(content.encode()).decode()
            else:
                content_to_send = content
            
            message = json.dumps({
                'type': 'message',
                'nickname': self.nickname,
                'content': content_to_send,
                'encrypted': encrypted,
                'msg_id': msg_id
            })
            
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(5)
            
            # Get port from peers or use default
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
                    self.message_status[msg_id] = {'status': 'delivered', 'time': time.time()}
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
    
    def broadcast_message(self, content):
        """Broadcast a message to all peers"""
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
                            'direction': msg['direction']
                        } for msg in chat_app.messages[-100:]]
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
                            'last_seen': int(time.time() - info['last_seen'])
                        } for ip, info in chat_app.peers.items()]
                    self.wfile.write(json.dumps(peers).encode('utf-8'))
                
                elif self.path == '/api/stats':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.send_header('Cache-Control', 'no-cache')
                    self.end_headers()
                    
                    with chat_app.peers_lock:
                        peer_count = len(chat_app.peers)
                    with chat_app.messages_lock:
                        message_count = len(chat_app.messages)
                    
                    stats = {
                        'peers': peer_count,
                        'messages': message_count,
                        'nickname': chat_app.nickname,
                        'ip': chat_app.local_ip,
                        'uptime': int(time.time())
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
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, Oxygen, Ubuntu, Cantarell, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
            color: #333;
        }
        .container {
            max-width: 1600px;
            margin: 0 auto;
        }
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
        .header-left h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 5px;
            font-weight: 700;
        }
        .header-left p {
            color: #666;
            font-size: 1.1em;
        }
        .header-right {
            text-align: right;
        }
        .header-info {
            color: #666;
            font-size: 0.9em;
            margin-top: 5px;
        }
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
            transition: transform 0.3s, box-shadow 0.3s;
        }
        .stat-card:hover {
            transform: translateY(-5px);
            box-shadow: 0 15px 40px rgba(0,0,0,0.3);
        }
        .stat-number {
            font-size: 3em;
            font-weight: 700;
            color: #667eea;
            margin-bottom: 10px;
        }
        .stat-label {
            color: #666;
            font-size: 1em;
            font-weight: 500;
            text-transform: uppercase;
            letter-spacing: 1px;
        }
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
            display: flex;
            justify-content: space-between;
            align-items: center;
        }
        .panel-header .icon {
            font-size: 1.2em;
        }
        .peers-list {
            max-height: 500px;
            overflow-y: auto;
        }
        .peer-item {
            padding: 15px;
            margin: 10px 0;
            background: linear-gradient(135deg, #f8f9ff 0%, #e8edff 100%);
            border-radius: 12px;
            border-left: 5px solid #667eea;
            transition: all 0.3s;
            cursor: pointer;
        }
        .peer-item:hover {
            transform: translateX(5px);
            box-shadow: 0 5px 15px rgba(102, 126, 234, 0.3);
        }
        .peer-header {
            display: flex;
            justify-content: space-between;
            align-items: center;
            margin-bottom: 5px;
        }
        .peer-nickname {
            font-weight: 700;
            color: #333;
            font-size: 1.1em;
        }
        .peer-status {
            background: #4caf50;
            color: white;
            padding: 3px 10px;
            border-radius: 12px;
            font-size: 0.75em;
            font-weight: 600;
        }
        .peer-ip {
            font-size: 0.9em;
            color: #666;
            font-family: 'Courier New', monospace;
        }
        .messages-container {
            height: 600px;
            overflow-y: auto;
            padding: 15px;
            background: linear-gradient(to bottom, #f8f9ff 0%, #ffffff 100%);
            border-radius: 15px;
            scroll-behavior: smooth;
        }
        .message {
            margin: 15px 0;
            padding: 15px 20px;
            border-radius: 15px;
            animation: slideIn 0.4s cubic-bezier(0.68, -0.55, 0.265, 1.55);
            max-width: 80%;
            word-wrap: break-word;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(20px) scale(0.95);
            }
            to {
                opacity: 1;
                transform: translateY(0) scale(1);
            }
        }
        .message.sent {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border-bottom-right-radius: 5px;
            margin-left: auto;
            text-align: right;
        }
        .message.received {
            background: linear-gradient(135deg, #f1f8e9 0%, #dcedc8 100%);
            border-bottom-left-radius: 5px;
            margin-right: auto;
        }
        .message-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 8px;
            font-size: 0.85em;
        }
        .message.sent .message-header {
            flex-direction: row-reverse;
        }
        .message-sender {
            font-weight: 700;
        }
        .message.sent .message-sender {
            color: rgba(255,255,255,0.9);
        }
        .message.received .message-sender {
            color: #2e7d32;
        }
        .message-time {
            opacity: 0.7;
            font-size: 0.95em;
        }
        .message-content {
            line-height: 1.5;
        }
        .message.sent .message-content {
            color: white;
        }
        .message.received .message-content {
            color: #333;
        }
        .no-data {
            text-align: center;
            padding: 60px 20px;
            color: #999;
            font-size: 1.2em;
        }
        .no-data-icon {
            font-size: 4em;
            margin-bottom: 15px;
            opacity: 0.3;
        }
        .refresh-btn {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            color: white;
            border: none;
            padding: 12px 25px;
            border-radius: 10px;
            cursor: pointer;
            font-size: 1em;
            font-weight: 600;
            margin-top: 15px;
            width: 100%;
            transition: all 0.3s;
        }
        .refresh-btn:hover {
            transform: translateY(-2px);
            box-shadow: 0 10px 20px rgba(102, 126, 234, 0.4);
        }
        .refresh-btn:active {
            transform: translateY(0);
        }
        ::-webkit-scrollbar {
            width: 10px;
        }
        ::-webkit-scrollbar-track {
            background: #f1f1f1;
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb {
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            border-radius: 10px;
        }
        ::-webkit-scrollbar-thumb:hover {
            background: #5568d3;
        }
        @media (max-width: 1024px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
            .header {
                flex-direction: column;
                text-align: center;
            }
            .header-right {
                margin-top: 15px;
                text-align: center;
            }
        }
        @media (max-width: 768px) {
            .stats {
                grid-template-columns: 1fr;
            }
            .message {
                max-width: 95%;
            }
        }
        .loading {
            text-align: center;
            padding: 20px;
            color: #667eea;
            font-weight: 600;
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <div class="header-left">
                <h1>📡 ChatCLI Dashboard</h1>
                <p>Real-time monitoring of your LAN chat network</p>
            </div>
            <div class="header-right">
                <div style="font-size: 1.2em; font-weight: 600; color: #667eea;" id="user-nickname">Loading...</div>
                <div class="header-info" id="user-ip">IP: Loading...</div>
            </div>
        </div>
        
        <div class="stats">
            <div class="stat-card">
                <div class="stat-number" id="peer-count">0</div>
                <div class="stat-label">Active Peers</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="message-count">0</div>
                <div class="stat-label">Total Messages</div>
            </div>
            <div class="stat-card">
                <div class="stat-number" id="status">🟢</div>
                <div class="stat-label">System Status</div>
            </div>
        </div>
        
        <div class="dashboard">
            <div class="panel peers-panel">
                <div class="panel-header">
                    <span>👥 Active Peers</span>
                    <span class="icon">📡</span>
                </div>
                <div class="peers-list" id="peers-list">
                    <div class="loading">Discovering peers...</div>
                </div>
                <button class="refresh-btn" onclick="loadData()">🔄 Refresh Data</button>
            </div>
            
            <div class="panel messages-panel">
                <div class="panel-header">
                    <span>💬 Message History</span>
                    <span class="icon">📨</span>
                </div>
                <div class="messages-container" id="messages">
                    <div class="loading">Loading messages...</div>
                </div>
            </div>
        </div>
    </div>

    <script>
        let lastMessageCount = 0;
        let lastPeerCount = 0;
        
        function loadStats() {
            fetch('/api/stats')
                .then(res => res.json())
                .then(stats => {
                    document.getElementById('user-nickname').textContent = stats.nickname;
                    document.getElementById('user-ip').textContent = 'IP: ' + stats.ip;
                })
                .catch(err => console.error('Error loading stats:', err));
        }
        
        function loadPeers() {
            fetch('/api/peers')
                .then(res => res.json())
                .then(peers => {
                    const container = document.getElementById('peers-list');
                    const count = document.getElementById('peer-count');
                    count.textContent = peers.length;
                    
                    if (peers.length === 0) {
                        container.innerHTML = '<div class="no-data"><div class="no-data-icon">👥</div><div>No peers discovered yet</div><div style="font-size: 0.9em; margin-top: 10px;">Peers will appear automatically</div></div>';
                        return;
                    }
                    
                    container.innerHTML = peers.map(peer => {
                        const lastSeen = peer.last_seen < 5 ? 'Just now' : `${peer.last_seen}s ago`;
                        return `
                            <div class="peer-item">
                                <div class="peer-header">
                                    <div class="peer-nickname">👤 ${peer.nickname}</div>
                                    <div class="peer-status">● ONLINE</div>
                                </div>
                                <div class="peer-ip">${peer.ip}</div>
                                <div style="font-size: 0.8em; color: #999; margin-top: 5px;">Last seen: ${lastSeen}</div>
                            </div>
                        `;
                    }).join('');
                    
                    if (peers.length !== lastPeerCount) {
                        lastPeerCount = peers.length;
                    }
                })
                .catch(err => {
                    console.error('Error loading peers:', err);
                    document.getElementById('peers-list').innerHTML = '<div class="no-data">Failed to load peers</div>';
                });
        }
        
        function loadMessages() {
            fetch('/api/messages')
                .then(res => res.json())
                .then(messages => {
                    const container = document.getElementById('messages');
                    const count = document.getElementById('message-count');
                    count.textContent = messages.length;
                    
                    if (messages.length === 0) {
                        container.innerHTML = '<div class="no-data"><div class="no-data-icon">💬</div><div>No messages yet</div><div style="font-size: 0.9em; margin-top: 10px;">Start chatting to see messages here</div></div>';
                        return;
                    }
                    
                    const shouldScroll = container.scrollHeight - container.scrollTop <= container.clientHeight + 100;
                    
                    container.innerHTML = messages.map(msg => `
                        <div class="message ${msg.direction}">
                            <div class="message-header">
                                <span class="message-sender">${msg.sender}</span>
                                <span class="message-time">${msg.timestamp}</span>
                            </div>
                            <div class="message-content">${msg.content}</div>
                        </div>
                    `).join('');
                    
                    if (shouldScroll || messages.length !== lastMessageCount) {
                        container.scrollTop = container.scrollHeight;
                        lastMessageCount = messages.length;
                    }
                })
                .catch(err => {
                    console.error('Error loading messages:', err);
                    document.getElementById('messages').innerHTML = '<div class="no-data">Failed to load messages</div>';
                });
        }
        
        function loadData() {
            loadStats();
            loadPeers();
            loadMessages();
        }
        
        // Initial load
        loadData();
        
        // Auto-refresh every 2 seconds
        setInterval(loadData, 2000);
        
        // Update status indicator
        setInterval(() => {
            const status = document.getElementById('status');
            status.textContent = '🟢';
        }, 1000);
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
  /broadcast <text>      - Broadcast message to all peers
  /save [filename]       - Save chat history to file
  /nickname <name>       - Change your nickname
  /web                   - Start web dashboard
  /clear                 - Clear screen
  /help                  - Show this help
  /exit                  - Exit ChatCLI

Chat Mode Commands:
  /end                   - End current chat session
  
Features:
  ✓ Auto peer discovery    ✓ Delivery confirmation
  ✓ Real-time messaging    ✓ Broadcast messages
  ✓ Chat history           ✓ Web dashboard
  ✓ Cross-platform         ✓ Timestamps

Tips:
  • Use /list to see available peers before chatting
  • Peer numbers may change as peers connect/disconnect
  • Messages are stored in memory and can be saved with /save
  • Web dashboard updates automatically every 2 seconds

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
                
                elif command.startswith('/chat '):
                    try:
                        parts = command.split()
                        if len(parts) < 2:
                            self.print_error("Usage: /chat <number>")
                            continue
                            
                        peer_num = int(parts[1]) - 1
                        with self.peers_lock:
                            peers_list = list(self.peers.keys())
                            if 0 <= peer_num < len(peers_list):
                                self.start_chat(peers_list[peer_num])
                            else:
                                self.print_error(f"Invalid peer number! Use /list to see available peers (1-{len(peers_list)})")
                    except ValueError:
                        self.print_error("Usage: /chat <number> (number must be an integer)")
                    except IndexError:
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
                        else:
                            self.print_error(f"Failed to send message to {peer_name}")
                    except ValueError:
                        self.print_error("Usage: /msg <number> <message> (number must be an integer)")
                    except IndexError:
                        self.print_error("Usage: /msg <number> <message>")
                    except KeyError:
                        self.print_error("Peer not found. Use /list to see available peers")
                
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
    parser = argparse.ArgumentParser(description='ChatCLI - LAN Chat Application')
    parser.add_argument('-n', '--nickname', help='Set your nickname', default=None)
    parser.add_argument('-p', '--port', help='Port number (default: 5555)', type=int, default=5555)
    parser.add_argument('-w', '--web-port', help='Web dashboard port (default: 8080)', type=int, default=8080)
    parser.add_argument('-v', '--version', action='version', version='ChatCLI v1.0.0')
    
    args = parser.parse_args()
    
    banner = """
╔═══════════════════════════════════════════════════════════════╗
║   _____ _           _    ____ _     ___                       ║
║  / ____| |         | |  / ___| |   |_ _|                      ║
║ | |    | |__   __ _| |_| |   | |    | |                       ║
║ | |    | '_ \ / _` | __| |   | |    | |                       ║
║ | |____| | | | (_| | |_| |___| |___ | |                       ║
║  \_____|_| |_|\__,_|\__|\____|_____|___|                      ║
║                                                               ║
║              LAN Chat Application v1.0.0                      ║
║           Cross-platform • Secure • Easy to use               ║
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
