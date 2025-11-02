# chatcli/main.py
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
        
    def _get_local_ip(self):
        """Get the local IP address"""
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            ip = s.getsockname()[0]
            s.close()
            return ip
        except:
            return "127.0.0.1"
    
    def _timestamp(self):
        """Get current timestamp in [HH:MM:SS] format"""
        return datetime.now().strftime("[%H:%M:%S]")
    
    def start(self):
        """Initialize and start all services"""
        self.running = True
        
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
                    self.print_error(f"TCP listener error: {e}")
    
    def _handle_tcp_connection(self, conn, addr):
        """Handle incoming TCP connection"""
        try:
            data = conn.recv(4096).decode('utf-8')
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
                
                self._store_message(sender, content, 'received')
                
                if self.current_chat is None or self.current_chat != addr[0]:
                    self.print_message(f"{self._timestamp()} 💬 {sender}: {content}")
                else:
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
                self.print_broadcast(f"{self._timestamp()} 📢 BROADCAST from {sender}: {content}")
                self._store_message(f"BROADCAST-{sender}", content, 'received')
                
        except Exception as e:
            pass
        finally:
            conn.close()
    
    def _udp_listener(self):
        """Listen for UDP discovery broadcasts"""
        while self.running:
            try:
                self.udp_socket.settimeout(1.0)
                data, addr = self.udp_socket.recvfrom(1024)
                message = json.loads(data.decode('utf-8'))
                
                if message['type'] == 'announce' and addr[0] != self.local_ip:
                    with self.peers_lock:
                        self.peers[addr[0]] = {
                            'nickname': message['nickname'],
                            'last_seen': time.time(),
                            'port': message['port']
                        }
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
        return f"{ip_parts[0]}.{ip_parts[1]}.{ip_parts[2]}.255"
    
    def _cleanup_peers(self):
        """Remove inactive peers"""
        while self.running:
            with self.peers_lock:
                current_time = time.time()
                inactive = [ip for ip, info in self.peers.items() 
                           if current_time - info['last_seen'] > 15]
                for ip in inactive:
                    del self.peers[ip]
            time.sleep(10)
    
    def _store_message(self, sender, content, direction):
        """Store message in history"""
        with self.messages_lock:
            self.messages.append({
                'timestamp': datetime.now(),
                'sender': sender,
                'content': content,
                'direction': direction
            })
    
    def list_peers(self):
        """List all discovered peers"""
        with self.peers_lock:
            if not self.peers:
                self.print_info("No peers discovered yet. Wait a few seconds...")
                return
            
            self.print_info("\n📡 Discovered Peers:")
            self.print_info("=" * 60)
            for idx, (ip, info) in enumerate(self.peers.items(), 1):
                self.print_info(f"  {idx}. {info['nickname']} ({ip})")
            self.print_info("=" * 60)
    
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
            sock.connect((target_ip, self.port))
            sock.send(message.encode())
            
            # Wait for acknowledgment
            try:
                ack_data = sock.recv(1024).decode('utf-8')
                ack = json.loads(ack_data)
                if ack['type'] == 'ack':
                    self.message_status[msg_id] = {'status': 'delivered', 'time': time.time()}
                    status = "✓ Delivered"
                else:
                    status = "✓ Sent"
            except:
                status = "✓ Sent"
            
            sock.close()
            
            self._store_message(self.nickname, content, 'sent')
            self.print_sent(f"{self._timestamp()} You: {content} {status}")
            return True
            
        except Exception as e:
            self.print_error(f"Failed to send message: {e}")
            return False
    
    def broadcast_message(self, content):
        """Broadcast a message to all peers"""
        message = json.dumps({
            'type': 'broadcast',
            'nickname': self.nickname,
            'content': content
        })
        
        sent_count = 0
        with self.peers_lock:
            for ip in self.peers.keys():
                try:
                    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    sock.settimeout(2)
                    sock.connect((ip, self.port))
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
        self.print_info(f"\n💬 Chat started with {peer_nickname} ({target_ip})")
        self.print_info("Type your messages (or /end to exit chat)")
        self.print_info("=" * 60)
        
        while self.running and self.current_chat:
            try:
                message = input(f"{self._timestamp()} You: ")
                
                if message.strip() == '/end':
                    self.current_chat = None
                    self.print_info("Chat ended.")
                    break
                
                if message.strip():
                    self.send_message(target_ip, message)
                    
            except (KeyboardInterrupt, EOFError):
                self.current_chat = None
                break
    
    def save_chat_history(self, filename=None):
        """Save chat history to file"""
        if not filename:
            filename = f"chat_history_{datetime.now().strftime('%Y%m%d_%H%M%S')}.txt"
        
        try:
            with self.messages_lock:
                with open(filename, 'w') as f:
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
        if self.web_server:
            self.print_info("Web dashboard is already running!")
            return
        
        handler = self._create_web_handler()
        self.web_server = HTTPServer(('0.0.0.0', self.web_port), handler)
        
        def run_server():
            while self.running:
                try:
                    self.web_server.handle_request()
                except:
                    break
        
        threading.Thread(target=run_server, daemon=True).start()
        self.print_info(f"\n🌐 Web Dashboard: http://{self.local_ip}:{self.web_port}")
        self.print_info(f"   Local access: http://localhost:{self.web_port}\n")
    
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
                    html = self._get_html()
                    self.wfile.write(html.encode())
                
                elif self.path == '/api/messages':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    with chat_app.messages_lock:
                        messages = [{
                            'timestamp': msg['timestamp'].strftime('%H:%M:%S'),
                            'sender': msg['sender'],
                            'content': msg['content'],
                            'direction': msg['direction']
                        } for msg in chat_app.messages[-100:]]
                    self.wfile.write(json.dumps(messages).encode())
                
                elif self.path == '/api/peers':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    with chat_app.peers_lock:
                        peers = [{
                            'ip': ip,
                            'nickname': info['nickname']
                        } for ip, info in chat_app.peers.items()]
                    self.wfile.write(json.dumps(peers).encode())
                
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def _get_html(self):
                return """<!DOCTYPE html>
<html><head><title>ChatCLI Dashboard</title><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1.0"><style>*{margin:0;padding:0;box-sizing:border-box}body{font-family:'Segoe UI',Tahoma,Geneva,Verdana,sans-serif;background:linear-gradient(135deg,#667eea 0%,#764ba2 100%);min-height:100vh;padding:20px}.container{max-width:1400px;margin:0 auto}.header{background:white;border-radius:15px;padding:30px;margin-bottom:20px;box-shadow:0 10px 30px rgba(0,0,0,.2)}.header h1{color:#667eea;font-size:2.5em;margin-bottom:10px}.header p{color:#666;font-size:1.1em}.dashboard{display:grid;grid-template-columns:300px 1fr;gap:20px}.peers-panel,.messages-panel{background:white;border-radius:15px;padding:20px;box-shadow:0 10px 30px rgba(0,0,0,.2)}.panel-header{font-size:1.5em;color:#667eea;margin-bottom:15px;padding-bottom:10px;border-bottom:2px solid #667eea}.peer-item{padding:12px;margin:8px 0;background:#f8f9ff;border-radius:8px;border-left:4px solid #667eea}.peer-nickname{font-weight:700;color:#333}.peer-ip{font-size:.9em;color:#666}.messages-container{height:600px;overflow-y:auto;padding:10px;background:#f8f9ff;border-radius:8px}.message{margin:10px 0;padding:12px;border-radius:8px;animation:slideIn .3s ease}@keyframes slideIn{from{opacity:0;transform:translateY(10px)}to{opacity:1;transform:translateY(0)}}.message.sent{background:#e3f2fd;border-left:4px solid #2196f3;margin-left:20px}.message.received{background:#f1f8e9;border-left:4px solid #8bc34a;margin-right:20px}.message-header{display:flex;justify-content:space-between;margin-bottom:5px}.message-sender{font-weight:700;color:#333}.message-time{color:#999;font-size:.9em}.message-content{color:#555}.no-data{text-align:center;padding:40px;color:#999}.refresh-btn{background:#667eea;color:#fff;border:none;padding:10px 20px;border-radius:8px;cursor:pointer;font-size:1em;margin-top:10px;width:100%}.refresh-btn:hover{background:#5568d3}.stats{display:grid;grid-template-columns:repeat(3,1fr);gap:15px;margin-bottom:20px}.stat-card{background:white;border-radius:10px;padding:20px;box-shadow:0 5px 15px rgba(0,0,0,.1);text-align:center}.stat-number{font-size:2em;font-weight:700;color:#667eea;margin-bottom:5px}.stat-label{color:#666;font-size:.9em}@media (max-width:768px){.dashboard{grid-template-columns:1fr}.stats{grid-template-columns:1fr}}</style></head><body><div class="container"><div class="header"><h1>📡 ChatCLI Dashboard</h1><p>Real-time monitoring of your LAN chat network</p></div><div class="stats"><div class="stat-card"><div class="stat-number" id="peer-count">0</div><div class="stat-label">Active Peers</div></div><div class="stat-card"><div class="stat-number" id="message-count">0</div><div class="stat-label">Messages</div></div><div class="stat-card"><div class="stat-number" id="status">🟢</div><div class="stat-label">Status</div></div></div><div class="dashboard"><div class="peers-panel"><div class="panel-header">Active Peers</div><div id="peers-list"></div><button class="refresh-btn" onclick="loadData()">🔄 Refresh</button></div><div class="messages-panel"><div class="panel-header">Recent Messages</div><div class="messages-container" id="messages"></div></div></div></div><script>function loadPeers(){fetch('/api/peers').then(r=>r.json()).then(peers=>{const c=document.getElementById('peers-list');document.getElementById('peer-count').textContent=peers.length;if(peers.length===0){c.innerHTML='<div class="no-data">No peers discovered</div>';return}c.innerHTML=peers.map(p=>`<div class="peer-item"><div class="peer-nickname">👤 ${p.nickname}</div><div class="peer-ip">${p.ip}</div></div>`).join('')}).catch(e=>console.error('Error:',e))}function loadMessages(){fetch('/api/messages').then(r=>r.json()).then(msgs=>{const c=document.getElementById('messages');document.getElementById('message-count').textContent=msgs.length;if(msgs.length===0){c.innerHTML='<div class="no-data">No messages yet</div>';return}c.innerHTML=msgs.map(m=>`<div class="message ${m.direction}"><div class="message-header"><span class="message-sender">${m.sender}</span><span class="message-time">${m.timestamp}</span></div><div class="message-content">${m.content}</div></div>`).join('');c.scrollTop=c.scrollHeight}).catch(e=>console.error('Error:',e))}function loadData(){loadPeers();loadMessages()}setInterval(loadData,2000);loadData()</script></body></html>"""
        
        return ChatHandler
    
    def show_help(self):
        """Display help information"""
        help_text = """
╔═══════════════════════════════════════════════════════════════╗
║                    ChatCLI - Command Help                      ║
╚═══════════════════════════════════════════════════════════════╝

Commands:
  /list                  - List all discovered peers
  /chat <number>         - Start chatting with peer
  /msg <number> <text>   - Send quick message
  /broadcast <text>      - Broadcast to all peers
  /save [filename]       - Save chat history
  /nickname <name>       - Change your nickname
  /web                   - Start web dashboard
  /help                  - Show this help
  /exit                  - Exit ChatCLI

Chat Mode:
  /end                   - End current chat

Features:
  ✓ Auto discovery  ✓ Delivery status  ✓ Timestamps
  ✓ Multi-user      ✓ Encryption ready ✓ Broadcasts
  ✓ Chat history    ✓ Web dashboard    ✓ Cross-platform

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
                
                elif command == '/web':
                    self.start_web_dashboard()
                
                elif command.startswith('/chat '):
                    try:
                        peer_num = int(command.split()[1]) - 1
                        with self.peers_lock:
                            peers_list = list(self.peers.keys())
                            if 0 <= peer_num < len(peers_list):
                                self.start_chat(peers_list[peer_num])
                            else:
                                self.print_error("Invalid peer number!")
                    except (ValueError, IndexError):
                        self.print_error("Usage: /chat <number>")
                
                elif command.startswith('/msg '):
                    try:
                        parts = command.split(maxsplit=2)
                        peer_num = int(parts[1]) - 1
                        message = parts[2]
                        with self.peers_lock:
                            peers_list = list(self.peers.keys())
                            if 0 <= peer_num < len(peers_list):
                                self.send_message(peers_list[peer_num], message)
                            else:
                                self.print_error("Invalid peer number!")
                    except (ValueError, IndexError):
                        self.print_error("Usage: /msg <number> <message>")
                
                elif command.startswith('/broadcast '):
                    message = command[11:]
                    self.broadcast_message(message)
                
                elif command.startswith('/save'):
                    parts = command.split(maxsplit=1)
                    filename = parts[1] if len(parts) > 1 else None
                    self.save_chat_history(filename)
                
                elif command.startswith('/nickname '):
                    new_nickname = command[10:].strip()
                    if new_nickname:
                        self.nickname = new_nickname
                        self.print_info(f"Nickname changed to: {self.nickname}")
                
                else:
                    self.print_error(f"Unknown command: {command}")
                    self.print_info("Type /help for available commands")
                    
            except KeyboardInterrupt:
                print()
                self.print_info("Press Ctrl+C again or type /exit to quit")
            except EOFError:
                break
    
    def stop(self):
        """Stop all services"""
        self.running = False
        
        if self.tcp_socket:
            self.tcp_socket.close()
        if self.udp_socket:
            self.udp_socket.close()
        if self.broadcast_socket:
            self.broadcast_socket.close()
        if self.web_server:
            self.web_server.shutdown()
    
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
║                                                                ║
║              LAN Chat Application v1.0.0                       ║
║           Cross-platform • Secure • Easy to use                ║
╚═══════════════════════════════════════════════════════════════╝
"""
    print(banner)
    
    try:
        app = ChatCLI(nickname=args.nickname, port=args.port)
        app.start()
        app.interactive_menu()
    except KeyboardInterrupt:
        print("\n\nShutting down...")
    except Exception as e:
        print(f"Error: {e}")
    finally:
        try:
            app.stop()
        except:
            pass


if __name__ == '__main__':
    main()