#!/usr/bin/env python3
"""
ChatCLI Web Dashboard
Optional web interface for viewing chats
"""

from http.server import HTTPServer, BaseHTTPRequestHandler
import json
import threading
import os

class WebDashboard:
    def __init__(self, chat_app, port=8080):
        self.chat_app = chat_app
        self.port = port
        self.server = None
        self.running = False
        
    def start(self):
        """Start the web server"""
        handler = self._create_handler()
        self.server = HTTPServer(('0.0.0.0', self.port), handler)
        self.running = True
        
        thread = threading.Thread(target=self._run_server, daemon=True)
        thread.start()
        
        print(f"\n🌐 Web Dashboard started at http://{self.chat_app.local_ip}:{self.port}")
        print(f"   Access from browser: http://localhost:{self.port}\n")
    
    def _run_server(self):
        """Run the HTTP server"""
        while self.running:
            try:
                self.server.handle_request()
            except:
                break
    
    def stop(self):
        """Stop the web server"""
        self.running = False
        if self.server:
            self.server.shutdown()
    
    def _create_handler(self):
        """Create request handler with access to chat app"""
        chat_app = self.chat_app
        
        class ChatHandler(BaseHTTPRequestHandler):
            def log_message(self, format, *args):
                pass  # Suppress logs
            
            def do_GET(self):
                if self.path == '/':
                    self.send_response(200)
                    self.send_header('Content-type', 'text/html')
                    self.end_headers()
                    self.wfile.write(self._get_html().encode())
                
                elif self.path == '/api/messages':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    with chat_app.messages_lock:
                        messages = [
                            {
                                'timestamp': msg['timestamp'].strftime('%H:%M:%S'),
                                'sender': msg['sender'],
                                'content': msg['content'],
                                'direction': msg['direction']
                            }
                            for msg in chat_app.messages[-50:]  # Last 50 messages
                        ]
                    self.wfile.write(json.dumps(messages).encode())
                
                elif self.path == '/api/peers':
                    self.send_response(200)
                    self.send_header('Content-type', 'application/json')
                    self.end_headers()
                    
                    with chat_app.peers_lock:
                        peers = [
                            {
                                'ip': ip,
                                'nickname': info['nickname']
                            }
                            for ip, info in chat_app.peers.items()
                        ]
                    self.wfile.write(json.dumps(peers).encode())
                
                else:
                    self.send_response(404)
                    self.end_headers()
            
            def _get_html(self):
                return """<!DOCTYPE html>
<html>
<head>
    <title>ChatCLI Dashboard</title>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        * {
            margin: 0;
            padding: 0;
            box-sizing: border-box;
        }
        body {
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            padding: 20px;
        }
        .container {
            max-width: 1200px;
            margin: 0 auto;
        }
        .header {
            background: white;
            border-radius: 15px;
            padding: 30px;
            margin-bottom: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .header h1 {
            color: #667eea;
            font-size: 2.5em;
            margin-bottom: 10px;
        }
        .header p {
            color: #666;
            font-size: 1.1em;
        }
        .dashboard {
            display: grid;
            grid-template-columns: 300px 1fr;
            gap: 20px;
        }
        .peers-panel, .messages-panel {
            background: white;
            border-radius: 15px;
            padding: 20px;
            box-shadow: 0 10px 30px rgba(0,0,0,0.2);
        }
        .panel-header {
            font-size: 1.5em;
            color: #667eea;
            margin-bottom: 15px;
            padding-bottom: 10px;
            border-bottom: 2px solid #667eea;
        }
        .peer-item {
            padding: 12px;
            margin: 8px 0;
            background: #f8f9ff;
            border-radius: 8px;
            border-left: 4px solid #667eea;
        }
        .peer-nickname {
            font-weight: bold;
            color: #333;
        }
        .peer-ip {
            font-size: 0.9em;
            color: #666;
        }
        .messages-container {
            height: 500px;
            overflow-y: auto;
            padding: 10px;
            background: #f8f9ff;
            border-radius: 8px;
        }
        .message {
            margin: 10px 0;
            padding: 12px;
            border-radius: 8px;
            animation: slideIn 0.3s ease;
        }
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateY(10px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        .message.sent {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            margin-left: 20px;
        }
        .message.received {
            background: #f1f8e9;
            border-left: 4px solid #8bc34a;
            margin-right: 20px;
        }
        .message-header {
            display: flex;
            justify-content: space-between;
            margin-bottom: 5px;
        }
        .message-sender {
            font-weight: bold;
            color: #333;
        }
        .message-time {
            color: #999;
            font-size: 0.9em;
        }
        .message-content {
            color: #555;
        }
        .no-data {
            text-align: center;
            padding: 40px;
            color: #999;
        }
        .refresh-btn {
            background: #667eea;
            color: white;
            border: none;
            padding: 10px 20px;
            border-radius: 8px;
            cursor: pointer;
            font-size: 1em;
            margin-top: 10px;
            width: 100%;
        }
        .refresh-btn:hover {
            background: #5568d3;
        }
        @media (max-width: 768px) {
            .dashboard {
                grid-template-columns: 1fr;
            }
        }
    </style>
</head>
<body>
    <div class="container">
        <div class="header">
            <h1>📡 ChatCLI Dashboard</h1>
            <p>Real-time monitoring of your LAN chat</p>
        </div>
        
        <div class="dashboard">
            <div class="peers-panel">
                <div class="panel-header">Active Peers</div>
                <div id="peers-list"></div>
                <button class="refresh-btn" onclick="loadData()">🔄 Refresh</button>
            </div>
            
            <div class="messages-panel">
                <div class="panel-header">Recent Messages</div>
                <div class="messages-container" id="messages"></div>
            </div>
        </div>
    </div>

    <script>
        function loadPeers() {
            fetch('/api/peers')
                .then(res => res.json())
                .then(peers => {
                    const container = document.getElementById('peers-list');
                    if (peers.length === 0) {
                        container.innerHTML = '<div class="no-data">No peers discovered</div>';
                        return;
                    }
                    container.innerHTML = peers.map(peer => `
                        <div class="peer-item">
                            <div class="peer-nickname">👤 ${peer.nickname}</div>
                            <div class="peer-ip">${peer.ip}</div>
                        </div>
                    `).join('');
                })
                .catch(err => console.error('Error loading peers:', err));
        }

        function loadMessages() {
            fetch('/api/messages')
                .then(res => res.json())
                .then(messages => {
                    const container = document.getElementById('messages');
                    if (messages.length === 0) {
                        container.innerHTML = '<div class="no-data">No messages yet</div>';
                        return;
                    }
                    container.innerHTML = messages.map(msg => `
                        <div class="message ${msg.direction}">
                            <div class="message-header">
                                <span class="message-sender">${msg.sender}</span>
                                <span class="message-time">${msg.timestamp}</span>
                            </div>
                            <div class="message-content">${msg.content}</div>
                        </div>
                    `).join('');
                    container.scrollTop = container.scrollHeight;
                })
                .catch(err => console.error('Error loading messages:', err));
        }

        function loadData() {
            loadPeers();
            loadMessages();
        }

        // Auto-refresh every 3 seconds
        setInterval(loadData, 3000);
        loadData();
    </script>
</body>
</html>"""
        
        return ChatHandler


def add_web_command(chat_app):
    """Add /web command to start web dashboard"""
    original_interactive = chat_app.interactive_menu
    web_dashboard = None
    
    def enhanced_interactive():
        nonlocal web_dashboard
        # Override the interactive menu to add /web command
        while chat_app.running:
            try:
                command = input(f"\n{chat_app.nickname}> ").strip()
                
                if command == '/web':
                    if web_dashboard is None:
                        web_dashboard = WebDashboard(chat_app)
                        web_dashboard.start()
                    else:
                        chat_app.print_info("Web dashboard is already running!")
                    continue
                
                # Handle other commands normally
                # (This would integrate with the main app's command handling)
                
            except KeyboardInterrupt:
                break
    
    return enhanced_interactive