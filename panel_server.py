"""
Главный сервер панели управления
- Прокси-сервер (HTTP/SOCKS5) на портах 8080/8090
- API для нод на порту 3333
- REST API для клиентов на порту 8000
"""
import socket
import threading
import select
import base64
import hashlib
import time
import struct
import logging
from flask import Flask, request, jsonify
import jwt
from functools import wraps
import database as db

# --- КОНФИГУРАЦИЯ ---
LOCAL_HOST = '0.0.0.0'
HTTP_PORT = 8080
SOCKS5_PORT = 8090
API_PORT = 8000
NODE_API_PORT = 3333  # Порт для подключения нод
JWT_SECRET = 'CHANGE_THIS_SECRET_KEY_IN_PRODUCTION!!!'
TOKEN_LIFETIME = 3600 * 24

# Инициализация Flask приложений
api_app = Flask('proxy_panel_api')
node_api_app = Flask('proxy_panel_node_api')

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# =================================================================
# ПРОКСИ-СЕРВЕР (HTTP и SOCKS5)
# =================================================================

class ProxyHandler(threading.Thread):
    """Базовый класс для обработки прокси-запросов."""
    
    def __init__(self, client_sock, client_addr):
        super().__init__()
        self.client_sock = client_sock
        self.client_addr = client_addr
        self.client_ip = client_addr[0]
        self.username = None
        self.node = None
        self.destination = "N/A"
        self.start_time = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.daemon = True
    
    def authenticate(self, username, password):
        """Аутентифицирует пользователя и получает назначенную ноду."""
        user = db.authenticate_user(username, password)
        if not user:
            return False, "Invalid credentials"
        
        # Получаем назначенные ноды
        nodes = db.get_user_nodes(username)
        if not nodes:
            return False, "No nodes assigned"
        
        # Фильтруем только активные ноды
        active_nodes = [n for n in nodes if n.get('is_active', 0) == 1]
        if not active_nodes:
            return False, "No active nodes assigned"
        
        # Если у пользователя только одна нода - используем её
        if len(active_nodes) == 1:
            best_node = active_nodes[0]
        else:
            # Если несколько нод - выбираем с наименьшей нагрузкой (балансировка)
            best_node = min(active_nodes, key=lambda n: (
                n.get('current_connections', 0) / max(n.get('max_connections', 100), 1),
                n.get('current_connections', 0)
            ))
        
        # Проверяем лимит устройств
        conn = db.get_db_connection()
        with db.db_lock:
            cursor = conn.execute(
                "SELECT COUNT(DISTINCT client_ip) as count FROM active_sessions WHERE username = ?",
                (username,)
            )
            session_count = cursor.fetchone()['count']
        
        if session_count >= user['device_limit']:
            # Проверяем, есть ли уже сессия с этого IP
            cursor = conn.execute(
                "SELECT 1 FROM active_sessions WHERE username = ? AND client_ip = ?",
                (username, self.client_ip)
            )
            if not cursor.fetchone():
                conn.close()
                return False, f"Device limit exceeded ({session_count}/{user['device_limit']})"
        
        conn.close()
        
        self.username = username
        self.node = best_node
        return True, "OK"
    
    def register_session(self):
        """Регистрирует активную сессию."""
        conn = db.get_db_connection()
        with db.db_lock:
            conn.execute(
                "INSERT OR REPLACE INTO active_sessions (username, client_ip, node_id) VALUES (?, ?, ?)",
                (self.username, self.client_ip, self.node['node_id'])
            )
            conn.commit()
        conn.close()
    
    def unregister_session(self):
        """Удаляет активную сессию."""
        conn = db.get_db_connection()
        with db.db_lock:
            conn.execute(
                "DELETE FROM active_sessions WHERE username = ? AND client_ip = ?",
                (self.username, self.client_ip)
            )
            conn.commit()
        conn.close()
    
    def connect_to_node(self, target_host, target_port):
        """Подключается к назначенной ноде и передает запрос на целевой сервер."""
        max_retries = 2
        retry_delay = 0.1
        
        for attempt in range(max_retries):
            node_sock = None
            try:
                # Подключаемся к ноде с retry логикой
                node_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                node_sock.settimeout(15)  # Увеличен таймаут до 15 секунд
                
                # Устанавливаем TCP_NODELAY для уменьшения задержек
                node_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                node_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
                
                # Попытка подключения
                node_sock.connect((self.node['host'], self.node['port']))
                
                # Если нода поддерживает SOCKS5, отправляем запрос на целевой сервер
                if self.node['node_type'] == 'socks5':
                    # SOCKS5 handshake
                    node_sock.sendall(b'\x05\x01\x00')  # Версия, 1 метод (No auth)
                    node_sock.settimeout(5)  # Таймаут для handshake
                    response = node_sock.recv(2)
                    
                    if len(response) != 2 or response[0] != 0x05:
                        node_sock.close()
                        node_sock = None
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay * (attempt + 1))
                            continue
                        logger.error(f"Нода {self.node['node_id']}: неверный ответ SOCKS5 handshake")
                        return None
                    
                    # CONNECT команда
                    try:
                        addr_bytes = socket.inet_aton(target_host)
                        atyp = 0x01  # IPv4
                    except socket.error:
                        # Доменное имя
                        addr_bytes = target_host.encode('utf-8')
                        atyp = 0x03  # Domain
                    
                    if atyp == 0x01:
                        request = struct.pack('!BBBB', 0x05, 0x01, 0x00, 0x01)  # VER, CMD, RSV, ATYP (IPv4)
                        request += addr_bytes
                    else:
                        request = struct.pack('!BBBB', 0x05, 0x01, 0x00, 0x03)  # VER, CMD, RSV, ATYP (Domain)
                        request += struct.pack('!B', len(addr_bytes))
                        request += addr_bytes
                    
                    request += struct.pack('!H', target_port)
                    node_sock.sendall(request)
                    
                    # Получаем ответ с таймаутом
                    node_sock.settimeout(10)  # Таймаут для CONNECT ответа
                    response = node_sock.recv(10)
                    
                    if len(response) < 2 or response[1] != 0x00:
                        node_sock.close()
                        node_sock = None
                        error_code = response[1] if len(response) >= 2 else 'unknown'
                        if attempt < max_retries - 1:
                            time.sleep(retry_delay * (attempt + 1))
                            continue
                        logger.error(f"Нода {self.node['node_id']}: ошибка SOCKS5 CONNECT (код: {error_code})")
                        return None
                    
                    # Успешное подключение - сбрасываем таймаут для реле данных
                    node_sock.settimeout(None)  # Убираем таймаут для передачи данных
                
                # Для HTTP нод просто возвращаем соединение - данные будут переданы напрямую
                return node_sock
                
            except socket.timeout:
                if node_sock:
                    try:
                        node_sock.close()
                    except:
                        pass
                node_sock = None
                if attempt < max_retries - 1:
                    logger.warning(f"Таймаут подключения к ноде {self.node['node_id']}, попытка {attempt + 1}/{max_retries}")
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                logger.error(f"Таймаут подключения к ноде {self.node['node_id']} после {max_retries} попыток")
                return None
                
            except ConnectionRefusedError:
                if node_sock:
                    try:
                        node_sock.close()
                    except:
                        pass
                node_sock = None
                if attempt < max_retries - 1:
                    logger.warning(f"Нода {self.node['node_id']} отклонила подключение, попытка {attempt + 1}/{max_retries}")
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                logger.error(f"Нода {self.node['node_id']} отклонила подключение после {max_retries} попыток (проверьте, запущена ли нода)")
                return None
                
            except OSError as e:
                if node_sock:
                    try:
                        node_sock.close()
                    except:
                        pass
                node_sock = None
                if e.errno == 111:  # Connection refused
                    if attempt < max_retries - 1:
                        logger.warning(f"Нода {self.node['node_id']} недоступна (errno {e.errno}), попытка {attempt + 1}/{max_retries}")
                        time.sleep(retry_delay * (attempt + 1))
                        continue
                    logger.error(f"Нода {self.node['node_id']} недоступна после {max_retries} попыток (проверьте, запущена ли нода на {self.node['host']}:{self.node['port']})")
                else:
                    if attempt < max_retries - 1:
                        logger.warning(f"Ошибка подключения к ноде {self.node['node_id']}: {e}, попытка {attempt + 1}/{max_retries}")
                        time.sleep(retry_delay * (attempt + 1))
                        continue
                    logger.error(f"Ошибка подключения к ноде {self.node['node_id']}: {e}")
                return None
                
            except Exception as e:
                if node_sock:
                    try:
                        node_sock.close()
                    except:
                        pass
                node_sock = None
                if attempt < max_retries - 1:
                    logger.warning(f"Неожиданная ошибка подключения к ноде {self.node['node_id']}: {e}, попытка {attempt + 1}/{max_retries}")
                    time.sleep(retry_delay * (attempt + 1))
                    continue
                logger.error(f"Ошибка подключения к ноде {self.node['node_id']}: {e}")
                return None
        
        return None
    
    def cleanup(self, status="DISCONNECTED"):
        """Очистка ресурсов и логирование."""
        if self.username and self.node:
            duration = time.time() - self.start_time
            db.log_connection(
                self.username, self.client_ip, self.node['node_id'],
                self.destination, duration, self.bytes_sent, self.bytes_received, status
            )
            db.update_traffic_stats(
                self.username, self.node['node_id'],
                self.bytes_sent, self.bytes_received
            )
            self.unregister_session()
            logger.info(f"[{status}] {self.username} -> {self.node['node_id']} | {self.destination} | {duration:.2f}s | {self.bytes_sent + self.bytes_received} bytes")
        
        if self.client_sock:
            self.client_sock.close()


class HTTPProxyHandler(ProxyHandler):
    """Обработчик HTTP прокси-запросов."""
    
    def run(self):
        try:
            self.client_sock.settimeout(5)
            first_data = self.client_sock.recv(4096)
            if not first_data:
                return
            
            header_lines = first_data.split(b'\r\n')
            first_line = header_lines[0].decode('latin-1', errors='ignore')
            
            # Аутентификация
            if not self._authenticate(header_lines):
                return
            
            # Проверка метода CONNECT
            if not first_line.startswith('CONNECT '):
                self._send_error(405, "Only CONNECT method supported")
                return
            
            # Парсинг цели
            parts = first_line.split()
            target = parts[1]
            if ':' not in target:
                self._send_error(400, "Invalid address format")
                return
            
            target_host, target_port = target.split(':')
            target_port = int(target_port)
            self.destination = f"{target_host}:{target_port}"
            
            # Подключение к ноде
            node_sock = self.connect_to_node(target_host, target_port)
            if not node_sock:
                self._send_error(503, "Failed to connect to node")
                return
            
            # Регистрация сессии
            self.register_session()
            logger.info(f"[HTTP] {self.username} ({self.client_ip}) -> {self.node['node_id']} -> {self.destination}")
            
            # Отправка ответа клиенту
            self.client_sock.sendall(b'HTTP/1.1 200 Connection established\r\nProxy-Agent: ProxyPanel\r\n\r\n')
            
            # Релей данных
            self._relay_data(node_sock)
            
        except Exception as e:
            logger.error(f"[HTTP ERROR] {e}")
        finally:
            self.cleanup()
    
    def _authenticate(self, header_lines):
        """Извлекает и проверяет учетные данные из заголовков."""
        auth_header = None
        for line in header_lines:
            if line.lower().startswith(b'proxy-authorization: basic '):
                auth_header = line
                break
        
        if not auth_header:
            self._send_auth_required()
            return False
        
        try:
            encoded = auth_header.split(b' ')[-1]
            decoded = base64.b64decode(encoded).decode('latin-1')
            username, password = decoded.split(':', 1)
        except:
            self._send_error(401, "Invalid auth format")
            return False
        
        is_ok, reason = self.authenticate(username, password)
        if not is_ok:
            self._send_error(401 if "credentials" in reason.lower() else 403, reason)
            return False
        
        return True
    
    def _send_auth_required(self):
        response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"ProxyPanel\"\r\nConnection: close\r\n\r\n"
        try:
            self.client_sock.sendall(response.encode())
        except:
            pass
    
    def _send_error(self, code, message):
        response = f"HTTP/1.1 {code} {message}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{message}"
        try:
            self.client_sock.sendall(response.encode())
        except:
            pass
    
    def _relay_data(self, node_sock):
        """Передает данные между клиентом и нодой."""
        sockets = [self.client_sock, node_sock]
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 1)
            if xlist:
                break
            if rlist:
                for sock in rlist:
                    from_sock = sock
                    to_sock = node_sock if sock is self.client_sock else self.client_sock
                    try:
                        data = from_sock.recv(4096)
                        if data:
                            to_sock.sendall(data)
                            if sock is self.client_sock:
                                self.bytes_sent += len(data)
                            else:
                                self.bytes_received += len(data)
                        else:
                            return
                    except:
                        return
        if node_sock:
            node_sock.close()


class SOCKS5ProxyHandler(ProxyHandler):
    """Обработчик SOCKS5 прокси-запросов."""
    
    def run(self):
        try:
            self.client_sock.settimeout(5)
            
            # Получение методов аутентификации
            methods_data = self.client_sock.recv(256)
            if not methods_data or methods_data[0] != 0x05:
                self.client_sock.sendall(b'\x05\xFF')
                return
            
            if 0x02 not in methods_data[2:]:  # User/Pass auth
                self.client_sock.sendall(b'\x05\xFF')
                return
            
            self.client_sock.sendall(b'\x05\x02')  # Выбираем User/Pass
            
            # Получение учетных данных
            auth_data = self.client_sock.recv(512)
            if not auth_data or auth_data[0] != 0x01:
                self.client_sock.sendall(b'\x01\xFF')
                return
            
            ulength = auth_data[1]
            username = auth_data[2:2+ulength].decode('latin-1', errors='ignore')
            plength_offset = 2 + ulength
            plength = auth_data[plength_offset]
            password = auth_data[plength_offset+1:plength_offset+1+plength].decode('latin-1', errors='ignore')
            
            # Аутентификация
            is_ok, reason = self.authenticate(username, password)
            if not is_ok:
                self.client_sock.sendall(b'\x01\xFF')
                logger.warning(f"[SOCKS5 AUTH FAILED] {username} ({self.client_ip}): {reason}")
                return
            
            self.client_sock.sendall(b'\x01\x00')  # Auth success
            
            # Получение команды
            command_header = self.client_sock.recv(4)
            if not command_header or command_header[1] != 0x01:  # CONNECT only
                self.client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            # Получение адреса назначения
            command_data, dest_addr, dest_port = self._recv_target(command_header)
            if not command_data:
                self.client_sock.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            self.destination = f"{dest_addr}:{dest_port}"
            
            # Подключение к ноде
            node_sock = self.connect_to_node(dest_addr, dest_port)
            if not node_sock:
                self.client_sock.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            # Регистрация сессии
            self.register_session()
            logger.info(f"[SOCKS5] {self.username} ({self.client_ip}) -> {self.node['node_id']} -> {self.destination}")
            
            # Отправка успешного ответа
            self.client_sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            
            # Релей данных
            self._relay_data(node_sock)
            
        except Exception as e:
            logger.error(f"[SOCKS5 ERROR] {e}")
        finally:
            self.cleanup()
    
    def _recv_target(self, command_header):
        """Получает адрес назначения из SOCKS5 запроса."""
        command_data = command_header
        atyp = command_header[3]
        addr_len = 0
        dest_addr = "Unknown"
        dest_port = 0
        
        if atyp == 0x01:  # IPv4
            addr_len = 4
        elif atyp == 0x03:  # Domain
            domain_len_raw = self.client_sock.recv(1)
            if not domain_len_raw:
                return None, None, None
            domain_len = domain_len_raw[0]
            command_data += struct.pack('!B', domain_len)
            addr_len = domain_len
        elif atyp == 0x04:  # IPv6
            addr_len = 16
        else:
            return None, None, None
        
        addr_port_data = self.client_sock.recv(addr_len + 2)
        if len(addr_port_data) != addr_len + 2:
            return None, None, None
        
        command_data += addr_port_data
        
        if atyp == 0x01:
            dest_addr = socket.inet_ntoa(addr_port_data[:4])
        elif atyp == 0x03:
            dest_addr = addr_port_data[:-2].decode('latin-1', errors='ignore')
        
        dest_port = struct.unpack('!H', addr_port_data[-2:])[0]
        return command_data, dest_addr, dest_port
    
    def _relay_data(self, node_sock):
        """Передает данные между клиентом и нодой."""
        sockets = [self.client_sock, node_sock]
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 1)
            if xlist:
                break
            if rlist:
                for sock in rlist:
                    from_sock = sock
                    to_sock = node_sock if sock is self.client_sock else self.client_sock
                    try:
                        data = from_sock.recv(4096)
                        if data:
                            to_sock.sendall(data)
                            if sock is self.client_sock:
                                self.bytes_sent += len(data)
                            else:
                                self.bytes_received += len(data)
                        else:
                            return
                    except:
                        return
        if node_sock:
            node_sock.close()


def run_proxy_server(port, handler_class):
    """Запускает прокси-сервер."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((LOCAL_HOST, port))
        server_socket.listen(100)
        logger.info(f"[PROXY SERVER] {handler_class.__name__} listening on {LOCAL_HOST}:{port}")
        
        while True:
            try:
                client_sock, client_addr = server_socket.accept()
                handler = handler_class(client_sock, client_addr)
                handler.start()
            except Exception as e:
                logger.error(f"[PROXY ERROR] {e}")
    except Exception as e:
        logger.error(f"[FATAL] Failed to start proxy server on port {port}: {e}")
    finally:
        server_socket.close()


# =================================================================
# API ДЛЯ НОД (порт 3333)
# =================================================================

@node_api_app.route('/api/node/register', methods=['POST'])
def node_register():
    """Регистрация ноды в системе."""
    data = request.get_json()
    node_id = data.get('node_id')
    name = data.get('name')
    host = data.get('host')
    port = data.get('port')
    node_type = data.get('node_type', 'http')
    proxy_technology = data.get('proxy_technology', 'standard')
    auth_token = data.get('auth_token')
    max_connections = data.get('max_connections', 500)  # По умолчанию 500
    
    if not all([node_id, name, host, port, auth_token]):
        return jsonify({'error': 'Missing required fields'}), 400
    
    db.register_node(node_id, name, host, port, node_type, auth_token, proxy_technology, max_connections)
    logger.info(f"[NODE REGISTERED] {node_id} ({name}) at {host}:{port} [Technology: {proxy_technology}, MaxConn: {max_connections}]")
    
    return jsonify({'message': 'Node registered successfully'}), 200


@node_api_app.route('/api/node/heartbeat', methods=['POST'])
def node_heartbeat():
    """Heartbeat от ноды для обновления статуса."""
    data = request.get_json()
    node_id = data.get('node_id')
    auth_token = data.get('auth_token')
    current_connections = data.get('current_connections', 0)
    
    if not node_id or not auth_token:
        return jsonify({'error': 'Missing credentials'}), 400
    
    if not db.verify_node_token(node_id, auth_token):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    db.update_node_connections(node_id, current_connections)
    return jsonify({'message': 'Heartbeat received'}), 200


@node_api_app.route('/api/node/config', methods=['GET'])
def node_config():
    """Получение конфигурации ноды."""
    node_id = request.args.get('node_id')
    auth_token = request.args.get('auth_token')
    
    if not node_id or not auth_token:
        return jsonify({'error': 'Missing credentials'}), 400
    
    if not db.verify_node_token(node_id, auth_token):
        return jsonify({'error': 'Invalid credentials'}), 401
    
    node = db.get_node_by_id(node_id)
    if not node:
        return jsonify({'error': 'Node not found'}), 404
    
    return jsonify({
        'node_id': node['node_id'],
        'name': node['name'],
        'host': node['host'],
        'port': node['port'],
        'node_type': node['node_type'],
        'is_active': bool(node['is_active'])
    }), 200


def run_node_api():
    """Запускает API для нод."""
    logger.info(f"[NODE API] Listening on {LOCAL_HOST}:{NODE_API_PORT}")
    node_api_app.run(host=LOCAL_HOST, port=NODE_API_PORT, debug=False, use_reloader=False)


# =================================================================
# REST API ДЛЯ КЛИЕНТОВ (порт 8000)
# =================================================================

def api_token_required(f):
    """Декоратор для проверки JWT токена."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split()[1]
            except:
                return jsonify({'error': 'Invalid Authorization header'}), 401
        
        if not token:
            return jsonify({'error': 'Token is missing'}), 401
        
        try:
            data = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
            request.user_data = data
        except jwt.ExpiredSignatureError:
            return jsonify({'error': 'Token has expired'}), 401
        except jwt.InvalidTokenError:
            return jsonify({'error': 'Invalid token'}), 401
        
        return f(*args, **kwargs)
    return decorated


@api_app.route('/api/login', methods=['POST'])
def api_login():
    """Вход клиента и получение токена."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user = db.authenticate_user(username, password)
    if not user:
        return jsonify({'error': 'Invalid credentials'}), 401
    
    # Создание JWT токена
    payload = {
        'username': user['username'],
        'exp': time.time() + TOKEN_LIFETIME
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
    
    # Получение назначенных нод
    nodes = db.get_user_nodes(username)
    
    return jsonify({
        'message': 'Login successful',
        'token': token,
        'proxy_address': LOCAL_HOST,
        'http_port': HTTP_PORT,
        'socks5_port': SOCKS5_PORT,
        'assigned_nodes': [{'node_id': n['node_id'], 'name': n['name']} for n in nodes]
    }), 200


@api_app.route('/api/stats', methods=['GET'])
@api_token_required
def api_stats():
    """Получение статистики пользователя."""
    username = request.user_data.get('username')
    stats = db.get_traffic_stats(username=username, days=30)
    
    return jsonify({
        'stats': stats
    }), 200


def run_client_api():
    """Запускает REST API для клиентов."""
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR)
    logger.info(f"[CLIENT API] Listening on {LOCAL_HOST}:{API_PORT}")
    api_app.run(host=LOCAL_HOST, port=API_PORT, debug=False, use_reloader=False)


# =================================================================
# ГЛАВНАЯ ФУНКЦИЯ
# =================================================================

def main():
    """Запускает все сервисы."""
    # Инициализация БД
    db.setup_database()
    
    logger.info("=" * 60)
    logger.info("PROXY PANEL SERVER")
    logger.info("=" * 60)
    logger.info(f"HTTP Proxy:    {LOCAL_HOST}:{HTTP_PORT}")
    logger.info(f"SOCKS5 Proxy:  {LOCAL_HOST}:{SOCKS5_PORT}")
    logger.info(f"Client API:    {LOCAL_HOST}:{API_PORT}")
    logger.info(f"Node API:      {LOCAL_HOST}:{NODE_API_PORT}")
    logger.info("=" * 60)
    
    # Запуск всех сервисов в отдельных потоках
    threads = [
        threading.Thread(target=run_proxy_server, args=(HTTP_PORT, HTTPProxyHandler), daemon=True),
        threading.Thread(target=run_proxy_server, args=(SOCKS5_PORT, SOCKS5ProxyHandler), daemon=True),
        threading.Thread(target=run_client_api, daemon=True),
        threading.Thread(target=run_node_api, daemon=True),
    ]
    
    for thread in threads:
        thread.start()
    
    # Ожидание
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        logger.info("\n[STOP] Server stopped by user")


if __name__ == '__main__':
    main()

