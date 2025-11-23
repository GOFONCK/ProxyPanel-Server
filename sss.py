import socket
import threading
import select
import sys
import base64
import sqlite3
import time
import struct
import os
# import socks # УДАЛЕНО
import hashlib
from sqlite3 import IntegrityError, Error as SQLiteError
import random
import logging

# --- НОВЫЕ ИМПОРТЫ ДЛЯ API ---
from flask import Flask, request, jsonify # Нужна установка: pip install Flask
import jwt # Нужна установка: pip install pyjwt
from functools import wraps # Для декоратора API

# --- КОНФИГУРАЦИЯ ---
LOCAL_HOST = '0.0.0.0'
HTTP_PORT = 8080
SOCKS5_PORT = 8090
API_PORT = 8000     # Порт для API-интерфейса клиента
JWT_SECRET = 'YOUR_SUPER_SECURE_JWT_SECRET_KEY_HERE_!!!' # ОБЯЗАТЕЛЬНО СМЕНИТЕ
TOKEN_LIFETIME = 3600 * 24 # 24 часа

# Целевой SOCKS5 прокси (Shadowsocks) - УДАЛЕНО
# SS_HOST = '127.0.0.1' - УДАЛЕНО
# SS_PORT = 1080 - УДАЛЕНО

# База данных
DB_FILE = 'proxy_users.db'

# Администратор для веб-панели (данные для автоматического создания)
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD = 'super_secret_admin_password' 
ADMIN_DEVICE_LIMIT = 5
# ---------------------

# Используем Lock для обеспечения потокобезопасности SQLite
db_lock = threading.Lock()

# Инициализация Flask
api_app = Flask('stealthnet_api') # Даем уникальное имя во избежание конфликтов
api_app.config['SECRET_KEY'] = JWT_SECRET


# =================================================================
# === БЛОК УПРАВЛЕНИЯ БАЗОЙ ДАННЫХ (DB HELPERS) ====================
# =================================================================

def get_db_connection():
    """Создает и возвращает новое соединение с БД для потока."""
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def setup_database():
    """Инициализирует таблицы пользователей, активных сессий и логов."""
    conn = get_db_connection()
    cursor = conn.cursor()
    
    with db_lock:
        # 1. Таблица пользователей
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                username TEXT PRIMARY KEY,
                password TEXT NOT NULL,
                is_active BOOLEAN NOT NULL DEFAULT 1,
                device_limit INTEGER NOT NULL DEFAULT 1,
                can_rotate BOOLEAN NOT NULL DEFAULT 0
            )
        ''')
        
        # 2. Таблица активных сессий 
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                username TEXT NOT NULL, client_ip TEXT NOT NULL,
                session_start DATETIME DEFAULT (datetime('now', 'localtime')),
                PRIMARY KEY (username, client_ip)
            )
        ''')
        # 3. Таблица логов
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
                username TEXT NOT NULL, client_ip TEXT NOT NULL,
                destination TEXT NOT NULL, duration_sec REAL, status TEXT NOT NULL
            )
        ''')
        
        # Обновление таблицы (добавление can_rotate, если отсутствует)
        try:
            conn.execute("SELECT can_rotate FROM users LIMIT 1")
        except sqlite3.OperationalError:
            print("[DB] Обновление схемы: Добавление 'can_rotate'...")
            conn.execute("ALTER TABLE users ADD COLUMN can_rotate BOOLEAN NOT NULL DEFAULT 0")
        
        # Добавление админа
        admin_password_hash = hashlib.sha256(ADMIN_PASSWORD.encode()).hexdigest()
        try:
            cursor.execute("INSERT INTO users (username, password, is_active, device_limit, can_rotate) VALUES (?, ?, ?, ?, ?)", 
                           (ADMIN_USERNAME, admin_password_hash, 1, ADMIN_DEVICE_LIMIT, 1))
        except IntegrityError:
            cursor.execute("UPDATE users SET password = ?, device_limit = ?, can_rotate = ? WHERE username = ?", (admin_password_hash, ADMIN_DEVICE_LIMIT, 1, ADMIN_USERNAME))
            pass
            
        # Добавление тестового пользователя (user1/pass1, CORE)
        user1_pass_hash = hashlib.sha256('pass1'.encode()).hexdigest()
        try:
            cursor.execute("INSERT INTO users (username, password, is_active, device_limit, can_rotate) VALUES (?, ?, ?, ?, ?)", 
                           ('user1', user1_pass_hash, 1, 2, 0))
        except IntegrityError: pass
        
        # Добавление тестового PRO пользователя (pro/pro, PRO)
        pro_pass_hash = hashlib.sha256('pro'.encode()).hexdigest()
        try:
            cursor.execute("INSERT INTO users (username, password, is_active, device_limit, can_rotate) VALUES (?, ?, ?, ?, ?)", 
                           ('pro', pro_pass_hash, 1, 3, 1))
        except IntegrityError: pass

    conn.commit()
    conn.close()

# --- ФУНКЦИИ ДЛЯ РАБОТЫ ПРОКСИ (AUTHENTICATE, REGISTER, UNREGISTER, LOG) ---

def authenticate_and_check_limit(username, password, client_ip):
    """
    Проверяет учетные данные, статус и лимит устройств, используя хеши.
    """
    conn = get_db_connection()
    is_allowed = False
    reason = "User not found"
    user_info = None

    incoming_hash = None
    try:
        incoming_hash = hashlib.sha256(password.encode()).hexdigest()
    except:
        conn.close()
        return False, "Hash calculation error"

    with db_lock:
        cursor = conn.execute("SELECT password, is_active, device_limit FROM users WHERE username = ?", (username,))
        user_info = cursor.fetchone()

        if user_info:
            is_active = user_info['is_active'] == 1
            device_limit = user_info['device_limit']
            user_password_in_db = user_info['password']
            
            is_password_correct = (incoming_hash == user_password_in_db)

            if not is_password_correct:
                # Оставляем отладку только для НЕУДАЧНЫХ попыток
                print(f"[DEBUG AUTH FAILED] Пользователь {username} ({client_ip}) отправил неверный пароль.")
                reason = "Incorrect password"
            elif not is_active:
                reason = "Deactivated"
            
            if is_password_correct and is_active:
                # Проверка лимита устройств
                cursor = conn.execute("SELECT COUNT(DISTINCT client_ip) as count FROM active_sessions WHERE username = ?", (username,))
                session_count = cursor.fetchone()['count']
                
                if session_count >= device_limit:
                    ip_exists = conn.execute("SELECT 1 FROM active_sessions WHERE username = ? AND client_ip = ?", (username, client_ip)).fetchone()
                    if not ip_exists:
                        reason = f"Device limit exceeded ({session_count}/{device_limit})"
                        conn.close()
                        return False, reason
                        
                is_allowed = True
                reason = "OK"
            
    conn.close()
    return is_allowed, reason

def register_session(username, client_ip):
    conn = get_db_connection()
    with db_lock:
        try: conn.execute("INSERT OR REPLACE INTO active_sessions (username, client_ip) VALUES (?, ?)", (username, client_ip)); conn.commit()
        except SQLiteError as e: print(f"[DB ERROR] Failed to register session: {e}")
    conn.close()
    
def unregister_session(username, client_ip):
    conn = get_db_connection()
    with db_lock: conn.execute("DELETE FROM active_sessions WHERE username = ? AND client_ip = ?", (username, client_ip)); conn.commit()
    conn.close()

def log_connection_start(username, client_ip, destination):
    conn = get_db_connection()
    cursor = conn.cursor()
    with db_lock:
        cursor.execute("INSERT INTO logs (username, client_ip, destination, status) VALUES (?, ?, ?, ?)", (username, client_ip, destination, "CONNECTED"))
        conn.commit()
        log_id = cursor.lastrowid
    conn.close()
    return log_id

def log_connection_end(log_id, username, client_ip, start_time, status="DISCONNECTED"):
    duration = time.time() - start_time
    conn = get_db_connection()
    with db_lock:
        if log_id: conn.execute("UPDATE logs SET duration_sec = ?, status = ? WHERE id = ?", (duration, status, log_id))
        else: conn.execute("INSERT INTO logs (username, client_ip, destination, status, duration_sec) VALUES (?, ?, ?, ?, ?)", (username, client_ip, 'N/A', 'FAILED_LOG', duration))
        conn.commit()
    conn.close()

# =================================================================
# === ПРОКСИ БЛОКИ (HTTP и SOCKS5) =================================
# =================================================================
class HTTPProxyHandler(threading.Thread):
    def __init__(self, client_sock, client_addr):
        super().__init__()
        self.client_sock = client_sock
        self.client_addr = client_addr
        self.client_ip = client_addr[0]
        self.upstream_sock = None
        self.username = "UNAUTH"
        self.destination = "N/A"
        self.log_id = None
        self.start_time = time.time()
        self.daemon = True

    def run(self):
        try:
            self.client_sock.settimeout(5)
            first_data = self.client_sock.recv(4096)
            if not first_data: return

            header_lines = first_data.split(b'\r\n')
            first_line = header_lines[0].decode('latin-1', errors='ignore')

            if not self._authenticate_client_and_check_limit(header_lines):
                return 
            
            if not first_line.startswith('CONNECT '):
                self._send_error(405, "Поддерживается только метод CONNECT (HTTPS).")
                return

            parts = first_line.split()
            target = parts[1]
            if ':' not in target:
                self._send_error(400, "Неверный формат адреса.")
                return

            host, port = target.split(':')
            port = int(port)
            self.destination = f"{host}:{port}"
            
            # --- ИЗМЕНЕНИЕ ---
            # self.upstream_sock = socks.socksocket()
            # self.upstream_sock.set_proxy(socks.SOCKS5, SS_HOST, SS_PORT)
            # self.upstream_sock.connect((host, port))
            
            # Подключаемся напрямую к цели
            self.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.upstream_sock.connect((host, port))
            # --- КОНЕЦ ИЗМЕНЕНИЯ ---
            
            register_session(self.username, self.client_ip)
            self.log_id = log_connection_start(self.username, self.client_ip, self.destination)
            print(f"[AUTH OK | HTTP:{self.username} | {self.client_ip}] CONNECT -> {self.destination}")
            
            self.client_sock.sendall(b'HTTP/1.1 200 Connection established\r\nProxy-Agent: Secure-Bridge\r\n\r\n')
            self._relay_data()

        except socket.error as e:
            print(f"[ERROR | HTTP:{self.username}] Ошибка подключения к {self.destination}: {e}")
            self._send_error(503, f"Connection Error: {e}")
        except Exception as e:
            print(f"[ERROR | HTTP:{self.username}] Ошибка в обработчике: {e}")
        finally:
            self._cleanup()
    
    def _authenticate_client_and_check_limit(self, header_lines):
        auth_header = None
        for line in header_lines:
            if line.lower().startswith(b'proxy-authorization: basic '):
                auth_header = line
                break
        
        if not auth_header:
            self._send_auth_required()
            return False
            
        try:
            encoded_credentials = auth_header.split(b' ')[-1]
            decoded_credentials = base64.b64decode(encoded_credentials).decode('latin-1')
            username, password = decoded_credentials.split(':', 1)
        except Exception:
            self._send_error(401, "Proxy Authentication Failed: Invalid format")
            return False
            
        is_allowed, reason = authenticate_and_check_limit(username, password, self.client_ip)
        
        if is_allowed:
            self.username = username
            return True
        else:
            if reason == "Incorrect password" or reason == "User not found":
                self._send_error(401, "Proxy Authentication Failed: Invalid credentials")
            else:
                self._send_error(403, f"Forbidden: {reason}")
            
            print(f"[AUTH FAILED | HTTP] {reason} для пользователя: {username} ({self.client_ip})")
            return False

    def _send_auth_required(self):
        response = "HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"Secure Proxy Access\"\r\nConnection: close\r\n\r\n"
        try: self.client_sock.sendall(response.encode())
        except: pass

    def _send_error(self, code, message):
        response = f"HTTP/1.1 {code} {message}\r\nContent-Type: text/plain\r\nConnection: close\r\n\r\n{message}"
        try: self.client_sock.sendall(response.encode())
        except: pass

    def _relay_data(self):
        sockets = [self.client_sock, self.upstream_sock]
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 1)
            if xlist: break
            if rlist:
                for sock in rlist:
                    from_sock = sock
                    to_sock = self.upstream_sock if sock is self.client_sock else self.client_sock
                    try:
                        data = from_sock.recv(4096)
                        if data: 
                            to_sock.sendall(data)
                        else: return 
                    except: return
        
    def _cleanup(self, status="DISCONNECTED"):
        if self.username != "UNAUTH":
            unregister_session(self.username, self.client_ip)
            log_connection_end(self.log_id, self.username, self.client_ip, self.start_time, status=status)
            print(f"[{status} | HTTP:{self.username} | {self.client_ip}] {self.destination} завершено ({time.time() - self.start_time:.2f} сек)")
        
        if self.client_sock: self.client_sock.close()
        if self.upstream_sock: self.upstream_sock.close()

class SOCKS5AuthHandler(threading.Thread):
    def __init__(self, client_sock, client_addr):
        super().__init__()
        self.client_sock = client_sock
        self.client_addr = client_addr
        self.client_ip = client_addr[0]
        self.upstream_sock = None
        self.username = "UNAUTH"
        self.destination = "N/A"
        self.log_id = None
        self.start_time = time.time()
        self.daemon = True

    def run(self):
        try:
            self.client_sock.settimeout(5)
            
            methods_data = self.client_sock.recv(256)
            if not methods_data or methods_data[0] != 0x05:
                self.client_sock.sendall(b'\x05\xFF')
                return
            
            if 0x02 not in methods_data[2:]: # 0x02 - User/Pass
                self.client_sock.sendall(b'\x05\xFF')
                return
                
            self.client_sock.sendall(b'\x05\x02') # Отвечаем, что требуем User/Pass (0x02)

            auth_data = self.client_sock.recv(512)
            if not auth_data or auth_data[0] != 0x01:
                self.client_sock.sendall(b'\x01\xFF')
                return

            ulength = auth_data[1]
            username = auth_data[2:2+ulength].decode('latin-1', errors='ignore')
            
            plength_offset = 2 + ulength
            plength = auth_data[plength_offset]
            password = auth_data[plength_offset+1:plength_offset+1+plength].decode('latin-1', errors='ignore')

            is_allowed, reason = authenticate_and_check_limit(username, password, self.client_ip)
            
            if not is_allowed:
                self.client_sock.sendall(b'\x01\xFF') # Auth Failure
                print(f"[AUTH FAILED | SOCKS5] {reason} для пользователя: {username} ({self.client_ip})")
                return
            
            self.username = username
            self.client_sock.sendall(b'\x01\x00') # Auth Success

            command_header = self.client_sock.recv(4) # V, CMD, RSV, ATYP
            if not command_header or command_header[1] != 0x01:
                self.client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00') # Command not supported
                return
            
            self.command_data, self.destination, dest_port = self._recv_socks5_target(command_header)
            
            if not self.command_data:
                self.client_sock.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00') # Address type not supported
                return
            
            host = self.destination.split(':')[0]
            
            # --- ИЗМЕНЕНИЕ ---
            # self.upstream_sock = socks.socksocket()
            # self.upstream_sock.set_proxy(socks.SOCKS5, SS_HOST, SS_PORT)
            # self.upstream_sock.connect((host, dest_port))

            # Подключаемся напрямую к цели
            self.upstream_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.upstream_sock.connect((host, dest_port))
            # --- КОНЕЦ ИЗМЕНЕНИЯ ---
            
            register_session(self.username, self.client_ip)
            self.log_id = log_connection_start(self.username, self.client_ip, self.destination)
            print(f"[AUTH OK | SOCKS5:{self.username} | {self.client_ip}] CONNECT -> {self.destination}")

            self.client_sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00') 

            self._relay_data()

        except Exception as e:
            print(f"[ERROR | SOCKS5:{self.username}] Ошибка при обработке соединения: {e}")
        finally:
            self._cleanup()


    def _recv_socks5_target(self, command_header):
        command_data = command_header
        atyp = command_header[3]
        addr_len = 0
        dest_addr_str = "Unknown"
        dest_port = 0
        
        if atyp == 0x01: addr_len = 4
        elif atyp == 0x03:
            domain_len_raw = self.client_sock.recv(1)
            if not domain_len_raw: return None, None, None
            domain_len = domain_len_raw[0]
            command_data += struct.pack('!B', domain_len)
            addr_len = domain_len
        elif atyp == 0x04: addr_len = 16
        else: return None, None, None

        addr_port_data = self.client_sock.recv(addr_len + 2)
        if len(addr_port_data) != addr_len + 2: return None, None, None
        
        command_data += addr_port_data
        
        if atyp == 0x01: dest_addr_str = socket.inet_ntoa(addr_port_data[:4])
        elif atyp == 0x03: dest_addr_str = addr_port_data[:-2].decode('latin-1', errors='ignore')
        
        dest_port = struct.unpack('!H', addr_port_data[-2:])[0]
        return command_data, f"{dest_addr_str}:{dest_port}", dest_port

    def _relay_data(self):
        sockets = [self.client_sock, self.upstream_sock]
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 1)
            if xlist: break
            if rlist:
                for sock in rlist:
                    from_sock = sock
                    to_sock = self.upstream_sock if sock is self.client_sock else self.client_sock
                    try:
                        data = from_sock.recv(4096)
                        if data: 
                            to_sock.sendall(data)
                        else: return 
                    except: return
                    
    def _cleanup(self, status="DISCONNECTED"):
        if self.username != "UNAUTH":
            unregister_session(self.username, self.client_ip)
            log_connection_end(self.log_id, self.username, self.client_ip, self.start_time, status=status)
            print(f"[{status} | SOCKS5:{self.username} | {self.client_ip}] {self.destination} завершено ({time.time() - self.start_time:.2f} сек)")
        
        if self.client_sock: self.client_sock.close()
        if self.upstream_sock: self.upstream_sock.close()


# =================================================================
# === БЛОК API FLASK (PORT 8000) ===================================
# =================================================================

def api_check_credentials(username, password):
    """
    Проверяет учетные данные для API-запросов. 
    Возвращает (user_info, reason) или (None, reason).
    """
    conn = get_db_connection()
    user_info = None
    reason = "User not found"
    
    with db_lock:
        cursor = conn.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_info = cursor.fetchone()

    if not user_info:
        conn.close()
        return None, reason

    is_active = user_info['is_active'] == 1
    if not is_active:
        conn.close()
        return None, "Account deactivated"

    user_password_in_db = user_info['password']
    is_password_correct = False
    
    # Проверка хешированного пароля
    try:
        if user_password_in_db == hashlib.sha256(password.encode()).hexdigest():
            is_password_correct = True
    except:
        pass
        
    conn.close()
    
    if is_password_correct:
        return user_info, "OK"
    else:
        return None, "Incorrect credentials"

def api_token_required(f):
    """Декоратор для проверки JWT токена."""
    @wraps(f)
    def decorated(*args, **kwargs):
        token = None
        if 'Authorization' in request.headers:
            try:
                token = request.headers['Authorization'].split()[1]
            except:
                 return jsonify({'error': 'Invalid Authorization header format'}), 401
        
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
    """API-точка для входа клиента и получения токена."""
    data = request.get_json()
    username = data.get('username')
    password = data.get('password')
    
    if not username or not password:
        return jsonify({'error': 'Username and password required'}), 400
    
    user_info, reason = api_check_credentials(username, password)
    
    if user_info:
        payload = {
            'username': user_info['username'],
            'exp': time.time() + TOKEN_LIFETIME
        }
        token = jwt.encode(payload, JWT_SECRET, algorithm='HS256')
        
        client_config = {
            'proxy_address': LOCAL_HOST, 
            'proxy_port': SOCKS5_PORT,      
            'tariff': 'PRO' if user_info['can_rotate'] == 1 else 'CORE',
            'rotation_allowed': user_info['can_rotate'] == 1,
        }
        
        return jsonify({
            'message': 'Login successful',
            'token': token,
            'config': client_config
        }), 200
    else:
        return jsonify({'error': f'Authentication failed: {reason}'}), 401


@api_app.route('/api/rotate', methods=['POST'])
@api_token_required
def api_rotate():
    """API-точка для ротации IP."""
    username = request.user_data.get('username')
    
    conn = get_db_connection()
    cursor = conn.execute("SELECT can_rotate FROM users WHERE username = ?", (username,))
    can_rotate_row = cursor.fetchone()
    conn.close()
    
    if not can_rotate_row or can_rotate_row[0] != 1:
        return jsonify({'error': 'Rotation not allowed for your tariff (CORE)'}), 403
    
    # ИМИТАЦИЯ РОТАЦИИ 
    new_ip = f"203.0.{random.randint(100, 255)}.{random.randint(10, 99)}" 
    print(f"[API ROTATE] Пользователь {username} (PRO) запросил смену IP. Новый: {new_ip}")
    
    return jsonify({
        'message': 'IP rotation successful',
        'new_proxy_address': LOCAL_HOST, 
        'new_external_ip': new_ip,       
        'proxy_port': SOCKS5_PORT
    }), 200

# =================================================================
# === ГЛАВНАЯ ФУНКЦИЯ ЗАПУСКА ВСЕХ СЕРВЕРОВ =========================
# =================================================================

def run_flask_server():
    """Запускает Flask-API в отдельном потоке."""
    print(f"[API SERVER STARTED] Flask API слушает {LOCAL_HOST}:{API_PORT}")
    log = logging.getLogger('werkzeug')
    log.setLevel(logging.ERROR) 
    api_app.run(host=LOCAL_HOST, port=API_PORT, debug=False)


def run_server(port, handler_class):
    """Запускает слушающий прокси-сервер в отдельном потоке."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((LOCAL_HOST, port))
        server_socket.listen(5)
    except Exception as e:
        print(f"[FATAL] Не удалось запустить сервер на порту {port}: {e}")
        return

    print(f"[PROXY SERVER STARTED] {handler_class.__name__} слушает {LOCAL_HOST}:{port}")
    
    while True:
        try:
            client_sock, client_addr = server_socket.accept()
            handler = handler_class(client_sock, client_addr)
            handler.start()
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[ERROR] Ошибка в цикле сервера на порту {port}: {e}")
            
    server_socket.close()

def main():
    try:
        # import socks # УДАЛЕНО
        import logging
        import jwt
        from flask import Flask 
    except ImportError:
        print("\n[КРИТИЧЕСКАЯ ОШИБКА] Не найдены все необходимые библиотеки.")
        # PySocks больше не нужен
        print("Установите их: pip install Flask pyjwt")
        sys.exit(1)
        
    setup_database() 

    print(f"--- UNIFIED STEALTHNET SERVER ---")
    print(f"WEB API (Client Control): {LOCAL_HOST}:{API_PORT}")
    print(f"HTTP Proxy (Auth/Limits): {LOCAL_HOST}:{HTTP_PORT}")
    print(f"SOCKS5 Proxy (Auth/Limits): {LOCAL_HOST}:{SOCKS5_PORT}")
    # print(f"Shadowsocks Upstream: {SS_HOST}:{SS_PORT}") # УДАЛЕНО
    print(f"----------------------------------")
    print(f"*** ТЕСТОВЫЕ ДАННЫЕ: user1/pass1 (CORE), pro/pro (PRO) ***")
    print(f"*** СМЕНИТЕ JWT_SECRET В КОНФИГУРАЦИИ! ***")

    # 1. Запуск Flask API
    flask_thread = threading.Thread(target=run_flask_server)
    flask_thread.daemon = True
    flask_thread.start()

    # 2. Запуск HTTP-прокси
    http_thread = threading.Thread(target=run_server, args=(HTTP_PORT, HTTPProxyHandler))
    http_thread.daemon = True
    http_thread.start()

    # 3. Запуск SOCKS5-прокси
    socks5_thread = threading.Thread(target=run_server, args=(SOCKS5_PORT, SOCKS5AuthHandler))
    socks5_thread.daemon = True
    socks5_thread.start()

    # Основной поток ждет
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        print("\n[STOP] Сервер остановлен пользователем.")

if __name__ == '__main__':
    main()
