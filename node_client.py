"""
Клиент для ноды (прокси-сервера)
Подключается к панели управления и обрабатывает запросы от пользователей
"""
import socket
import threading
import select
import struct
import time
import requests
import logging
import sys
import json

# --- КОНФИГУРАЦИЯ НОДЫ ---
NODE_ID = 'node-001'  # Уникальный ID ноды
NODE_NAME = 'Node 1'
NODE_HOST = '0.0.0.0'  # IP адрес этой ноды (для подключения клиентов)
NODE_PORT = 1080  # Порт этой ноды
NODE_TYPE = 'socks5'  # 'http' или 'socks5'
AUTH_TOKEN = 'node_secret_token_123'  # Токен для аутентификации в панели

# Адрес панели управления
PANEL_HOST = 'ip панели'
PANEL_PORT = 3333
PANEL_URL = f'http://{PANEL_HOST}:{PANEL_PORT}'

# Настройка логирования
logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

class NodeProxyHandler(threading.Thread):
    """Обработчик прокси-запросов на ноде."""
    
    def __init__(self, client_sock, client_addr):
        super().__init__()
        self.client_sock = client_sock
        self.client_addr = client_addr
        self.daemon = True
        self.start_time = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
    
    def run(self):
        """Обрабатывает SOCKS5 подключение."""
        try:
            self.client_sock.settimeout(10)
            
            # SOCKS5 handshake
            methods_data = self.client_sock.recv(256)
            if not methods_data or methods_data[0] != 0x05:
                self.client_sock.sendall(b'\x05\xFF')
                return
            
            # Поддержка без аутентификации (0x00)
            if 0x00 not in methods_data[2:]:
                self.client_sock.sendall(b'\x05\xFF')
                return
            
            self.client_sock.sendall(b'\x05\x00')  # No auth required
            
            # Получение команды
            command_header = self.client_sock.recv(4)
            if not command_header or command_header[1] != 0x01:  # CONNECT only
                self.client_sock.sendall(b'\x05\x07\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            # Получение адреса назначения
            dest_addr, dest_port = self._recv_target(command_header)
            if not dest_addr:
                self.client_sock.sendall(b'\x05\x08\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            logger.info(f"[NODE] Подключение к {dest_addr}:{dest_port} от {self.client_addr[0]}")
            
            # Подключение к целевому серверу
            try:
                target_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                target_sock.settimeout(10)
                target_sock.connect((dest_addr, dest_port))
            except Exception as e:
                logger.error(f"[NODE] Ошибка подключения к {dest_addr}:{dest_port}: {e}")
                self.client_sock.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            # Отправка успешного ответа
            self.client_sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            
            # Релей данных
            self._relay_data(target_sock)
            
        except Exception as e:
            logger.error(f"[NODE ERROR] {e}")
        finally:
            self.cleanup()
    
    def _recv_target(self, command_header):
        """Получает адрес назначения из SOCKS5 запроса."""
        atyp = command_header[3]
        addr_len = 0
        dest_addr = None
        dest_port = 0
        
        if atyp == 0x01:  # IPv4
            addr_len = 4
        elif atyp == 0x03:  # Domain
            domain_len_raw = self.client_sock.recv(1)
            if not domain_len_raw:
                return None, None
            domain_len = domain_len_raw[0]
            addr_len = domain_len
        elif atyp == 0x04:  # IPv6
            addr_len = 16
        else:
            return None, None
        
        addr_port_data = self.client_sock.recv(addr_len + 2)
        if len(addr_port_data) != addr_len + 2:
            return None, None
        
        if atyp == 0x01:
            dest_addr = socket.inet_ntoa(addr_port_data[:4])
        elif atyp == 0x03:
            dest_addr = addr_port_data[:-2].decode('latin-1', errors='ignore')
        
        dest_port = struct.unpack('!H', addr_port_data[-2:])[0]
        return dest_addr, dest_port
    
    def _relay_data(self, target_sock):
        """Передает данные между клиентом и целевым сервером."""
        sockets = [self.client_sock, target_sock]
        while True:
            rlist, _, xlist = select.select(sockets, [], sockets, 1)
            if xlist:
                break
            if rlist:
                for sock in rlist:
                    from_sock = sock
                    to_sock = target_sock if sock is self.client_sock else self.client_sock
                    try:
                        data = from_sock.recv(4096)
                        if data:
                            to_sock.sendall(data)
                            if sock is self.client_sock:
                                self.bytes_received += len(data)
                            else:
                                self.bytes_sent += len(data)
                        else:
                            return
                    except:
                        return
        if target_sock:
            target_sock.close()
    
    def cleanup(self):
        """Очистка ресурсов."""
        duration = time.time() - self.start_time
        total_bytes = self.bytes_sent + self.bytes_received
        logger.info(f"[NODE] Соединение завершено: {duration:.2f}s, {total_bytes} bytes")
        if self.client_sock:
            self.client_sock.close()


def register_with_panel():
    """Регистрирует ноду в панели управления."""
    try:
        response = requests.post(
            f'{PANEL_URL}/api/node/register',
            json={
                'node_id': NODE_ID,
                'name': NODE_NAME,
                'host': NODE_HOST,
                'port': NODE_PORT,
                'node_type': NODE_TYPE,
                'proxy_technology': 'standard',
                'auth_token': AUTH_TOKEN
            },
            timeout=5
        )
        if response.status_code == 200:
            logger.info(f"[NODE] Успешно зарегистрирована в панели")
            return True
        else:
            logger.error(f"[NODE] Ошибка регистрации: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"[NODE] Не удалось подключиться к панели: {e}")
        return False


def send_heartbeat():
    """Отправляет heartbeat в панель управления."""
    while True:
        try:
            time.sleep(30)  # Каждые 30 секунд
            
            # Подсчет активных подключений (упрощенно)
            active_connections = threading.active_count() - 3  # Минус основные потоки
            
            response = requests.post(
                f'{PANEL_URL}/api/node/heartbeat',
                json={
                    'node_id': NODE_ID,
                    'auth_token': AUTH_TOKEN,
                    'current_connections': max(0, active_connections)
                },
                timeout=5
            )
            
            if response.status_code == 200:
                logger.debug(f"[NODE] Heartbeat отправлен (подключений: {active_connections})")
            else:
                logger.warning(f"[NODE] Ошибка heartbeat: {response.status_code}")
        except Exception as e:
            logger.warning(f"[NODE] Ошибка отправки heartbeat: {e}")


def run_node_server():
    """Запускает прокси-сервер ноды."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    
    try:
        server_socket.bind((NODE_HOST, NODE_PORT))
        server_socket.listen(100)
        logger.info(f"[NODE] Прокси-сервер запущен на {NODE_HOST}:{NODE_PORT}")
        
        while True:
            try:
                client_sock, client_addr = server_socket.accept()
                handler = NodeProxyHandler(client_sock, client_addr)
                handler.start()
            except Exception as e:
                logger.error(f"[NODE ERROR] {e}")
    except Exception as e:
        logger.error(f"[NODE FATAL] Не удалось запустить сервер: {e}")
    finally:
        server_socket.close()


def main():
    """Главная функция."""
    logger.info("=" * 60)
    logger.info("NODE CLIENT - Прокси-сервер ноды")
    logger.info("=" * 60)
    logger.info(f"Node ID: {NODE_ID}")
    logger.info(f"Node Name: {NODE_NAME}")
    logger.info(f"Listening on: {NODE_HOST}:{NODE_PORT}")
    logger.info(f"Panel URL: {PANEL_URL}")
    logger.info("=" * 60)
    
    # Регистрация в панели
    if not register_with_panel():
        logger.warning("[NODE] Не удалось зарегистрироваться в панели. Продолжаем работу...")
    
    # Запуск heartbeat в отдельном потоке
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    heartbeat_thread.start()
    
    # Запуск прокси-сервера
    try:
        run_node_server()
    except KeyboardInterrupt:
        logger.info("\n[NODE] Сервер остановлен пользователем")


if __name__ == '__main__':
    # Проверка зависимостей
    try:
        import requests
    except ImportError:
        print("ОШИБКА: Установите requests: pip install requests")
        sys.exit(1)
    
    main()

