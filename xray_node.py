"""
Нода с интеграцией Xray
Подключается к панели управления как обычная нода, но проксирует трафик через Xray
Поддерживает различные протоколы Xray (VMess, VLESS, Trojan, Shadowsocks)
"""
import socket
import threading
import select
import struct
import time
import requests
import logging
import sys
import subprocess
import os
import json
import tempfile

# --- КОНФИГУРАЦИЯ НОДЫ ---
NODE_ID = 'xray-node-001'  # Уникальный ID ноды
NODE_NAME = 'Xray Node'
NODE_HOST = '0.0.0.0'  # IP адрес этой ноды (для подключения клиентов)
NODE_PORT = 1080  # Порт этой ноды
NODE_TYPE = 'socks5'  # 'http' или 'socks5'
AUTH_TOKEN = 'node_secret_token_123'  # Токен для аутентификации в панели

# --- НАСТРОЙКИ ПРОИЗВОДИТЕЛЬНОСТИ ---
# Для больших нагрузок (100-1000+ пользователей одновременно)
MAX_CONCURRENT_CONNECTIONS = 2000  # Максимальное количество одновременных подключений (увеличено для больших нагрузок)
CONNECTION_TIMEOUT = 30  # Таймаут подключения в секундах
IDLE_TIMEOUT = 300  # Таймаут простоя соединения в секундах
BUFFER_SIZE = 8192  # Размер буфера для передачи данных (8KB для лучшей производительности)
KEEP_ALIVE_INTERVAL = 60  # Интервал для keep-alive проверки (секунды)
RETRY_ON_ERROR = True  # Повторять попытки при временных ошибках
MAX_RETRIES = 2  # Максимальное количество попыток повтора
GRACEFUL_SHUTDOWN = True  # Корректное закрытие соединений (для избежания PR_END_OF_FILE_ERROR)
SHUTDOWN_TIMEOUT = 5  # Таймаут для graceful shutdown (секунды)
WAIT_FOR_REMOTE_CLOSE = False  # Ждать закрытия соединения от удаленной стороны (отключено для стабильности)
LOG_CONNECTIONS = False  # Логировать каждое подключение (ВЫКЛЮЧЕНО для производительности при больших нагрузках)
LOG_DISCONNECTIONS = False  # Логировать завершение соединений (ВЫКЛЮЧЕНО для производительности)
LOG_CONNECTION_RESETS = False  # Логировать "Connection reset by peer" (обычно это нормально)
LOG_SSL_ERRORS = False  # Логировать ошибки SSL/TLS (отключено для производительности при больших нагрузках)
LOG_LEVEL = logging.WARNING  # Уровень логирования: DEBUG, INFO, WARNING, ERROR (WARNING для больших нагрузок)

# Адрес панели управления
PANEL_HOST = '0.0.0.0'  # IP адрес панели управления
PANEL_PORT = 3333
PANEL_URL = f'http://{PANEL_HOST}:{PANEL_PORT}'

# --- КОНФИГУРАЦИЯ XRAY ---
# Вариант 1: Xray работает как SOCKS5 прокси (самый простой)
XRAY_SOCKS5_HOST = '127.0.0.1'  # Адрес Xray SOCKS5 прокси
XRAY_SOCKS5_PORT = 10808  # Порт Xray SOCKS5 прокси

# Вариант 2: Xray работает через другие протоколы (VMess, VLESS, Trojan)
# В этом случае нужно использовать Xray API или подключаться напрямую
XRAY_MODE = 'socks5'  # 'socks5', 'vmess', 'vless', 'trojan', 'auto'

# Вариант 3: Автоматический запуск Xray (если Xray установлен)
AUTO_START_XRAY = True  # Автоматически запускать Xray при старте ноды
XRAY_BINARY_PATH = '/usr/local/bin/xray'  # Путь к исполняемому файлу Xray
XRAY_CONFIG_PATH = '/opt/xray_config.json'  # Путь к конфигу Xray (если None, создается временный)
# Или укажите путь к вашему JSON конфигу: XRAY_CONFIG_PATH = '/path/to/xray_config.json'
# Если указан путь к JSON конфигу, он будет использован (например, 'config.json' или '/path/to/config.json')
# В конфиге должен быть хотя бы один inbound (если нет SOCKS5, он будет добавлен автоматически)

# Настройка логирования
logging.basicConfig(level=LOG_LEVEL, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# Счетчик активных подключений для heartbeat
active_connections_count = 0
connections_lock = threading.Lock()
max_connections_semaphore = threading.Semaphore(MAX_CONCURRENT_CONNECTIONS)

# Процесс Xray (если запущен автоматически)
xray_process = None


class XrayBridgeHandler(threading.Thread):
    """Обработчик прокси-запросов с мостом через Xray."""
    
    def __init__(self, client_sock, client_addr):
        super().__init__()
        self.client_sock = client_sock
        self.client_addr = client_addr
        self.daemon = True
        self.start_time = time.time()
        self.bytes_sent = 0
        self.bytes_received = 0
        self.semaphore_acquired = False
    
    def _increment_connections(self):
        """Увеличивает счетчик активных подключений."""
        global active_connections_count
        # Пытаемся получить семафор (ограничение на количество подключений)
        if max_connections_semaphore.acquire(blocking=False):
            self.semaphore_acquired = True
            with connections_lock:
                active_connections_count += 1
            return True
        else:
            return False
    
    def _decrement_connections(self):
        """Уменьшает счетчик активных подключений."""
        global active_connections_count
        if self.semaphore_acquired:
            with connections_lock:
                active_connections_count = max(0, active_connections_count - 1)
            max_connections_semaphore.release()
            self.semaphore_acquired = False
    
    def run(self):
        """Обрабатывает SOCKS5 подключение."""
        # Семафор уже получен в run_node_server, просто увеличиваем счетчик
        with connections_lock:
            global active_connections_count
            active_connections_count += 1
        self.semaphore_acquired = True
        
        try:
            self.client_sock.settimeout(CONNECTION_TIMEOUT)
            
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
            
            # Логируем подключение только если включено
            if LOG_CONNECTIONS:
                logger.info(f"[XRAY NODE] Подключение к {dest_addr}:{dest_port} от {self.client_addr[0]}")
            
            # Подключение через Xray прокси с retry логикой
            target_sock = None
            retries = 0
            while not target_sock and retries < (MAX_RETRIES if RETRY_ON_ERROR else 1):
                target_sock = self._connect_via_xray(dest_addr, dest_port)
                if not target_sock and retries < MAX_RETRIES - 1:
                    retries += 1
                    time.sleep(0.1 * retries)  # Экспоненциальная задержка
                    if LOG_LEVEL == logging.DEBUG:
                        logger.debug(f"[XRAY NODE] Повтор подключения {retries}/{MAX_RETRIES} к {dest_addr}:{dest_port}")
            
            if not target_sock:
                self.client_sock.sendall(b'\x05\x04\x00\x01\x00\x00\x00\x00\x00\x00')
                return
            
            # Отправка успешного ответа
            self.client_sock.sendall(b'\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00')
            
            # Устанавливаем параметры сокетов для лучшей производительности
            # TCP_NODELAY для уменьшения задержек
            self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            target_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
            
            # SO_KEEPALIVE для поддержания соединения (особенно важно для HTTPS)
            self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
            
            # TCP_KEEPIDLE, TCP_KEEPINTVL, TCP_KEEPCNT для лучшей работы keep-alive (если доступно)
            try:
                # Linux
                import socket as socket_module
                if hasattr(socket_module, 'TCP_KEEPIDLE'):
                    self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                    target_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPIDLE, 60)
                if hasattr(socket_module, 'TCP_KEEPINTVL'):
                    self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                    target_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPINTVL, 10)
                if hasattr(socket_module, 'TCP_KEEPCNT'):
                    self.client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
                    target_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_KEEPCNT, 3)
            except:
                pass  # Опции keep-alive не доступны на всех системах
            
            # Увеличиваем размер буферов для лучшей производительности
            try:
                self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                self.client_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
                target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
                target_sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
            except:
                pass  # Некоторые системы могут не поддерживать изменение размера буфера
            
            # Для HTTPS соединений (порт 443) увеличиваем таймауты
            is_https = dest_port == 443
            read_timeout = IDLE_TIMEOUT * 2 if is_https else IDLE_TIMEOUT
            
            # Устанавливаем таймауты для передачи данных
            self.client_sock.settimeout(read_timeout)
            target_sock.settimeout(read_timeout)
            
            # Релей данных
            self._relay_data(target_sock)
            
        except socket.timeout:
            if LOG_CONNECTIONS:
                logger.debug(f"[XRAY NODE] Таймаут соединения с {self.client_addr[0]}")
        except ConnectionResetError as e:
            # Connection reset by peer - это нормально, когда удаленная сторона закрывает соединение
            if LOG_CONNECTION_RESETS:
                logger.debug(f"[XRAY NODE] Соединение сброшено удаленной стороной: {self.client_addr[0]}")
        except BrokenPipeError:
            # Broken pipe - клиент закрыл соединение
            if LOG_CONNECTIONS:
                logger.debug(f"[XRAY NODE] Клиент закрыл соединение: {self.client_addr[0]}")
        except OSError as e:
            # Обработка специфичных ошибок ОС
            if e.errno == 104:  # Connection reset by peer
                if LOG_CONNECTION_RESETS:
                    logger.debug(f"[XRAY NODE] Connection reset by peer: {self.client_addr[0]}")
            elif e.errno == 32:  # Broken pipe
                if LOG_CONNECTIONS:
                    logger.debug(f"[XRAY NODE] Broken pipe: {self.client_addr[0]}")
            else:
                logger.error(f"[XRAY NODE ERROR] OSError {e.errno}: {e}")
        except Exception as e:
            # Логируем только серьезные ошибки
            error_str = str(e)
            if 'Connection reset' not in error_str and 'Broken pipe' not in error_str:
                logger.error(f"[XRAY NODE ERROR] {e}")
        finally:
            self.cleanup()
    
    def _connect_via_xray(self, dest_addr, dest_port):
        """Подключается к целевому серверу через Xray."""
        try:
            if XRAY_MODE == 'socks5':
                # Используем PySocks для подключения через Xray SOCKS5
                try:
                    import socks
                    target_sock = socks.socksocket()
                    target_sock.set_proxy(socks.SOCKS5, XRAY_SOCKS5_HOST, XRAY_SOCKS5_PORT)
                    target_sock.settimeout(CONNECTION_TIMEOUT)
                    target_sock.connect((dest_addr, dest_port))
                    return target_sock
                except ImportError:
                    logger.error("[XRAY NODE] Ошибка: PySocks не установлен. Установите: pip install PySocks")
                    return None
                except Exception as e:
                    if LOG_CONNECTIONS:
                        logger.debug(f"[XRAY NODE] Ошибка подключения через Xray SOCKS5 к {dest_addr}:{dest_port}: {e}")
                    return None
            else:
                # Для других протоколов (VMess, VLESS, Trojan) нужна специальная библиотека
                # Пока используем SOCKS5 как fallback
                logger.warning(f"[XRAY NODE] Протокол {XRAY_MODE} требует специальной библиотеки. Используем SOCKS5.")
                try:
                    import socks
                    target_sock = socks.socksocket()
                    target_sock.set_proxy(socks.SOCKS5, XRAY_SOCKS5_HOST, XRAY_SOCKS5_PORT)
                    target_sock.settimeout(CONNECTION_TIMEOUT)
                    target_sock.connect((dest_addr, dest_port))
                    return target_sock
                except Exception as e:
                    if LOG_CONNECTIONS:
                        logger.debug(f"[XRAY NODE] Ошибка подключения к {dest_addr}:{dest_port}: {e}")
                    return None
        except Exception as e:
            logger.error(f"[XRAY NODE] Ошибка _connect_via_xray: {e}")
            return None
    
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
        """Передает данные между клиентом и целевым сервером через Xray с оптимизацией."""
        sockets = [self.client_sock, target_sock]
        last_activity = time.time()
        
        while True:
            try:
                # Используем select с таймаутом для проверки активности
                rlist, wlist, xlist = select.select(sockets, [], sockets, KEEP_ALIVE_INTERVAL)
                
                # Проверка на исключения
                if xlist:
                    break
                
                # Проверка активности соединения
                current_time = time.time()
                if current_time - last_activity > IDLE_TIMEOUT:
                    if LOG_CONNECTIONS:
                        logger.debug(f"[XRAY NODE] Таймаут простоя соединения с {self.client_addr[0]}")
                    break
                
                # Обработка данных
                if rlist:
                    for sock in rlist:
                        from_sock = sock
                        to_sock = target_sock if sock is self.client_sock else self.client_sock
                        
                        try:
                            # Используем увеличенный буфер для лучшей производительности
                            data = from_sock.recv(BUFFER_SIZE)
                            
                            if data:
                                last_activity = current_time
                                # Отправка данных с обработкой ошибок
                                try:
                                    to_sock.sendall(data)
                                    # Обновление статистики
                                    if sock is self.client_sock:
                                        self.bytes_received += len(data)
                                    else:
                                        self.bytes_sent += len(data)
                                except (ConnectionResetError, BrokenPipeError, OSError) as e:
                                    # Обработка ошибок отправки
                                    if isinstance(e, OSError) and e.errno in (104, 32):
                                        # Connection reset или broken pipe - соединение закрыто
                                        return
                                    raise
                            else:
                                # Нет данных - соединение закрыто корректно
                                # При закрытии одной стороны завершаем соединение
                                return
                                
                        except (ConnectionResetError, BrokenPipeError):
                            # Нормальное закрытие соединения - завершаем
                            return
                                
                        except OSError as e:
                            # Обработка специфичных ошибок ОС
                            if e.errno == 104:  # Connection reset by peer
                                # Для HTTPS это может быть проблемой - логируем
                                if LOG_SSL_ERRORS and self.client_addr:
                                    try:
                                        if LOG_LEVEL <= logging.WARNING:
                                            logger.warning(f"[XRAY NODE] Connection reset для {self.client_addr[0]} - возможен PR_END_OF_FILE_ERROR")
                                    except:
                                        pass
                                return
                            elif e.errno == 32:  # Broken pipe
                                return
                            elif e.errno == 11:  # Resource temporarily unavailable (EAGAIN)
                                continue  # Продолжаем работу
                            else:
                                # Другие ошибки - логируем только в debug режиме
                                if LOG_LEVEL == logging.DEBUG:
                                    logger.debug(f"[XRAY NODE] OSError в relay: {e}")
                                return
                        except socket.timeout:
                            # Таймаут на чтение - проверяем активность
                            continue
                        except Exception as e:
                            # Неизвестные ошибки
                            if LOG_LEVEL == logging.DEBUG:
                                logger.debug(f"[XRAY NODE] Ошибка в relay: {e}")
                            return
                else:
                    # Нет данных для чтения - проверяем, не истек ли таймаут простоя
                    if current_time - last_activity > IDLE_TIMEOUT:
                        break
                        
            except (ConnectionResetError, BrokenPipeError):
                return
            except OSError as e:
                if e.errno in (104, 32):  # Connection reset or broken pipe
                    return
                if LOG_LEVEL == logging.DEBUG:
                    logger.debug(f"[XRAY NODE] OSError в select: {e}")
                return
            except Exception as e:
                if LOG_LEVEL == logging.DEBUG:
                    logger.debug(f"[XRAY NODE] Неожиданная ошибка в relay: {e}")
                break
        
        # Graceful shutdown - корректное закрытие соединений
        if GRACEFUL_SHUTDOWN:
            self._graceful_shutdown(target_sock)
        else:
            try:
                if target_sock:
                    target_sock.close()
            except:
                pass
    
    def _graceful_shutdown(self, target_sock):
        """Корректное закрытие соединений для избежания PR_END_OF_FILE_ERROR."""
        try:
            # Закрываем соединения в правильном порядке
            # Сначала закрываем запись на обеих сторонах, чтобы дать возможность отправить все данные
            try:
                if target_sock:
                    target_sock.shutdown(socket.SHUT_WR)  # Закрываем запись на целевом сокете
            except (OSError, ConnectionResetError, BrokenPipeError):
                pass  # Сокет уже закрыт
            
            try:
                if self.client_sock:
                    self.client_sock.shutdown(socket.SHUT_WR)  # Закрываем запись на клиентском сокете
            except (OSError, ConnectionResetError, BrokenPipeError):
                pass  # Сокет уже закрыт
            
            # Ждем немного для отправки всех данных (только если включено ожидание)
            if WAIT_FOR_REMOTE_CLOSE:
                time.sleep(0.05)  # Уменьшили время ожидания
            
            # Полное закрытие соединений
            try:
                if target_sock:
                    target_sock.close()
            except:
                pass
            
            try:
                if self.client_sock:
                    self.client_sock.close()
            except:
                pass
                    
        except Exception:
            # При любых ошибках просто закрываем соединения
            try:
                if target_sock:
                    target_sock.close()
                if self.client_sock:
                    self.client_sock.close()
            except:
                pass
    
    def cleanup(self):
        """Очистка ресурсов."""
        duration = time.time() - self.start_time
        total_bytes = self.bytes_sent + self.bytes_received
        
        # Логируем завершение только если включено
        if LOG_DISCONNECTIONS and total_bytes > 0:
            logger.debug(f"[XRAY NODE] Соединение завершено: {duration:.2f}s, {total_bytes} bytes")
        
        # Закрываем соединения
        if self.client_sock:
            try:
                self.client_sock.close()
            except:
                pass
        
        # Освобождаем ресурсы подключения
        self._decrement_connections()


def load_xray_config(config_path=None):
    """Загружает конфигурацию Xray из JSON файла."""
    if config_path and os.path.exists(config_path):
        try:
            with open(config_path, 'r', encoding='utf-8') as f:
                config = json.load(f)
            logger.info(f"[XRAY] Конфигурация загружена из: {config_path}")
            return config
        except Exception as e:
            logger.error(f"[XRAY] Ошибка загрузки конфигурации из {config_path}: {e}")
            return None
    return None


def ensure_socks5_inbound(config):
    """Проверяет наличие SOCKS5 inbound в конфиге и добавляет его если нет."""
    if 'inbounds' not in config:
        config['inbounds'] = []
    
    # Проверяем, есть ли уже SOCKS5 inbound
    has_socks5 = False
    for inbound in config['inbounds']:
        if inbound.get('protocol') == 'socks':
            has_socks5 = True
            # Обновляем порт если нужно
            if inbound.get('port') != XRAY_SOCKS5_PORT:
                inbound['port'] = XRAY_SOCKS5_PORT
                logger.info(f"[XRAY] Порт SOCKS5 inbound обновлен на {XRAY_SOCKS5_PORT}")
            # Убеждаемся что есть tag
            if 'tag' not in inbound:
                inbound['tag'] = 'socks5-for-node'
            break
    
    # Если SOCKS5 нет, добавляем его
    if not has_socks5:
        socks5_inbound = {
            "port": XRAY_SOCKS5_PORT,
            "listen": "127.0.0.1",
            "protocol": "socks",
            "settings": {
                "auth": "noauth",
                "udp": True,
                "ip": "127.0.0.1"
            },
            "tag": "socks5-for-node"
        }
        config['inbounds'].insert(0, socks5_inbound)  # Добавляем в начало
        logger.info(f"[XRAY] SOCKS5 inbound добавлен на порт {XRAY_SOCKS5_PORT}")
    
    return config


def ensure_routing_for_socks5(config):
    """Проверяет и добавляет routing rules для SOCKS5 inbound, чтобы использовать правильный outbound."""
    if 'routing' not in config:
        config['routing'] = {}
    
    if 'rules' not in config['routing']:
        config['routing']['rules'] = []
    
    # Ищем существующие outbounds, чтобы определить какой использовать
    default_outbound = None
    shadowsocks_outbound = None
    
    if 'outbounds' in config:
        # Ищем Shadowsocks, VMess, VLESS, Trojan outbounds (приоритет Shadowsocks)
        for outbound in config['outbounds']:
            tag = outbound.get('tag', '')
            protocol = outbound.get('protocol', '')
            
            # Приоритет: Shadowsocks > VMess > VLESS > Trojan
            if protocol == 'shadowsocks':
                shadowsocks_outbound = tag if tag else 'SHADOWSOCKS_REMOTE'
                if not default_outbound:
                    default_outbound = shadowsocks_outbound
            elif protocol == 'vmess' and not default_outbound:
                default_outbound = tag if tag else 'VMESS_REMOTE'
            elif protocol == 'vless' and not default_outbound:
                default_outbound = tag if tag else 'VLESS_REMOTE'
            elif protocol == 'trojan' and not default_outbound:
                default_outbound = tag if tag else 'TROJAN_REMOTE'
        
        # Если нашли Shadowsocks, используем его
        if shadowsocks_outbound:
            default_outbound = shadowsocks_outbound
    
    # Если не нашли прокси outbound, оставляем None (будет использован первый outbound или DIRECT)
    if not default_outbound:
        default_outbound = 'DIRECT'
    
    # Проверяем, есть ли уже правило для SOCKS5 inbound
    has_socks5_rule = False
    for rule in config['routing']['rules']:
        inbound_tag = rule.get('inboundTag', [])
        if isinstance(inbound_tag, str):
            inbound_tag = [inbound_tag]
        if 'socks5-for-node' in inbound_tag:
            has_socks5_rule = True
            logger.info(f"[XRAY] Routing rule для SOCKS5 уже существует: {rule.get('outboundTag', 'N/A')}")
            break
    
    # Если правила нет, добавляем его
    if not has_socks5_rule and default_outbound != 'DIRECT':
        # Добавляем правило в начало (высокий приоритет)
        config['routing']['rules'].insert(0, {
            "type": "field",
            "inboundTag": ["socks5-for-node"],
            "outboundTag": default_outbound
        })
        logger.info(f"[XRAY] Добавлено routing rule: SOCKS5 inbound → {default_outbound}")
    elif not has_socks5_rule:
        logger.warning(f"[XRAY] Не найден прокси outbound, будет использован DIRECT. Проверьте конфиг Xray.")
    
    # Убеждаемся, что есть domainStrategy
    if 'domainStrategy' not in config['routing']:
        config['routing']['domainStrategy'] = 'AsIs'
    
    return config


def create_xray_config():
    """Создает или загружает конфигурационный файл для Xray."""
    config = None
    
    # Пытаемся загрузить внешний конфиг
    if XRAY_CONFIG_PATH and os.path.exists(XRAY_CONFIG_PATH):
        config = load_xray_config(XRAY_CONFIG_PATH)
    
    # Если конфиг не загружен, создаем базовый
    if config is None:
        logger.info("[XRAY] Создание базовой конфигурации Xray")
        config = {
            "log": {
                "loglevel": "warning"
            },
            "inbounds": [
                {
                    "port": XRAY_SOCKS5_PORT,
                    "listen": "127.0.0.1",
                    "protocol": "socks",
                    "settings": {
                        "auth": "noauth",
                        "udp": True
                    }
                }
            ],
            "outbounds": [
                {
                    "protocol": "freedom",
                    "settings": {}
                }
            ]
        }
    else:
        # Если загружен внешний конфиг, проверяем наличие SOCKS5 inbound
        config = ensure_socks5_inbound(config)
        # Проверяем и добавляем routing rules для SOCKS5 inbound
        config = ensure_routing_for_socks5(config)
    
    # Определяем путь для сохранения конфига
    if XRAY_CONFIG_PATH and os.path.exists(XRAY_CONFIG_PATH):
        # Если указан существующий файл, используем его
        config_file = XRAY_CONFIG_PATH
        # Сохраняем обновленную конфигурацию (с добавленным SOCKS5 если нужно)
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        logger.info(f"[XRAY] Конфигурация сохранена: {config_file}")
    else:
        # Создаем временный файл
        temp_file = tempfile.NamedTemporaryFile(mode='w', suffix='.json', delete=False, encoding='utf-8')
        config_file = temp_file.name
        temp_file.close()
        
        with open(config_file, 'w', encoding='utf-8') as f:
            json.dump(config, f, indent=2, ensure_ascii=False)
        
        logger.info(f"[XRAY] Временный конфигурационный файл создан: {config_file}")
    
    return config_file


def start_xray():
    """Запускает Xray процесс (если включен AUTO_START_XRAY)."""
    global xray_process
    
    if not AUTO_START_XRAY:
        return False
    
    if not os.path.exists(XRAY_BINARY_PATH):
        logger.warning(f"[XRAY] Xray не найден по пути: {XRAY_BINARY_PATH}")
        logger.warning("[XRAY] Убедитесь, что Xray установлен, или установите AUTO_START_XRAY = False")
        return False
    
    try:
        config_file = create_xray_config()
        
        # Запускаем Xray
        xray_process = subprocess.Popen(
            [XRAY_BINARY_PATH, 'run', '-config', config_file],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE
        )
        
        # Даем время на запуск
        time.sleep(2)
        
        # Проверяем, что процесс запущен
        if xray_process.poll() is None:
            logger.info(f"[XRAY] Xray успешно запущен (PID: {xray_process.pid})")
            logger.info(f"[XRAY] SOCKS5 прокси доступен на {XRAY_SOCKS5_HOST}:{XRAY_SOCKS5_PORT}")
            return True
        else:
            stdout, stderr = xray_process.communicate()
            logger.error(f"[XRAY] Ошибка запуска Xray: {stderr.decode()}")
            return False
    except Exception as e:
        logger.error(f"[XRAY] Ошибка при запуске Xray: {e}")
        return False


def stop_xray():
    """Останавливает Xray процесс."""
    global xray_process
    
    if xray_process:
        try:
            xray_process.terminate()
            xray_process.wait(timeout=5)
            logger.info("[XRAY] Xray остановлен")
        except subprocess.TimeoutExpired:
            xray_process.kill()
            logger.warning("[XRAY] Xray принудительно остановлен")
        except Exception as e:
            logger.error(f"[XRAY] Ошибка при остановке Xray: {e}")
        finally:
            xray_process = None


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
                'proxy_technology': 'xray',
                'auth_token': AUTH_TOKEN,
                'max_connections': MAX_CONCURRENT_CONNECTIONS  # Отправляем максимальное количество подключений
            },
            timeout=5
        )
        if response.status_code == 200:
            logger.info(f"[XRAY NODE] Успешно зарегистрирована в панели (max_connections: {MAX_CONCURRENT_CONNECTIONS})")
            return True
        else:
            logger.error(f"[XRAY NODE] Ошибка регистрации: {response.status_code} - {response.text}")
            return False
    except Exception as e:
        logger.error(f"[XRAY NODE] Не удалось подключиться к панели: {e}")
        return False


def send_heartbeat():
    """Отправляет heartbeat в панель управления."""
    while True:
        try:
            time.sleep(30)  # Каждые 30 секунд
            
            # Получаем количество активных подключений
            with connections_lock:
                current_connections = active_connections_count
            
            # Логируем статистику каждые 5 минут (10 heartbeat'ов)
            if current_connections > MAX_CONCURRENT_CONNECTIONS * 0.8:
                logger.warning(f"[XRAY NODE] Высокая нагрузка: {current_connections}/{MAX_CONCURRENT_CONNECTIONS} подключений")
            
            response = requests.post(
                f'{PANEL_URL}/api/node/heartbeat',
                json={
                    'node_id': NODE_ID,
                    'auth_token': AUTH_TOKEN,
                    'current_connections': current_connections
                },
                timeout=10  # Увеличили таймаут до 10 секунд
            )
            
            if response.status_code == 200:
                if LOG_LEVEL == logging.DEBUG:
                    logger.debug(f"[XRAY NODE] Heartbeat отправлен (подключений: {current_connections})")
            else:
                logger.warning(f"[XRAY NODE] Ошибка heartbeat: {response.status_code} - {response.text[:100]}")
        except requests.exceptions.Timeout:
            logger.warning(f"[XRAY NODE] Таймаут при отправке heartbeat к {PANEL_URL}")
        except Exception as e:
            logger.warning(f"[XRAY NODE] Ошибка отправки heartbeat: {e}")


def run_node_server():
    """Запускает прокси-сервер ноды."""
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    # Увеличиваем размер очереди подключений
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_RCVBUF, 65536)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536)
    
    try:
        server_socket.bind((NODE_HOST, NODE_PORT))
        # Оптимизированная очередь подключений для больших нагрузок (100-1000+ пользователей)
        # Используем большую очередь для обработки пиковых нагрузок
        listen_queue = min(MAX_CONCURRENT_CONNECTIONS // 2, 1000)
        server_socket.listen(listen_queue)
        
        # Делаем accept неблокирующим для проверки доступности слотов
        server_socket.settimeout(0.1)  # Минимальный таймаут для accept для максимальной производительности
        
        logger.info(f"[XRAY NODE] Прокси-сервер запущен на {NODE_HOST}:{NODE_PORT}")
        logger.info(f"[XRAY NODE] Максимум одновременных подключений: {MAX_CONCURRENT_CONNECTIONS}")
        logger.info(f"[XRAY NODE] Размер очереди подключений: {listen_queue}")
        logger.info(f"[XRAY NODE] Таймаут подключения: {CONNECTION_TIMEOUT}s, Таймаут простоя: {IDLE_TIMEOUT}s")
        
        if XRAY_MODE == 'socks5':
            logger.info(f"[XRAY NODE] Трафик проксируется через Xray SOCKS5: {XRAY_SOCKS5_HOST}:{XRAY_SOCKS5_PORT}")
        else:
            logger.info(f"[XRAY NODE] Режим Xray: {XRAY_MODE}")
        
        consecutive_rejects = 0  # Счетчик последовательных отклонений
        
        while True:
            try:
                # Проверяем доступность слотов перед accept
                with connections_lock:
                    current_connections = active_connections_count
                
                # Пытаемся принять подключение (принимаем всегда, проверяем лимит после)
                try:
                    client_sock, client_addr = server_socket.accept()
                except socket.timeout:
                    # Таймаут - нормально, продолжаем цикл
                    continue
                except OSError as e:
                    # Если ошибка из-за перегрузки, просто продолжаем
                    if e.errno in (24, 23):  # Too many open files / Too many files open
                        logger.error(f"[XRAY NODE] Превышен лимит открытых файлов. Текущие подключения: {current_connections}")
                        time.sleep(0.1)
                    continue
                
                # Проверяем семафор перед обработкой (быстрая проверка)
                if max_connections_semaphore.acquire(blocking=False):
                    # Есть свободный слот - обрабатываем подключение
                    try:
                        # Устанавливаем TCP_NODELAY для уменьшения задержек
                        client_sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                        handler = XrayBridgeHandler(client_sock, client_addr)
                        handler.start()
                    except Exception as e:
                        max_connections_semaphore.release()
                        logger.error(f"[XRAY NODE ERROR] Ошибка при запуске обработчика: {e}")
                        try:
                            client_sock.close()
                        except:
                            pass
                else:
                    # Нет свободных слотов - быстро отклоняем подключение
                    try:
                        # Отправляем быстрый отказ (для SOCKS5)
                        client_sock.sendall(b'\x05\xFF')  # No acceptable methods
                        client_sock.close()
                    except:
                        pass
                    
                    consecutive_rejects += 1
                    if consecutive_rejects % 50 == 0:
                        with connections_lock:
                            current = active_connections_count
                        logger.warning(f"[XRAY NODE] Превышен лимит подключений. Отклонено подключение от {client_addr[0] if 'client_addr' in locals() else 'unknown'}. Активных: {current}/{MAX_CONCURRENT_CONNECTIONS}")
                
            except KeyboardInterrupt:
                break
            except Exception as e:
                logger.error(f"[XRAY NODE ERROR] {e}")
                time.sleep(0.1)  # Небольшая пауза при ошибке
                
    except Exception as e:
        logger.error(f"[XRAY NODE FATAL] Не удалось запустить сервер: {e}")
    finally:
        server_socket.close()


def main():
    """Главная функция."""
    logger.info("=" * 60)
    logger.info("XRAY NODE - Нода с интеграцией Xray")
    logger.info("=" * 60)
    logger.info(f"Node ID: {NODE_ID}")
    logger.info(f"Node Name: {NODE_NAME}")
    logger.info(f"Listening on: {NODE_HOST}:{NODE_PORT}")
    logger.info(f"Xray Mode: {XRAY_MODE}")
    logger.info(f"Xray SOCKS5: {XRAY_SOCKS5_HOST}:{XRAY_SOCKS5_PORT}")
    logger.info(f"Panel URL: {PANEL_URL}")
    logger.info("=" * 60)
    
    # Проверка PySocks (для SOCKS5 режима)
    if XRAY_MODE == 'socks5':
        try:
            import socks
            logger.info("[XRAY NODE] PySocks установлен ✓")
        except ImportError:
            logger.error("[XRAY NODE] ОШИБКА: PySocks не установлен!")
            logger.error("[XRAY NODE] Установите: pip install PySocks")
            sys.exit(1)
    
    # Автоматический запуск Xray (если включен)
    if AUTO_START_XRAY:
        if XRAY_CONFIG_PATH:
            logger.info(f"[XRAY NODE] Используется конфигурационный файл: {XRAY_CONFIG_PATH}")
            if not os.path.exists(XRAY_CONFIG_PATH):
                logger.warning(f"[XRAY NODE] Файл конфигурации не найден: {XRAY_CONFIG_PATH}")
                logger.warning("[XRAY NODE] Будет создан базовый конфиг")
        if not start_xray():
            logger.warning("[XRAY NODE] Не удалось запустить Xray автоматически. Продолжаем работу...")
            logger.warning("[XRAY NODE] Убедитесь, что Xray запущен вручную или установите AUTO_START_XRAY = False")
    
    # Регистрация в панели
    if not register_with_panel():
        logger.warning("[XRAY NODE] Не удалось зарегистрироваться в панели. Продолжаем работу...")
    
    # Запуск heartbeat в отдельном потоке
    heartbeat_thread = threading.Thread(target=send_heartbeat, daemon=True)
    heartbeat_thread.start()
    
    # Запуск прокси-сервера
    try:
        run_node_server()
    except KeyboardInterrupt:
        logger.info("\n[XRAY NODE] Сервер остановлен пользователем")
        stop_xray()


if __name__ == '__main__':
    # Проверка зависимостей
    try:
        import requests
    except ImportError:
        print("ОШИБКА: Установите requests: pip install requests")
        sys.exit(1)
    
    main()

