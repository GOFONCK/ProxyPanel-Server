"""
Модуль для работы с базой данных
Расширенная схема: пользователи, ноды, назначения, статистика
"""
import sqlite3
import hashlib
import threading
from datetime import datetime

DB_FILE = 'proxy_panel.db'
db_lock = threading.Lock()

def get_db_connection():
    """Создает и возвращает новое соединение с БД для потока."""
    conn = sqlite3.connect(DB_FILE, check_same_thread=False, timeout=5.0)
    conn.row_factory = sqlite3.Row
    # Устанавливаем таймауты для избежания блокировок
    conn.execute("PRAGMA busy_timeout = 3000")
    conn.execute("PRAGMA journal_mode = WAL")  # WAL режим для лучшей производительности
    return conn

def setup_database():
    """Инициализирует все таблицы базы данных."""
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
                created_at DATETIME DEFAULT (datetime('now', 'localtime'))
            )
        ''')
        
        # 2. Таблица нод (прокси-серверов)
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS nodes (
                node_id TEXT PRIMARY KEY,
                name TEXT NOT NULL,
                host TEXT NOT NULL,
                port INTEGER NOT NULL,
                node_type TEXT NOT NULL DEFAULT 'http',  -- 'http' или 'socks5'
                proxy_technology TEXT DEFAULT 'standard',  -- 'standard', 'shadowsocks', 'xray'
                is_active BOOLEAN NOT NULL DEFAULT 1,
                max_connections INTEGER NOT NULL DEFAULT 100,
                current_connections INTEGER NOT NULL DEFAULT 0,
                last_seen DATETIME,
                registered_at DATETIME DEFAULT (datetime('now', 'localtime')),
                auth_token TEXT NOT NULL  -- Токен для аутентификации ноды
            )
        ''')
        
        # Миграция: добавляем поле proxy_technology если его нет
        try:
            cursor.execute("ALTER TABLE nodes ADD COLUMN proxy_technology TEXT DEFAULT 'standard'")
            conn.commit()
        except sqlite3.OperationalError:
            # Колонка уже существует
            pass
        
        # 3. Таблица назначений нод пользователям
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS user_nodes (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                node_id TEXT NOT NULL,
                assigned_at DATETIME DEFAULT (datetime('now', 'localtime')),
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE CASCADE,
                UNIQUE(username, node_id)
            )
        ''')
        
        # 4. Таблица активных сессий
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS active_sessions (
                username TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                node_id TEXT,
                session_start DATETIME DEFAULT (datetime('now', 'localtime')),
                PRIMARY KEY (username, client_ip)
            )
        ''')
        
        # 5. Таблица статистики трафика
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_stats (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                username TEXT NOT NULL,
                node_id TEXT,
                date DATE NOT NULL,
                bytes_sent INTEGER NOT NULL DEFAULT 0,
                bytes_received INTEGER NOT NULL DEFAULT 0,
                connections_count INTEGER NOT NULL DEFAULT 0,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE,
                FOREIGN KEY (node_id) REFERENCES nodes(node_id) ON DELETE SET NULL
            )
        ''')
        
        # 6. Таблица логов подключений
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS connection_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
                username TEXT NOT NULL,
                client_ip TEXT NOT NULL,
                node_id TEXT,
                destination TEXT NOT NULL,
                duration_sec REAL,
                bytes_sent INTEGER DEFAULT 0,
                bytes_received INTEGER DEFAULT 0,
                status TEXT NOT NULL
            )
        ''')
        
        # 7. Таблица истории действий администратора
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS admin_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
                action_type TEXT NOT NULL,
                admin_username TEXT NOT NULL,
                target_type TEXT,
                target_id TEXT,
                description TEXT,
                ip_address TEXT
            )
        ''')
        
        # 8. Таблица квот трафика
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS traffic_quotas (
                username TEXT PRIMARY KEY,
                monthly_limit_gb REAL DEFAULT 0,
                current_usage_gb REAL DEFAULT 0,
                reset_date DATE,
                FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
            )
        ''')
        
        # Создание индексов для производительности
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_nodes_username ON user_nodes(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_user_nodes_node_id ON user_nodes(node_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_traffic_stats_date ON traffic_stats(date)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_connection_logs_username ON connection_logs(username)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_connection_logs_node_id ON connection_logs(node_id)')
        cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_actions_timestamp ON admin_actions(timestamp)')
        
        # Создание админа по умолчанию
        admin_username = 'admin'
        admin_password = 'admin123'  # СМЕНИТЕ ПАРОЛЬ!
        admin_password_hash = hashlib.sha256(admin_password.encode()).hexdigest()
        
        try:
            cursor.execute("INSERT INTO users (username, password, is_active, device_limit) VALUES (?, ?, ?, ?)", 
                          (admin_username, admin_password_hash, 1, 10))
            print(f"[DB] Создан администратор: {admin_username}")
        except sqlite3.IntegrityError:
            pass  # Админ уже существует
    
    conn.commit()
    conn.close()
    
    print("[DB] База данных инициализирована успешно")

def migrate_database():
    """Миграция БД - создание новых таблиц если их нет."""
    try:
        conn = get_db_connection()
        cursor = conn.cursor()
        
        # Проверяем существование таблиц быстро
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_actions'")
        has_admin_actions = cursor.fetchone() is not None
        
        cursor.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='traffic_quotas'")
        has_traffic_quotas = cursor.fetchone() is not None
        
        if not has_admin_actions or not has_traffic_quotas:
            with db_lock:
                if not has_admin_actions:
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS admin_actions (
                            id INTEGER PRIMARY KEY AUTOINCREMENT,
                            timestamp DATETIME DEFAULT (datetime('now', 'localtime')),
                            action_type TEXT NOT NULL,
                            admin_username TEXT NOT NULL,
                            target_type TEXT,
                            target_id TEXT,
                            description TEXT,
                            ip_address TEXT
                        )
                    ''')
                    cursor.execute('CREATE INDEX IF NOT EXISTS idx_admin_actions_timestamp ON admin_actions(timestamp)')
                
                if not has_traffic_quotas:
                    cursor.execute('''
                        CREATE TABLE IF NOT EXISTS traffic_quotas (
                            username TEXT PRIMARY KEY,
                            monthly_limit_gb REAL DEFAULT 0,
                            current_usage_gb REAL DEFAULT 0,
                            reset_date DATE,
                            FOREIGN KEY (username) REFERENCES users(username) ON DELETE CASCADE
                        )
                    ''')
                
                conn.commit()
        conn.close()
    except Exception as e:
        print(f"[DB WARNING] Ошибка миграции: {e}")

# =================================================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С ПОЛЬЗОВАТЕЛЯМИ
# =================================================================

def authenticate_user(username, password):
    """Проверяет учетные данные пользователя."""
    conn = get_db_connection()
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    
    with db_lock:
        cursor = conn.execute(
            "SELECT * FROM users WHERE username = ? AND password = ? AND is_active = 1",
            (username, password_hash)
        )
        user = cursor.fetchone()
    
    conn.close()
    return dict(user) if user else None

def get_all_users():
    """Получает список всех пользователей."""
    try:
        conn = get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")
        with db_lock:
            # Проверяем существование таблицы
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
            if cursor.fetchone():
                cursor = conn.execute("SELECT * FROM users ORDER BY username LIMIT 1000")
                users = [dict(row) for row in cursor.fetchall()]
            else:
                users = []
        conn.close()
        return users
    except Exception as e:
        print(f"[DB ERROR get_all_users] {e}")
        return []

def get_user_nodes(username):
    """Получает список назначенных нод для пользователя."""
    conn = get_db_connection()
    with db_lock:
        cursor = conn.execute('''
            SELECT n.* FROM nodes n
            INNER JOIN user_nodes un ON n.node_id = un.node_id
            WHERE un.username = ? AND n.is_active = 1
            ORDER BY un.assigned_at DESC
        ''', (username,))
        nodes = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return nodes

def assign_node_to_user(username, node_id, replace_existing=True):
    """
    Назначает ноду пользователю.
    Если replace_existing=True, удаляет все старые назначения и назначает новую.
    Если replace_existing=False, добавляет ноду (если еще не назначена).
    """
    conn = get_db_connection()
    try:
        with db_lock:
            # Проверяем существование пользователя и ноды
            user_check = conn.execute("SELECT 1 FROM users WHERE username = ?", (username,)).fetchone()
            node_check = conn.execute("SELECT 1 FROM nodes WHERE node_id = ?", (node_id,)).fetchone()
            
            if not user_check:
                return False, "User not found"
            if not node_check:
                return False, "Node not found"
            
            # Если нужно заменить существующие назначения
            if replace_existing:
                # Удаляем все старые назначения для этого пользователя
                conn.execute("DELETE FROM user_nodes WHERE username = ?", (username,))
            
            # Проверяем, не назначена ли уже эта нода
            existing = conn.execute(
                "SELECT 1 FROM user_nodes WHERE username = ? AND node_id = ?",
                (username, node_id)
            ).fetchone()
            
            if existing:
                # Обновляем время назначения
                conn.execute(
                    "UPDATE user_nodes SET assigned_at = datetime('now', 'localtime') WHERE username = ? AND node_id = ?",
                    (username, node_id)
                )
            else:
                # Добавляем новое назначение
                conn.execute(
                    "INSERT INTO user_nodes (username, node_id, assigned_at) VALUES (?, ?, datetime('now', 'localtime'))",
                    (username, node_id)
                )
            
            conn.commit()
        return True, "OK"
    except Exception as e:
        print(f"[DB ERROR] Ошибка назначения ноды: {e}")
        return False, str(e)
    finally:
        conn.close()

def unassign_node_from_user(username, node_id):
    """Удаляет назначение ноды пользователю."""
    conn = get_db_connection()
    with db_lock:
        conn.execute(
            "DELETE FROM user_nodes WHERE username = ? AND node_id = ?",
            (username, node_id)
        )
        conn.commit()
    conn.close()

# =================================================================
# ФУНКЦИИ ДЛЯ РАБОТЫ С НОДАМИ
# =================================================================

def register_node(node_id, name, host, port, node_type, auth_token, proxy_technology='standard', max_connections=500):
    """Регистрирует новую ноду или обновляет существующую."""
    conn = get_db_connection()
    with db_lock:
        cursor = conn.execute('''
            INSERT INTO nodes (node_id, name, host, port, node_type, proxy_technology, auth_token, last_seen, max_connections)
            VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now', 'localtime'), ?)
            ON CONFLICT(node_id) DO UPDATE SET
                name = excluded.name,
                host = excluded.host,
                port = excluded.port,
                node_type = excluded.node_type,
                proxy_technology = excluded.proxy_technology,
                last_seen = datetime('now', 'localtime'),
                max_connections = COALESCE(excluded.max_connections, max_connections, 500)
        ''', (node_id, name, host, port, node_type, proxy_technology, auth_token, max_connections))
        conn.commit()
    conn.close()

def get_node_by_id(node_id):
    """Получает информацию о ноде по ID."""
    conn = get_db_connection()
    with db_lock:
        cursor = conn.execute("SELECT * FROM nodes WHERE node_id = ?", (node_id,))
        node = cursor.fetchone()
    conn.close()
    return dict(node) if node else None

def get_all_nodes():
    """Получает список всех нод."""
    try:
        conn = get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")
        with db_lock:
            # Проверяем существование таблицы
            cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nodes'")
            if cursor.fetchone():
                cursor = conn.execute("SELECT * FROM nodes ORDER BY name LIMIT 1000")
                nodes = [dict(row) for row in cursor.fetchall()]
            else:
                nodes = []
        conn.close()
        return nodes
    except Exception as e:
        print(f"[DB ERROR get_all_nodes] {e}")
        return []

def update_node_status(node_id, is_active):
    """Обновляет статус ноды."""
    conn = get_db_connection()
    with db_lock:
        conn.execute("UPDATE nodes SET is_active = ? WHERE node_id = ?", (is_active, node_id))
        conn.commit()
    conn.close()

def update_node_connections(node_id, current_connections):
    """Обновляет количество активных подключений на ноде."""
    conn = get_db_connection()
    with db_lock:
        conn.execute(
            "UPDATE nodes SET current_connections = ?, last_seen = datetime('now', 'localtime') WHERE node_id = ?",
            (current_connections, node_id)
        )
        conn.commit()
    conn.close()

def verify_node_token(node_id, auth_token):
    """Проверяет токен аутентификации ноды."""
    conn = get_db_connection()
    with db_lock:
        cursor = conn.execute(
            "SELECT 1 FROM nodes WHERE node_id = ? AND auth_token = ?",
            (node_id, auth_token)
        )
        exists = cursor.fetchone() is not None
    conn.close()
    return exists

# =================================================================
# ФУНКЦИИ ДЛЯ СТАТИСТИКИ
# =================================================================

def log_connection(username, client_ip, node_id, destination, duration, bytes_sent, bytes_received, status):
    """Логирует подключение."""
    conn = get_db_connection()
    with db_lock:
        conn.execute('''
            INSERT INTO connection_logs 
            (username, client_ip, node_id, destination, duration_sec, bytes_sent, bytes_received, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        ''', (username, client_ip, node_id, destination, duration, bytes_sent, bytes_received, status))
        conn.commit()
    conn.close()

def update_traffic_stats(username, node_id, bytes_sent, bytes_received):
    """Обновляет статистику трафика."""
    conn = get_db_connection()
    today = datetime.now().date().isoformat()
    with db_lock:
        cursor = conn.execute('''
            SELECT id FROM traffic_stats 
            WHERE username = ? AND node_id = ? AND date = ?
        ''', (username, node_id, today))
        existing = cursor.fetchone()
        
        if existing:
            conn.execute('''
                UPDATE traffic_stats 
                SET bytes_sent = bytes_sent + ?, 
                    bytes_received = bytes_received + ?,
                    connections_count = connections_count + 1
                WHERE id = ?
            ''', (bytes_sent, bytes_received, existing['id']))
        else:
            conn.execute('''
                INSERT INTO traffic_stats 
                (username, node_id, date, bytes_sent, bytes_received, connections_count)
                VALUES (?, ?, ?, ?, ?, 1)
            ''', (username, node_id, today, bytes_sent, bytes_received))
        conn.commit()
    conn.close()

def get_traffic_stats(username=None, node_id=None, days=30):
    """Получает статистику трафика."""
    conn = get_db_connection()
    with db_lock:
        query = '''
            SELECT * FROM traffic_stats 
            WHERE date >= date('now', '-' || ? || ' days')
        '''
        params = [days]
        
        if username:
            query += ' AND username = ?'
            params.append(username)
        if node_id:
            query += ' AND node_id = ?'
            params.append(node_id)
        
        query += ' ORDER BY date DESC'
        cursor = conn.execute(query, params)
        stats = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return stats

# =================================================================
# ФУНКЦИИ ДЛЯ ИСТОРИИ ДЕЙСТВИЙ АДМИНИСТРАТОРА
# =================================================================

def log_admin_action(action_type, admin_username, target_type=None, target_id=None, description=None, ip_address=None):
    """Логирует действие администратора."""
    conn = get_db_connection()
    with db_lock:
        conn.execute('''
            INSERT INTO admin_actions 
            (action_type, admin_username, target_type, target_id, description, ip_address)
            VALUES (?, ?, ?, ?, ?, ?)
        ''', (action_type, admin_username, target_type, target_id, description, ip_address))
        conn.commit()
    conn.close()

def get_admin_actions(limit=100):
    """Получает историю действий администратора."""
    try:
        conn = get_db_connection()
        # Проверяем существование таблицы быстро
        cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='admin_actions'")
        if not cursor.fetchone():
            conn.close()
            return []
        
        with db_lock:
            cursor = conn.execute('''
                SELECT * FROM admin_actions 
                ORDER BY timestamp DESC 
                LIMIT ?
            ''', (limit,))
            actions = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return actions
    except Exception:
        return []

# =================================================================
# ФУНКЦИИ ДЛЯ КВОТ ТРАФИКА
# =================================================================

def set_traffic_quota(username, monthly_limit_gb):
    """Устанавливает квоту трафика для пользователя."""
    conn = get_db_connection()
    with db_lock:
        # Получаем текущее использование
        cursor = conn.execute('''
            SELECT SUM(bytes_sent + bytes_received) as total 
            FROM traffic_stats 
            WHERE username = ? AND date >= date('now', 'start of month')
        ''', (username,))
        result = cursor.fetchone()
        current_usage = (result['total'] or 0) / (1024 ** 3)  # Конвертируем в GB
        
        # Устанавливаем или обновляем квоту
        conn.execute('''
            INSERT INTO traffic_quotas (username, monthly_limit_gb, current_usage_gb, reset_date)
            VALUES (?, ?, ?, date('now', 'start of month', '+1 month'))
            ON CONFLICT(username) DO UPDATE SET
                monthly_limit_gb = excluded.monthly_limit_gb,
                reset_date = date('now', 'start of month', '+1 month')
        ''', (username, monthly_limit_gb, current_usage))
        conn.commit()
    conn.close()

def get_traffic_quota(username):
    """Получает квоту трафика для пользователя."""
    conn = get_db_connection()
    with db_lock:
        cursor = conn.execute('SELECT * FROM traffic_quotas WHERE username = ?', (username,))
        quota = cursor.fetchone()
    conn.close()
    return dict(quota) if quota else None

def update_traffic_usage(username, bytes_added):
    """Обновляет использование трафика пользователем."""
    conn = get_db_connection()
    with db_lock:
        # Проверяем, нужно ли сбросить квоту (новый месяц)
        cursor = conn.execute('SELECT reset_date FROM traffic_quotas WHERE username = ?', (username,))
        quota = cursor.fetchone()
        
        if quota:
            reset_date = quota['reset_date']
            today = datetime.now().date().isoformat()
            if today >= reset_date:
                # Сбрасываем использование и обновляем дату сброса
                conn.execute('''
                    UPDATE traffic_quotas 
                    SET current_usage_gb = 0,
                        reset_date = date('now', 'start of month', '+1 month')
                    WHERE username = ?
                ''', (username,))
            else:
                # Обновляем использование
                conn.execute('''
                    UPDATE traffic_quotas 
                    SET current_usage_gb = current_usage_gb + ?
                    WHERE username = ?
                ''', (bytes_added / (1024 ** 3), username))
            conn.commit()
    conn.close()

