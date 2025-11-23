"""
Веб-панель управления прокси-системой
Управление пользователями, нодами, назначениями, статистикой
"""
from flask import Flask, render_template_string, request, redirect, url_for, session, flash, jsonify, Response
import sqlite3
import os
import secrets
import hashlib
from functools import wraps
import threading
import sys
import json as json_lib
import csv
import io
from datetime import datetime, timedelta
import database as db
import shutil
import time
import base64
from collections import defaultdict

# Опциональные библиотеки
try:
    import psutil  # Для мониторинга производительности
    # Проверяем, что psutil работает (не просто импортируется)
    try:
        psutil.cpu_percent(interval=0.1)
        PSUTIL_AVAILABLE = True
        print("[INFO] psutil загружен успешно")
    except Exception as e:
        PSUTIL_AVAILABLE = False
        print(f"[WARNING] psutil импортирован, но не работает: {e}")
        print("[WARNING] Попробуйте переустановить: pip3 uninstall psutil && pip3 install psutil")
except ImportError as e:
    PSUTIL_AVAILABLE = False
    print(f"[WARNING] psutil не установлен: {e}")
    print("[INFO] Установите: pip3 install psutil")

try:
    import pyotp  # Для 2FA
    QRCODE_AVAILABLE = True
except ImportError:
    QRCODE_AVAILABLE = False

try:
    from reportlab.lib import colors
    from reportlab.lib.pagesizes import letter, A4
    from reportlab.platypus import SimpleDocTemplate, Table, TableStyle, Paragraph, Spacer
    from reportlab.lib.styles import getSampleStyleSheet
    from reportlab.lib.units import inch
    PDF_AVAILABLE = True
except ImportError:
    PDF_AVAILABLE = False

# --- КОНФИГУРАЦИЯ ---
ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = hashlib.sha256('admin123'.encode()).hexdigest()  # СМЕНИТЕ ПАРОЛЬ!
FLASK_SECRET_KEY = os.environ.get('FLASK_SECRET_KEY', secrets.token_hex(32))

# Настройки безопасности
RATE_LIMIT_ENABLED = False  # Отключено по умолчанию для избежания проблем
IP_WHITELIST_ENABLED = False  # Включить для ограничения доступа по IP
ALLOWED_IPS = ['127.0.0.1', '::1']  # Разрешенные IP адреса
RATE_LIMIT_STORAGE = defaultdict(list)  # Простое хранилище для rate limiting
RATE_LIMIT_LOCK = threading.Lock()  # Блокировка для потокобезопасности

app = Flask(__name__)
app.secret_key = FLASK_SECRET_KEY

# Глобальный обработчик ошибок
@app.errorhandler(Exception)
def handle_error(e):
    """Обработка всех ошибок"""
    import traceback
    error_msg = str(e)
    print(f"[ERROR] {error_msg}")
    print(traceback.format_exc())
    
    # Если это ошибка БД, возвращаем простую страницу
    if 'no such table' in error_msg.lower() or 'database' in error_msg.lower():
        return f'''
        <html>
        <head><title>Ошибка базы данных</title></head>
        <body style="font-family: Arial; padding: 40px; text-align: center;">
            <h2>Ошибка базы данных</h2>
            <p>База данных не инициализирована. Запустите panel_server.py сначала.</p>
            <p style="color: #666; font-size: 12px;">{error_msg}</p>
        </body>
        </html>
        ''', 500
    
    # Для других ошибок возвращаем общее сообщение
    return f'''
    <html>
    <head><title>Ошибка</title></head>
    <body style="font-family: Arial; padding: 40px; text-align: center;">
        <h2>Произошла ошибка</h2>
        <p>Попробуйте обновить страницу или вернуться на главную.</p>
        <a href="/">Главная</a> | <a href="/settings">Настройки</a>
    </body>
    </html>
    ''', 500

# =================================================================
# АУТЕНТИФИКАЦИЯ И БЕЗОПАСНОСТЬ
# =================================================================

# Rate Limiting
def check_rate_limit(ip, max_requests=20, window=300):
    """Проверка rate limit для IP адреса (более мягкие настройки)"""
    if not RATE_LIMIT_ENABLED:
        return True
    
    with RATE_LIMIT_LOCK:
        now = time.time()
        # Очищаем старые запросы
        RATE_LIMIT_STORAGE[ip] = [req_time for req_time in RATE_LIMIT_STORAGE[ip] if now - req_time < window]
        
        # Проверяем лимит
        if len(RATE_LIMIT_STORAGE[ip]) >= max_requests:
            return False
        
        # Добавляем текущий запрос
        RATE_LIMIT_STORAGE[ip].append(now)
    return True

def clear_rate_limit(ip):
    """Очистка rate limit для IP (при успешном входе)"""
    with RATE_LIMIT_LOCK:
        if ip in RATE_LIMIT_STORAGE:
            del RATE_LIMIT_STORAGE[ip]

def check_ip_whitelist(ip):
    """Проверка IP whitelist"""
    if not IP_WHITELIST_ENABLED:
        return True
    return ip in ALLOWED_IPS

def rate_limit_decorator(max_requests=10, window=60):
    """Декоратор для rate limiting"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            ip = request.remote_addr
            if not check_rate_limit(ip, max_requests, window):
                return jsonify({'error': 'Rate limit exceeded'}), 429
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def require_login(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        # Быстрая проверка без блокировок
        if not is_logged_in():
            # Для API endpoints возвращаем JSON, для обычных страниц - редирект
            if request.path.startswith('/api/'):
                return jsonify({'error': 'Unauthorized', 'login_required': True}), 401
            return redirect(url_for('login'))
        
        # Проверка IP whitelist (только если включен)
        if IP_WHITELIST_ENABLED and not check_ip_whitelist(request.remote_addr):
            if request.path.startswith('/api/'):
                return jsonify({'error': 'IP not allowed'}), 403
            flash('Доступ запрещен с вашего IP адреса', 'error')
            return redirect(url_for('login'))
        
        # Проверка 2FA если включена (только если действительно включена)
        if session.get('2fa_enabled') and not session.get('2fa_verified'):
            if request.path.startswith('/api/'):
                return jsonify({'error': '2FA verification required'}), 401
            return redirect(url_for('verify_2fa'))
        
        return f(*args, **kwargs)
    return decorated_function

def is_logged_in():
    return 'logged_in' in session and session['logged_in']

def has_permission(permission):
    """Проверка прав доступа"""
    if not is_logged_in():
        return False
    
    # Администратор имеет все права
    if session.get('username') == ADMIN_USERNAME:
        return True
    
    # Проверка роли пользователя (базовая реализация)
    role = session.get('role', 'user')
    permissions = {
        'admin': ['all'],
        'moderator': ['view_users', 'view_nodes', 'view_stats', 'edit_users'],
        'user': ['view_stats']
    }
    
    user_perms = permissions.get(role, [])
    return 'all' in user_perms or permission in user_perms

def require_permission(permission):
    """Декоратор для проверки прав доступа"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if not has_permission(permission):
                flash('У вас нет прав для выполнения этого действия', 'error')
                return redirect('/')
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def log_admin_action_decorator(action_type):
    """Декоратор для логирования действий администратора."""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            result = f(*args, **kwargs)
            if is_logged_in():
                ip_address = request.remote_addr
                db.log_admin_action(action_type, ADMIN_USERNAME, ip_address=ip_address)
            return result
        return decorated_function
    return decorator

# =================================================================
# МАРШРУТЫ
# =================================================================

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        # Проверка rate limit только для POST запросов (попытки входа)
        ip = request.remote_addr
        if not check_rate_limit(ip, max_requests=10, window=300):
            flash('Слишком много попыток входа. Попробуйте позже.', 'error')
            return render_template_string(LOGIN_TEMPLATE, ADMIN_USERNAME=ADMIN_USERNAME)
        
        try:
            entered_hash = hashlib.sha256(request.form['password'].encode()).hexdigest()
            if request.form['username'] == ADMIN_USERNAME and entered_hash == ADMIN_PASSWORD_HASH:
                # Успешный вход - очищаем rate limit
                clear_rate_limit(ip)
                
                session['logged_in'] = True
                session['username'] = ADMIN_USERNAME
                session.permanent = True
                
                # Проверка 2FA если включена
                if session.get('2fa_enabled'):
                    session['2fa_verified'] = False
                    return redirect(url_for('verify_2fa'))
                
                flash('Вход выполнен успешно.', 'success')
                return redirect('/')
            else:
                flash('Неверный логин или пароль.', 'error')
        except Exception as e:
            flash(f'Ошибка входа: {str(e)}', 'error')
    
    return render_template_string(LOGIN_TEMPLATE, ADMIN_USERNAME=ADMIN_USERNAME)

@app.route('/2fa/setup')
@require_login
def setup_2fa():
    """Настройка 2FA"""
    if not QRCODE_AVAILABLE:
        flash('2FA недоступен. Установите pyotp: pip install pyotp', 'error')
        return redirect(url_for('settings'))
    
    # Генерируем секрет для 2FA
    secret = pyotp.random_base32()
    session['2fa_secret'] = secret
    
    # Создаем URI для QR кода
    totp_uri = pyotp.totp.TOTP(secret).provisioning_uri(
        name=ADMIN_USERNAME,
        issuer_name='Proxy Panel'
    )
    
    return render_template_string('''
        <html>
        <head><title>Настройка 2FA</title></head>
        <body style="font-family: Arial; padding: 40px; text-align: center;">
            <h2>Настройка двухфакторной аутентификации</h2>
            <p>Отсканируйте QR код в приложении Google Authenticator или Authy</p>
            <p><strong>Секрет:</strong> {secret}</p>
            <p>После настройки введите код подтверждения:</p>
            <form method="post" action="/2fa/verify-setup">
                <input type="text" name="code" placeholder="6-значный код" required>
                <button type="submit">Активировать 2FA</button>
            </form>
            <a href="/settings">Отмена</a>
        </body>
        </html>
    '''.format(secret=secret))

@app.route('/2fa/verify-setup', methods=['POST'])
@require_login
def verify_2fa_setup():
    """Проверка и активация 2FA"""
    if not QRCODE_AVAILABLE:
        return redirect(url_for('settings'))
    
    code = request.form.get('code', '')
    secret = session.get('2fa_secret')
    
    if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
        session['2fa_enabled'] = True
        session['2fa_verified'] = True
        flash('2FA успешно активирован', 'success')
        return redirect(url_for('settings'))
    else:
        flash('Неверный код', 'error')
        return redirect(url_for('setup_2fa'))

@app.route('/2fa/verify', methods=['GET', 'POST'])
def verify_2fa():
    """Проверка 2FA кода при входе"""
    if request.method == 'POST':
        code = request.form.get('code', '')
        secret = session.get('2fa_secret')
        
        if secret and pyotp.TOTP(secret).verify(code, valid_window=1):
            session['2fa_verified'] = True
            flash('2FA проверка пройдена', 'success')
            return redirect('/')
        else:
            flash('Неверный код 2FA', 'error')
    
    return render_template_string('''
        <html>
        <head><title>Проверка 2FA</title></head>
        <body style="font-family: Arial; padding: 40px; text-align: center;">
            <h2>Введите код из приложения аутентификации</h2>
            <form method="post">
                <input type="text" name="code" placeholder="6-значный код" required>
                <button type="submit">Проверить</button>
            </form>
        </body>
        </html>
    ''')

@app.route('/logout')
def logout():
    session.pop('logged_in', None)
    flash('Вы успешно вышли.', 'info')
    return redirect(url_for('login'))

@app.route('/')
@require_login
def dashboard():
    """Дашборд с оптимизированными запросами и таймаутами"""
    # Устанавливаем таймаут для всего запроса
    start_time = time.time()
    timeout = 5  # 5 секунд максимум
    
    try:
        # Получаем данные с таймаутами
        users = []
        nodes = []
        try:
            if hasattr(db, 'get_all_users'):
                users = db.get_all_users()
            else:
                # Прямой запрос если функция не существует
                conn_temp = db.get_db_connection()
                try:
                    conn_temp.execute("PRAGMA busy_timeout = 1000")
                    with db.db_lock:
                        cursor = conn_temp.execute("SELECT * FROM users WHERE username != ? LIMIT 1000", (ADMIN_USERNAME,))
                        users = [dict(row) for row in cursor.fetchall()]
                except:
                    users = []
                finally:
                    conn_temp.close()
            
            if hasattr(db, 'get_all_nodes'):
                nodes = db.get_all_nodes()
            else:
                # Прямой запрос если функция не существует
                conn_temp = db.get_db_connection()
                try:
                    conn_temp.execute("PRAGMA busy_timeout = 1000")
                    with db.db_lock:
                        cursor = conn_temp.execute("SELECT * FROM nodes LIMIT 1000")
                        nodes = [dict(row) for row in cursor.fetchall()]
                except:
                    nodes = []
                finally:
                    conn_temp.close()
        except Exception as e:
            print(f"[DASHBOARD ERROR] {e}")
            users = []
            nodes = []
    except Exception as e:
        print(f"[DASHBOARD ERROR] {e}")
        users = []
        nodes = []
    
    # Статистика
    total_users = len(users)
    total_nodes = len(nodes)
    active_nodes = sum(1 for n in nodes if n['is_active']) if nodes else 0
    inactive_nodes = total_nodes - active_nodes
    active_sessions = 0
    total_traffic = 0
    traffic_by_day = []
    
    # Быстрый запрос статистики с таймаутом
    conn = None
    try:
        conn = db.get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")  # 2 секунды таймаут
        
        # Проверяем таймаут
        if time.time() - start_time > timeout:
            raise TimeoutError("Request timeout")
        
        # Быстрый запрос для активных сессий
        try:
            with db.db_lock:
                cursor = conn.execute("SELECT COUNT(*) as count FROM active_sessions")
                result = cursor.fetchone()
                active_sessions = result['count'] if result else 0
        except:
            active_sessions = 0
        
        # Проверяем таймаут
        if time.time() - start_time > timeout:
            raise TimeoutError("Request timeout")
        
        # Быстрый запрос для трафика
        try:
            with db.db_lock:
                cursor = conn.execute("""
                    SELECT COALESCE(SUM(bytes_sent + bytes_received), 0) as total 
                    FROM traffic_stats 
                    WHERE date >= date('now', '-7 days')
                """)
                result = cursor.fetchone()
                total_traffic = result['total'] if result else 0
                
                # Данные для графика (упрощенный запрос)
                cursor = conn.execute("""
                    SELECT date, SUM(bytes_sent + bytes_received) as daily_traffic
                    FROM traffic_stats 
                    WHERE date >= date('now', '-7 days')
                    GROUP BY date
                    ORDER BY date
                """)
                traffic_data = {row['date']: row['daily_traffic'] for row in cursor.fetchall()}
        except:
            traffic_data = {}
        
        # Заполняем дни для графика
        for i in range(6, -1, -1):
            date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
            traffic_by_day.append({
                'date': date,
                'traffic': (traffic_data.get(date, 0) / (1024 ** 3))  # GB
            })
    except (TimeoutError, Exception) as e:
        # В случае ошибки используем пустые данные
        pass
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
        
        # Последние логи - опционально, не критично
        recent_logs = []
        if time.time() - start_time < timeout:
            try:
                conn = db.get_db_connection()
                conn.execute("PRAGMA busy_timeout = 1000")
                with db.db_lock:
                    cursor = conn.execute("""
                        SELECT username, node_id, destination, timestamp, status
                        FROM connection_logs 
                        ORDER BY timestamp DESC 
                        LIMIT 5
                    """)
                    recent_logs = [dict(row) for row in cursor.fetchall()]
                conn.close()
            except:
                pass
    
    try:
        return render_template_string(DASHBOARD_TEMPLATE,
                                 sidebar_html=SIDEBAR_HTML,
                                 total_users=total_users,
                                 total_nodes=total_nodes,
                                 active_nodes=active_nodes,
                                 inactive_nodes=inactive_nodes,
                                 active_sessions=active_sessions,
                                 total_traffic=total_traffic,
                                     recent_logs=recent_logs,
                                     traffic_by_day=traffic_by_day)
    except Exception as e:
        # Если ошибка рендеринга, возвращаем простую страницу
        import traceback
        print(f"[RENDER ERROR] {e}")
        print(traceback.format_exc())
        return f'''
        <html>
        <head><title>Ошибка</title></head>
        <body style="font-family: Arial; padding: 40px;">
            <h2>Ошибка загрузки дашборда</h2>
            <p>Попробуйте обновить страницу или перейти в <a href="/settings">настройки</a></p>
            <p style="color: #666; font-size: 12px;">Ошибка: {str(e)}</p>
        </body>
        </html>
        ''', 500

@app.route('/users')
@require_login
def users():
    """Страница пользователей с оптимизацией и таймаутами"""
    users_data = []
    conn = None
    
    try:
        conn = db.get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")
        
        # Быстрый запрос пользователей
        try:
            with db.db_lock:
                # Проверяем существование таблицы
                cursor = conn.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='users'")
                if cursor.fetchone():
                    cursor = conn.execute("SELECT * FROM users WHERE username != ? ORDER BY username LIMIT 1000", (ADMIN_USERNAME,))
                    users_data = [dict(row) for row in cursor.fetchall()]
                else:
                    users_data = []
        except Exception as e:
            print(f"[USERS ERROR] {e}")
            users_data = []
        
        if not users_data:
            if conn:
                conn.close()
            return render_template_string(USERS_TEMPLATE, sidebar_html=SIDEBAR_HTML, users_data=[])
        
        # Оптимизированные запросы с таймаутом
        usernames = [u['username'] for u in users_data]
        if len(usernames) > 100:  # Ограничиваем для производительности
            usernames = usernames[:100]
        
        placeholders = ','.join(['?'] * len(usernames))
        sessions_map = {}
        quotas_map = {}
        nodes_map = {}
        
        try:
            with db.db_lock:
                # Активные сессии
                cursor = conn.execute(f"""
                    SELECT username, COUNT(DISTINCT client_ip) as count 
                    FROM active_sessions 
                    WHERE username IN ({placeholders})
                    GROUP BY username
                """, usernames)
                sessions_map = {row['username']: row['count'] for row in cursor.fetchall()}
                
                # Квоты
                cursor = conn.execute(f"""
                    SELECT * FROM traffic_quotas 
                    WHERE username IN ({placeholders})
                """, usernames)
                quotas_map = {row['username']: dict(row) for row in cursor.fetchall()}
                
                # Ноды
                cursor = conn.execute(f"""
                    SELECT un.username, n.node_id, n.name, n.is_active
                    FROM user_nodes un
                    JOIN nodes n ON un.node_id = n.node_id
                    WHERE un.username IN ({placeholders})
                """, usernames)
                for row in cursor.fetchall():
                    username = row['username']
                    if username not in nodes_map:
                        nodes_map[username] = []
                    nodes_map[username].append({
                        'node_id': row['node_id'],
                        'name': row['name'],
                        'is_active': row['is_active']
                    })
        except:
            pass  # Продолжаем даже при ошибках
        
        # Объединяем данные
        for user in users_data:
            user['active_sessions'] = sessions_map.get(user['username'], 0)
            user['nodes'] = nodes_map.get(user['username'], [])
            if user['username'] in quotas_map:
                user['quota'] = quotas_map[user['username']]
    except Exception as e:
        # В случае ошибки возвращаем пустой список
        users_data = []
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
    
    try:
        return render_template_string(USERS_TEMPLATE, sidebar_html=SIDEBAR_HTML, users_data=users_data)
    except Exception as e:
        import traceback
        print(f"[USERS RENDER ERROR] {e}")
        print(traceback.format_exc())
        return f'''
        <html>
        <head><title>Ошибка</title></head>
        <body style="font-family: Arial; padding: 40px;">
            <h2>Ошибка загрузки страницы пользователей</h2>
            <p><a href="/">Главная</a> | <a href="/settings">Настройки</a></p>
        </body>
        </html>
        ''', 500

@app.route('/users/add', methods=['POST'])
@require_login
def add_user():
    username = request.form.get('username')
    password = request.form.get('password')
    device_limit = int(request.form.get('device_limit', 1))
    
    if not username or not password:
        flash('Логин и пароль обязательны.', 'error')
        return redirect(url_for('users'))
    
    if device_limit < 1:
        flash('Лимит устройств должен быть не меньше 1.', 'error')
        return redirect(url_for('users'))
    
    password_hash = hashlib.sha256(password.encode()).hexdigest()
    conn = db.get_db_connection()
    try:
        with db.db_lock:
            conn.execute(
                "INSERT INTO users (username, password, is_active, device_limit) VALUES (?, ?, 1, ?)",
                (username, password_hash, device_limit)
            )
            conn.commit()
        flash(f'Пользователь "{username}" успешно добавлен.', 'success')
        
        if hasattr(db, 'log_admin_action'):
            db.log_admin_action('CREATE_USER', ADMIN_USERNAME, 'user', username, 
                              f'Создан пользователь {username} с лимитом {device_limit}', request.remote_addr)
    except sqlite3.IntegrityError:
        flash(f'Пользователь "{username}" уже существует.', 'error')
    except Exception as e:
        flash(f'Ошибка при создании пользователя: {str(e)}', 'error')
    finally:
        conn.close()
    
    return redirect(url_for('users'))

@app.route('/users/<username>/delete')
@require_login
def delete_user(username):
    if username == ADMIN_USERNAME:
        flash('Нельзя удалить администратора.', 'error')
        return redirect(url_for('users'))
    
    conn = db.get_db_connection()
    with db.db_lock:
        conn.execute("DELETE FROM users WHERE username = ?", (username,))
        conn.commit()
    conn.close()
    
    if hasattr(db, 'log_admin_action'):
        db.log_admin_action('DELETE_USER', ADMIN_USERNAME, 'user', username, 
                          f'Удален пользователь {username}', request.remote_addr)
    
    flash(f'Пользователь {username} удален.', 'info')
    return redirect(url_for('users'))

@app.route('/users/<username>/toggle')
@require_login
def toggle_user(username):
    conn = db.get_db_connection()
    with db.db_lock:
        cursor = conn.execute("SELECT is_active FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
        if user:
            new_status = 0 if user['is_active'] else 1
            conn.execute("UPDATE users SET is_active = ? WHERE username = ?", (new_status, username))
            conn.commit()
            status_text = "активирован" if new_status else "деактивирован"
            flash(f'Пользователь {username} {status_text}.', 'success')
            
            if hasattr(db, 'log_admin_action'):
                db.log_admin_action('TOGGLE_USER', ADMIN_USERNAME, 'user', username, 
                                  f'Пользователь {username} {status_text}', request.remote_addr)
    conn.close()
    return redirect(url_for('users'))

@app.route('/users/<username>/limit', methods=['POST'])
@require_login
def set_user_limit(username):
    try:
        limit = int(request.form.get('device_limit'))
        if limit < 1:
            raise ValueError
        conn = db.get_db_connection()
        with db.db_lock:
            conn.execute("UPDATE users SET device_limit = ? WHERE username = ?", (limit, username))
            conn.commit()
        conn.close()
        flash(f'Лимит для {username} обновлен до {limit}.', 'success')
    except ValueError:
        flash('Лимит должен быть целым числом больше 0.', 'error')
    return redirect(url_for('users'))

@app.route('/nodes')
@require_login
def nodes():
    """Страница нод с оптимизацией"""
    nodes_data = []
    conn = None
    
    try:
        if hasattr(db, 'get_all_nodes'):
            nodes_data = db.get_all_nodes()
        else:
            # Прямой запрос
            conn_temp = db.get_db_connection()
            try:
                conn_temp.execute("PRAGMA busy_timeout = 1000")
                with db.db_lock:
                    cursor = conn_temp.execute("SELECT name FROM sqlite_master WHERE type='table' AND name='nodes'")
                    if cursor.fetchone():
                        cursor = conn_temp.execute("SELECT * FROM nodes LIMIT 1000")
                        nodes_data = [dict(row) for row in cursor.fetchall()]
                    else:
                        nodes_data = []
            except:
                nodes_data = []
            finally:
                conn_temp.close()
        
        if not nodes_data:
            return render_template_string(NODES_TEMPLATE, sidebar_html=SIDEBAR_HTML, nodes_data=[])
        
        conn = db.get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")
        
        node_ids = [n['node_id'] for n in nodes_data]
        if len(node_ids) > 100:  # Ограничение
            node_ids = node_ids[:100]
        
        placeholders = ','.join(['?'] * len(node_ids))
        users_map = {}
        connections_map = {}
        
        try:
            with db.db_lock:
                # Пользователи нод
                cursor = conn.execute(f"""
                    SELECT node_id, COUNT(DISTINCT username) as count 
                    FROM user_nodes 
                    WHERE node_id IN ({placeholders})
                    GROUP BY node_id
                """, node_ids)
                users_map = {row['node_id']: row['count'] for row in cursor.fetchall()}
                
                # Активные подключения
                cursor = conn.execute(f"""
                    SELECT node_id, COUNT(*) as count 
                    FROM active_sessions 
                    WHERE node_id IN ({placeholders})
                    GROUP BY node_id
                """, node_ids)
                connections_map = {row['node_id']: row['count'] for row in cursor.fetchall()}
        except:
            pass
        
        # Обрабатываем данные
        now = datetime.now()
        for node in nodes_data:
            node_id = node['node_id']
            node['assigned_users'] = users_map.get(node_id, 0)
            node['active_connections'] = connections_map.get(node_id, 0)
            
            # Статус онлайн/офлайн
            if node.get('last_seen'):
                try:
                    last_seen = datetime.strptime(node['last_seen'], '%Y-%m-%d %H:%M:%S')
                    time_diff = now - last_seen
                    node['is_online'] = time_diff.total_seconds() < 180  # Увеличили до 3 минут для надежности
                    if time_diff.total_seconds() < 60:
                        node['last_seen_ago'] = f"{int(time_diff.total_seconds())} сек"
                    elif time_diff.total_seconds() < 3600:
                        node['last_seen_ago'] = f"{int(time_diff.total_seconds() / 60)} мин"
                    elif time_diff.total_seconds() < 86400:
                        node['last_seen_ago'] = f"{int(time_diff.total_seconds() / 3600)} ч"
                    else:
                        node['last_seen_ago'] = f"{time_diff.days} дн"
                except:
                    node['is_online'] = False
                    node['last_seen_ago'] = 'Неизвестно'
            else:
                node['is_online'] = False
                node['last_seen_ago'] = 'Никогда'
            
            # Загрузка (ограничиваем максимум 100% для отображения)
            max_conn = node.get('max_connections', 100)
            current_conn = node.get('current_connections', 0)
            load_percent = (current_conn / max_conn * 100) if max_conn > 0 else 0
            node['load_percent'] = min(load_percent, 100.0)  # Ограничиваем до 100%
            if load_percent > 100:
                node['load_warning'] = True  # Флаг для предупреждения о перегрузке
    except:
        nodes_data = []
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
    
    try:
        return render_template_string(NODES_TEMPLATE, sidebar_html=SIDEBAR_HTML, nodes_data=nodes_data)
    except Exception as e:
        import traceback
        print(f"[NODES RENDER ERROR] {e}")
        print(traceback.format_exc())
        return f'''
        <html>
        <head><title>Ошибка</title></head>
        <body style="font-family: Arial; padding: 40px;">
            <h2>Ошибка загрузки страницы нод</h2>
            <p><a href="/">Главная</a> | <a href="/settings">Настройки</a></p>
        </body>
        </html>
        ''', 500

@app.route('/nodes/add', methods=['POST'])
@require_login
def add_node():
    node_id = request.form.get('node_id')
    name = request.form.get('name')
    host = request.form.get('host')
    port = int(request.form.get('port'))
    node_type = request.form.get('node_type', 'http')
    auth_token = request.form.get('auth_token')
    
    if not all([node_id, name, host, port, auth_token]):
        flash('Все поля обязательны.', 'error')
        return redirect(url_for('nodes'))
    
    db.register_node(node_id, name, host, port, node_type, auth_token)
    flash(f'Нода "{name}" успешно добавлена.', 'success')
    return redirect(url_for('nodes'))

@app.route('/nodes/<node_id>/toggle')
@require_login
def toggle_node(node_id):
    node = db.get_node_by_id(node_id)
    if node:
        new_status = 0 if node['is_active'] else 1
        db.update_node_status(node_id, new_status)
        status_text = "активирована" if new_status else "деактивирована"
        flash(f'Нода {node_id} {status_text}.', 'success')
    return redirect(url_for('nodes'))

@app.route('/nodes/<node_id>/delete')
@require_login
def delete_node(node_id):
    conn = db.get_db_connection()
    with db.db_lock:
        conn.execute("DELETE FROM nodes WHERE node_id = ?", (node_id,))
        conn.commit()
    conn.close()
    flash(f'Нода {node_id} удалена.', 'info')
    return redirect(url_for('nodes'))

@app.route('/assignments')
@require_login
def assignments():
    """Страница назначений с оптимизацией"""
    assignments_data = []
    users_list = []
    nodes_list = []
    conn = None
    
    try:
        conn = db.get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")
        
        try:
            with db.db_lock:
                # Получаем все назначения
                cursor = conn.execute('''
                    SELECT u.username, u.is_active, n.node_id, n.name as node_name, n.host, n.port, n.is_active as node_active
                    FROM user_nodes un
                    JOIN users u ON un.username = u.username
                    JOIN nodes n ON un.node_id = n.node_id
                    ORDER BY u.username, n.name
                    LIMIT 1000
                ''')
                all_assignments = [dict(row) for row in cursor.fetchall()]
                
                # Группируем по пользователям
                assignments_by_user = {}
                for assignment in all_assignments:
                    username = assignment['username']
                    if username not in assignments_by_user:
                        assignments_by_user[username] = {
                            'username': username,
                            'is_active': assignment['is_active'],
                            'nodes': []
                        }
                    assignments_by_user[username]['nodes'].append({
                        'node_id': assignment['node_id'],
                        'node_name': assignment['node_name'],
                        'host': assignment['host'],
                        'port': assignment['port'],
                        'node_active': assignment['node_active']
                    })
                
                # Преобразуем в список для шаблона
                assignments_data = list(assignments_by_user.values())
                
                # Получаем всех пользователей и ноды для формы (с лимитами)
                users_list = [dict(row) for row in conn.execute("SELECT username FROM users WHERE username != ? ORDER BY username LIMIT 500", (ADMIN_USERNAME,)).fetchall()]
                nodes_list = [dict(row) for row in conn.execute("SELECT node_id, name, host, port FROM nodes ORDER BY name LIMIT 500").fetchall()]
        except:
            pass
    except:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
    
    try:
        return render_template_string(ASSIGNMENTS_TEMPLATE,
                                     sidebar_html=SIDEBAR_HTML,
                                     assignments_data=assignments_data,
                                     users_list=users_list,
                                     nodes_list=nodes_list)
    except Exception as e:
        import traceback
        print(f"[ASSIGNMENTS RENDER ERROR] {e}")
        print(traceback.format_exc())
        return f'''
        <html>
        <head><title>Ошибка</title></head>
        <body style="font-family: Arial; padding: 40px;">
            <h2>Ошибка загрузки страницы назначений</h2>
            <p><a href="/">Главная</a> | <a href="/settings">Настройки</a></p>
        </body>
        </html>
        ''', 500

@app.route('/assignments/add', methods=['POST'])
@require_login
def add_assignment():
    username = request.form.get('username')
    node_id = request.form.get('node_id')
    
    if not username or not node_id:
        flash('Выберите пользователя и ноду.', 'error')
        return redirect(url_for('assignments'))
    
    result, message = db.assign_node_to_user(username, node_id)
    if result:
        flash(f'Нода назначена пользователю {username}.', 'success')
    else:
        flash(f'Ошибка при назначении ноды: {message}', 'error')
    
    return redirect(url_for('assignments'))

@app.route('/assignments/remove/<username>/<node_id>')
@require_login
def remove_assignment(username, node_id):
    db.unassign_node_from_user(username, node_id)
    flash(f'Нода удалена у пользователя {username}.', 'info')
    return redirect(url_for('assignments'))

@app.route('/assignments/remove-all/<username>')
@require_login
def remove_all_assignments(username):
    conn = db.get_db_connection()
    try:
        with db.db_lock:
            conn.execute("DELETE FROM user_nodes WHERE username = ?", (username,))
            conn.commit()
        flash(f'Все назначения удалены у пользователя {username}.', 'info')
    finally:
        conn.close()
    return redirect(url_for('assignments'))

@app.route('/assignments/bulk', methods=['POST'])
@require_login
def bulk_assign():
    """Массовое назначение нод пользователям."""
    username = request.form.get('username')
    node_ids = request.form.getlist('node_ids')  # Множественный выбор
    
    if not username or not node_ids:
        flash('Выберите пользователя и хотя бы одну ноду.', 'error')
        return redirect(url_for('assignments'))
    
    # Если выбрана только одна нода - заменяем существующие
    # Если несколько - добавляем к существующим
    replace_existing = (len(node_ids) == 1)
    
    # Если заменяем - удаляем все старые назначения
    if replace_existing:
        conn = db.get_db_connection()
        try:
            with db.db_lock:
                conn.execute("DELETE FROM user_nodes WHERE username = ?", (username,))
                conn.commit()
        finally:
            conn.close()
    
    success_count = 0
    error_count = 0
    
    for node_id in node_ids:
        result, message = db.assign_node_to_user(username, node_id, replace_existing=False)
        if result:
            success_count += 1
        else:
            error_count += 1
    
    if success_count > 0:
        if replace_existing:
            flash(f'Нода назначена пользователю {username} (старые назначения удалены).', 'success')
        else:
            flash(f'Успешно назначено нод: {success_count}.', 'success')
    if error_count > 0:
        flash(f'Ошибок при назначении: {error_count}.', 'error')
    
    return redirect(url_for('assignments'))

@app.route('/stats')
@require_login
def stats():
    """Страница статистики с фильтрами по датам"""
    # Получаем параметры фильтрации
    days = int(request.args.get('days', 30))
    start_date = request.args.get('start_date', '')
    end_date = request.args.get('end_date', '')
    
    # Получаем статистику с таймаутами
    stats_data = []
    conn = None
    
    try:
        conn = db.get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")
        
        if start_date and end_date:
            # Фильтр по диапазону дат
            try:
                with db.db_lock:
                    cursor = conn.execute("""
                        SELECT username, 
                               SUM(bytes_sent) as bytes_sent,
                               SUM(bytes_received) as bytes_received,
                               COUNT(*) as connections_count
                        FROM traffic_stats
                        WHERE date >= ? AND date <= ?
                        GROUP BY username
                        ORDER BY (bytes_sent + bytes_received) DESC
                        LIMIT 1000
                    """, (start_date, end_date))
                    stats_data = [dict(row) for row in cursor.fetchall()]
            except:
                pass
        else:
            # Фильтр по количеству дней
            try:
                stats_data = db.get_traffic_stats(days=days) if hasattr(db, 'get_traffic_stats') else []
                if len(stats_data) > 1000:
                    stats_data = stats_data[:1000]
            except:
                pass
    except:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
    
    # Группируем по пользователям
    user_stats = {}
    for stat in stats_data:
        username = stat['username']
        if username not in user_stats:
            user_stats[username] = {'bytes_sent': 0, 'bytes_received': 0, 'connections': 0}
        user_stats[username]['bytes_sent'] += stat.get('bytes_sent', 0)
        user_stats[username]['bytes_received'] += stat.get('bytes_received', 0)
        user_stats[username]['connections'] += stat.get('connections_count', 0)
    
    try:
        return render_template_string(STATS_TEMPLATE, sidebar_html=SIDEBAR_HTML, 
                                     stats_data=stats_data, user_stats=user_stats,
                                     days=days, start_date=start_date, end_date=end_date)
    except Exception as e:
        import traceback
        print(f"[STATS RENDER ERROR] {e}")
        print(traceback.format_exc())
        return f'''
        <html>
        <head><title>Ошибка</title></head>
        <body style="font-family: Arial; padding: 40px;">
            <h2>Ошибка загрузки статистики</h2>
            <p><a href="/">Главная</a> | <a href="/settings">Настройки</a></p>
        </body>
        </html>
        ''', 500

@app.route('/logs')
@require_login
def logs():
    """Страница логов с оптимизацией"""
    username = request.args.get('username')
    node_id = request.args.get('node_id')
    logs_data = []
    conn = None
    
    try:
        conn = db.get_db_connection()
        conn.execute("PRAGMA busy_timeout = 2000")
        
        try:
            with db.db_lock:
                if username:
                    cursor = conn.execute(
                        "SELECT * FROM connection_logs WHERE username = ? ORDER BY timestamp DESC LIMIT 200",
                        (username,)
                    )
                elif node_id:
                    cursor = conn.execute(
                        "SELECT * FROM connection_logs WHERE node_id = ? ORDER BY timestamp DESC LIMIT 200",
                        (node_id,)
                    )
                else:
                    cursor = conn.execute("SELECT * FROM connection_logs ORDER BY timestamp DESC LIMIT 200")
                
                logs_data = [dict(row) for row in cursor.fetchall()]
        except:
            pass
    except:
        pass
    finally:
        if conn:
            try:
                conn.close()
            except:
                pass
    
    try:
        return render_template_string(LOGS_TEMPLATE, sidebar_html=SIDEBAR_HTML, logs_data=logs_data)
    except Exception as e:
        import traceback
        print(f"[LOGS RENDER ERROR] {e}")
        print(traceback.format_exc())
        return f'''
        <html>
        <head><title>Ошибка</title></head>
        <body style="font-family: Arial; padding: 40px;">
            <h2>Ошибка загрузки логов</h2>
            <p><a href="/">Главная</a> | <a href="/settings">Настройки</a></p>
        </body>
        </html>
        ''', 500

# =================================================================
# HTML ШАБЛОНЫ
# =================================================================

LOGIN_TEMPLATE = """
<!DOCTYPE html>
<html>
<head>
    <title>Вход в панель</title>
    <style>
        @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800&display=swap');
        
        * { margin: 0; padding: 0; box-sizing: border-box; }
        
        body { 
            font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            background-attachment: fixed;
            display: flex; 
            justify-content: center; 
            align-items: center; 
            min-height: 100vh; 
            margin: 0;
            position: relative;
            overflow: hidden;
        }
        
        body::before {
            content: '';
            position: absolute;
            top: 0;
            left: 0;
            right: 0;
            bottom: 0;
            background: url('data:image/svg+xml,<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="grid" width="100" height="100" patternUnits="userSpaceOnUse"><path d="M 100 0 L 0 0 0 100" fill="none" stroke="rgba(255,255,255,0.1)" stroke-width="1"/></pattern></defs><rect width="100" height="100" fill="url(%23grid)"/></svg>');
            opacity: 0.3;
        }
        
        .login-box { 
            background: white; 
            padding: 50px 40px; 
            border-radius: 25px; 
            box-shadow: 0 20px 60px rgba(0,0,0,0.3); 
            width: 420px;
            position: relative;
            z-index: 1;
            animation: slideUp 0.5s ease-out;
        }
        
        @keyframes slideUp {
            from {
                opacity: 0;
                transform: translateY(30px);
            }
            to {
                opacity: 1;
                transform: translateY(0);
            }
        }
        
        h2 { 
            color: #667eea; 
            margin-bottom: 35px; 
            text-align: center; 
            font-size: 28px;
            font-weight: 700;
        }
        
        input[type="text"], input[type="password"] { 
            width: 100%; 
            padding: 14px 18px; 
            margin: 12px 0; 
            box-sizing: border-box; 
            border: 2px solid #e2e8f0; 
            border-radius: 12px; 
            font-size: 15px;
            transition: all 0.3s;
            font-family: 'Inter', sans-serif;
        }
        
        input[type="text"]:focus, input[type="password"]:focus {
            outline: none;
            border-color: #667eea;
            box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
        }
        
        input[type="submit"] { 
            width: 100%; 
            padding: 14px; 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%); 
            color: white; 
            border: none; 
            border-radius: 12px; 
            cursor: pointer; 
            font-size: 16px; 
            font-weight: 600; 
            margin-top: 15px;
            transition: all 0.3s;
            box-shadow: 0 4px 15px rgba(102, 126, 234, 0.4);
        }
        
        input[type="submit"]:hover { 
            transform: translateY(-2px);
            box-shadow: 0 6px 20px rgba(102, 126, 234, 0.5);
        }
        
        input[type="submit"]:active {
            transform: translateY(0);
        }
        
        .flash { 
            padding: 14px 18px; 
            margin-bottom: 20px; 
            border-radius: 12px;
            font-weight: 500;
            animation: slideIn 0.3s ease-out;
        }
        
        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-10px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }
        
        .flash.error { 
            background: rgba(239, 68, 68, 0.15);
            backdrop-filter: blur(10px);
            color: #f87171;
            border-left: 4px solid #ef4444;
            border: 1px solid rgba(239, 68, 68, 0.3);
        }
        
        .flash.success { 
            background: rgba(16, 185, 129, 0.15);
            backdrop-filter: blur(10px);
            color: #10b981;
            border-left: 4px solid #10b981;
            border: 1px solid rgba(16, 185, 129, 0.3);
        }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>🔐 Вход в панель управления</h2>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        <form method="post">
            <input type="text" name="username" placeholder="Логин" value="{{ ADMIN_USERNAME }}" readonly style="background: #f8fafc;">
            <input type="password" name="password" placeholder="Пароль" required autofocus>
            <input type="submit" value="Войти">
        </form>
    </div>
</body>
</html>
"""

BASE_STYLE = """
<style>
    @import url('https://fonts.googleapis.com/css2?family=Inter:wght@300;400;500;600;700;800;900&display=swap');
    @import url('https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css');
    
    * { margin: 0; padding: 0; box-sizing: border-box; }
    
    :root {
        --primary: #2563eb;
        --primary-dark: #1e40af;
        --primary-light: #3b82f6;
        --secondary: #1e40af;
        --accent: #06b6d4;
        --success: #10b981;
        --danger: #ef4444;
        --warning: #f59e0b;
        --info: #3b82f6;
        --dark: #0f172a;
        --dark-light: #1e293b;
        --dark-lighter: #334155;
        --sidebar-bg: #1e293b;
        --sidebar-dark: #0f172a;
        --light: #f8fafc;
        --light-blue: #f0f9ff;
        --white: #ffffff;
        --gray: #64748b;
        --gray-light: #94a3b8;
        --border: rgba(0, 0, 0, 0.1);
        --glass-bg: rgba(255, 255, 255, 0.95);
        --glass-border: rgba(0, 0, 0, 0.1);
        --shadow-sm: 0 1px 3px rgba(0,0,0,0.1);
        --shadow-md: 0 4px 6px rgba(0,0,0,0.1);
        --shadow-lg: 0 10px 15px rgba(0,0,0,0.1);
        --shadow-xl: 0 20px 25px rgba(0,0,0,0.15);
    }
    
    body { 
        font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', sans-serif; 
        background: #0a0e27;
        background-image: 
            radial-gradient(circle at 20% 50%, rgba(37, 99, 235, 0.15) 0%, transparent 50%),
            radial-gradient(circle at 80% 80%, rgba(99, 102, 241, 0.1) 0%, transparent 50%),
            radial-gradient(circle at 40% 20%, rgba(139, 92, 246, 0.08) 0%, transparent 50%),
            linear-gradient(180deg, #0a0e27 0%, #1a1f3a 100%);
        background-attachment: fixed;
        background-size: 100% 100%, 100% 100%, 100% 100%, 100% 100%;
        color: var(--dark);
        line-height: 1.6;
        min-height: 100vh;
        overflow-x: hidden;
        position: relative;
    }
    
    body::before {
        content: '';
        position: fixed;
        top: 0;
        left: 0;
        width: 100%;
        height: 100%;
        background: 
            url('data:image/svg+xml,<svg width="100" height="100" xmlns="http://www.w3.org/2000/svg"><defs><pattern id="stars" width="100" height="100" patternUnits="userSpaceOnUse"><circle cx="20" cy="20" r="1" fill="rgba(255,255,255,0.3)"/><circle cx="80" cy="40" r="0.5" fill="rgba(255,255,255,0.2)"/><circle cx="40" cy="80" r="1" fill="rgba(255,255,255,0.25)"/><circle cx="90" cy="90" r="0.5" fill="rgba(255,255,255,0.2)"/></pattern></defs><rect width="100" height="100" fill="url(%23stars)"/></svg>');
        opacity: 0.4;
        pointer-events: none;
        z-index: 0;
    }
    
    @keyframes gradientShift {
        0% { background-position: 0% 50%; }
        50% { background-position: 100% 50%; }
        100% { background-position: 0% 50%; }
    }
    
    @keyframes float {
        0%, 100% { transform: translateY(0px); }
        50% { transform: translateY(-10px); }
    }
    
    @keyframes pulse {
        0%, 100% { opacity: 1; }
        50% { opacity: 0.5; }
    }
    
    @keyframes pulse-dot {
        0%, 100% { opacity: 1; transform: scale(1); }
        50% { opacity: 0.6; transform: scale(1.2); }
    }
    
    @keyframes slideInRight {
        from {
            opacity: 0;
            transform: translateX(30px);
        }
        to {
            opacity: 1;
            transform: translateX(0);
        }
    }
    
    .app-container {
        display: flex;
        min-height: 100vh;
    }
    
    /* SIDEBAR */
    .sidebar {
        width: 280px;
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.95) 0%, rgba(30, 41, 59, 0.9) 100%);
        backdrop-filter: blur(25px) saturate(180%);
        -webkit-backdrop-filter: blur(25px) saturate(180%);
        border-right: 1px solid rgba(255, 255, 255, 0.12);
        box-shadow: 4px 0 40px rgba(0, 0, 0, 0.4), inset -1px 0 0 rgba(255, 255, 255, 0.05);
        position: fixed;
        height: 100vh;
        overflow-y: auto;
        z-index: 1000;
        transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
    }
    
    .sidebar::-webkit-scrollbar { width: 8px; }
    .sidebar::-webkit-scrollbar-track { background: rgba(0, 0, 0, 0.2); }
    .sidebar::-webkit-scrollbar-thumb { 
        background: linear-gradient(180deg, rgba(37, 99, 235, 0.6) 0%, rgba(99, 102, 241, 0.6) 100%);
        border-radius: 4px;
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    .sidebar::-webkit-scrollbar-thumb:hover {
        background: linear-gradient(180deg, rgba(37, 99, 235, 0.8) 0%, rgba(99, 102, 241, 0.8) 100%);
    }
    
    .sidebar-header {
        padding: 30px 20px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.12);
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
        backdrop-filter: blur(10px);
        position: relative;
        overflow: hidden;
    }
    
    .sidebar-header::before {
        content: '';
        position: absolute;
        top: 0;
        left: 0;
        right: 0;
        height: 2px;
        background: linear-gradient(90deg, transparent 0%, rgba(37, 99, 235, 0.8) 50%, transparent 100%);
    }
    
    .sidebar-header h1 {
        color: white;
        font-size: 24px;
        font-weight: 700;
        margin-bottom: 5px;
        display: flex;
        align-items: center;
        gap: 12px;
        text-shadow: 0 2px 10px rgba(0, 0, 0, 0.3);
    }
    
    .sidebar-logo {
        width: 52px;
        height: 52px;
        background: linear-gradient(135deg, rgba(37, 99, 235, 1) 0%, rgba(99, 102, 241, 1) 50%, rgba(139, 92, 246, 1) 100%);
        border-radius: 14px;
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 800;
        color: white;
        font-size: 22px;
        box-shadow: 0 4px 20px rgba(37, 99, 235, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        position: relative;
        overflow: hidden;
    }
    
    .sidebar-logo::before {
        content: '';
        position: absolute;
        top: -50%;
        left: -50%;
        width: 200%;
        height: 200%;
        background: linear-gradient(45deg, transparent 30%, rgba(255, 255, 255, 0.2) 50%, transparent 70%);
        animation: shine 3s infinite;
    }
    
    @keyframes shine {
        0% { transform: translateX(-100%) translateY(-100%) rotate(45deg); }
        100% { transform: translateX(100%) translateY(100%) rotate(45deg); }
    }
    
    .sidebar-header p {
        color: rgba(255, 255, 255, 0.75);
        font-size: 12px;
        margin-top: 8px;
        text-transform: uppercase;
        letter-spacing: 1px;
        font-weight: 600;
        text-shadow: 0 1px 3px rgba(0, 0, 0, 0.2);
    }
    
    .sidebar-menu {
        padding: 20px 12px;
    }
    
    .menu-item {
        display: flex;
        align-items: center;
        gap: 14px;
        padding: 14px 18px;
        color: rgba(255, 255, 255, 0.85);
        text-decoration: none;
        font-weight: 500;
        font-size: 14px;
        transition: all 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        position: relative;
        margin: 6px 0;
        border-radius: 12px;
        overflow: hidden;
    }
    
    .menu-item::before {
        content: '';
        position: absolute;
        left: 0;
        top: 0;
        bottom: 0;
        width: 3px;
        background: linear-gradient(180deg, rgba(37, 99, 235, 1) 0%, rgba(99, 102, 241, 1) 100%);
        transform: scaleY(0);
        transition: transform 0.3s cubic-bezier(0.4, 0, 0.2, 1);
        border-radius: 0 3px 3px 0;
    }
    
    .menu-item:hover {
        background: linear-gradient(90deg, rgba(37, 99, 235, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
        color: white;
        transform: translateX(4px);
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.2);
    }
    
    .menu-item:hover::before {
        transform: scaleY(1);
    }
    
    .menu-item.active {
        background: linear-gradient(90deg, rgba(37, 99, 235, 0.25) 0%, rgba(99, 102, 241, 0.2) 100%);
        color: white;
        box-shadow: 0 4px 16px rgba(37, 99, 235, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(37, 99, 235, 0.3);
    }
    
    .menu-item.active::before {
        transform: scaleY(1);
    }
    
    .menu-item-icon {
        font-size: 20px;
        width: 28px;
        text-align: center;
        display: flex;
        align-items: center;
        justify-content: center;
        height: 28px;
        border-radius: 8px;
        background: rgba(255, 255, 255, 0.08);
        transition: all 0.3s ease;
    }
    
    .menu-item:hover .menu-item-icon {
        background: rgba(37, 99, 235, 0.2);
        transform: scale(1.1);
    }
    
    .menu-item.active .menu-item-icon {
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.4) 0%, rgba(99, 102, 241, 0.4) 100%);
        box-shadow: 0 2px 8px rgba(37, 99, 235, 0.3);
    }
    
    .sidebar-footer {
        position: absolute;
        bottom: 0;
        left: 0;
        right: 0;
        padding: 20px;
        border-top: 1px solid rgba(255, 255, 255, 0.12);
        background: linear-gradient(180deg, rgba(15, 23, 42, 0.8) 0%, rgba(30, 41, 59, 0.9) 100%);
        backdrop-filter: blur(10px);
    }
    
    .user-info {
        display: flex;
        align-items: center;
        gap: 12px;
        color: white;
        padding: 14px;
        background: linear-gradient(135deg, rgba(37, 99, 235, 0.15) 0%, rgba(99, 102, 241, 0.1) 100%);
        border-radius: 12px;
        margin-bottom: 10px;
        border: 1px solid rgba(255, 255, 255, 0.1);
        box-shadow: 0 4px 12px rgba(0, 0, 0, 0.2);
        transition: all 0.3s ease;
    }
    
    .user-info:hover {
        transform: translateY(-2px);
        box-shadow: 0 6px 16px rgba(37, 99, 235, 0.3);
        border-color: rgba(37, 99, 235, 0.3);
    }
    
    .user-avatar {
        width: 42px;
        height: 42px;
        border-radius: 10px;
        background: linear-gradient(135deg, rgba(37, 99, 235, 1) 0%, rgba(99, 102, 241, 1) 100%);
        display: flex;
        align-items: center;
        justify-content: center;
        font-weight: 700;
        color: white;
        box-shadow: 0 4px 12px rgba(37, 99, 235, 0.4);
        border: 2px solid rgba(255, 255, 255, 0.2);
    }
    
    /* MAIN CONTENT */
    .main-content {
        flex: 1;
        margin-left: 280px;
        padding: 30px;
        min-height: 100vh;
        position: relative;
        z-index: 1;
    }
    
    .main-content > * {
        position: relative;
        z-index: 1;
    }
    
    .top-bar {
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 16px;
        padding: 20px 30px;
        margin-bottom: 30px;
        display: flex;
        justify-content: space-between;
        align-items: center;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
    }
    
    .page-title {
        color: white;
        font-size: 28px;
        font-weight: 700;
        text-shadow: 0 2px 10px rgba(0, 0, 0, 0.2);
    }
    
    .page-subtitle {
        color: rgba(255, 255, 255, 0.7);
        font-size: 14px;
        margin-top: 4px;
        font-weight: 400;
    }
    
    
    .card { 
        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 20px;
        padding: 30px; 
        margin-bottom: 25px; 
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        transition: all 0.3s ease;
        position: relative;
    }
    
    .card:hover {
        transform: translateY(-4px);
        box-shadow: 0 12px 48px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        border-color: rgba(255, 255, 255, 0.25);
        background: rgba(255, 255, 255, 0.12);
    }
    
    .card-header {
        display: flex;
        align-items: center;
        justify-content: space-between;
        margin-bottom: 20px;
        padding-bottom: 15px;
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    .card-title {
        font-size: 18px;
        font-weight: 600;
        color: rgba(255, 255, 255, 0.95);
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    .card h2 {
        color: var(--primary);
        margin-bottom: 25px; 
        font-size: 24px;
        font-weight: 700;
        padding-bottom: 15px;
        border-bottom: 2px solid;
        border-image: linear-gradient(90deg, var(--primary), var(--secondary)) 1;
        display: flex;
        align-items: center;
        gap: 10px;
    }
    
    table { 
        width: 100%; 
        border-collapse: separate;
        border-spacing: 0;
        margin-top: 20px;
        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        border-radius: 16px;
        overflow: hidden;
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
        border: 1px solid rgba(255, 255, 255, 0.15);
    }
    
    th, td { 
        padding: 14px 16px; 
        text-align: left; 
        border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        color: rgba(255, 255, 255, 0.9);
    }
    
    th { 
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px);
        font-weight: 600; 
        color: rgba(255, 255, 255, 0.95);
        font-size: 12px;
        text-transform: uppercase;
        letter-spacing: 0.5px;
    }
    
    tr {
        transition: all 0.15s ease;
    }
    
    tr:hover { 
        background: rgba(255, 255, 255, 0.1);
    }
    
    td strong {
        color: rgba(255, 255, 255, 0.95);
    }
    
    tr:last-child td {
        border-bottom: none;
    }
    
    .btn { 
        padding: 10px 20px; 
        border: none; 
        border-radius: 8px; 
        cursor: pointer; 
        text-decoration: none; 
        display: inline-flex;
        align-items: center;
        gap: 8px;
        font-size: 14px;
        font-weight: 500;
        transition: all 0.2s ease;
        box-shadow: none;
    }
    
    .btn:hover { 
        opacity: 0.9;
        transform: translateY(-1px);
    }
    
    .btn:active {
        transform: translateY(0);
    }
    
    .btn-primary { background: var(--primary); color: white; }
    .btn-danger { background: var(--danger); color: white; }
    .btn-success { background: var(--success); color: white; }
    .btn-warning { background: var(--warning); color: white; }
    
    .form-group { margin-bottom: 20px; }
    .form-group label { 
        display: block; 
        margin-bottom: 8px; 
        font-weight: 600;
        color: var(--dark);
        font-size: 14px;
    }
    
    .form-group input, .form-group select { 
        width: 100%; 
        padding: 12px 16px; 
        border: 1px solid rgba(255, 255, 255, 0.2); 
        border-radius: 12px;
        font-size: 14px;
        transition: all 0.2s ease;
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px) saturate(180%);
        -webkit-backdrop-filter: blur(10px) saturate(180%);
        color: rgba(255, 255, 255, 0.95);
    }
    
    .form-group input::placeholder {
        color: rgba(255, 255, 255, 0.5);
    }
    
    .form-group input:focus, .form-group select:focus {
        outline: none;
        border-color: var(--primary);
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2);
        background: rgba(255, 255, 255, 0.15);
    }
    
    .form-group label {
        color: rgba(255, 255, 255, 0.9);
    }
    
    .form-inline { 
        display: flex; 
        gap: 15px; 
        align-items: end; 
        flex-wrap: wrap;
    }
    
    .form-inline .form-group { 
        flex: 1;
        min-width: 150px;
    }
    
    .badge { 
        padding: 4px 10px; 
        border-radius: 6px; 
        font-size: 11px; 
        font-weight: 500;
        display: inline-flex;
        align-items: center;
        gap: 5px;
        backdrop-filter: blur(10px);
    }
    
    .badge-success { background: rgba(16, 185, 129, 0.2); color: #10b981; border: 1px solid rgba(16, 185, 129, 0.3); }
    .badge-danger { background: rgba(239, 68, 68, 0.2); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .badge-info { background: rgba(59, 130, 246, 0.2); color: #60a5fa; border: 1px solid rgba(59, 130, 246, 0.3); }
    .badge-warning { background: rgba(245, 158, 11, 0.2); color: #fbbf24; border: 1px solid rgba(245, 158, 11, 0.3); }
    
    .flash { 
        padding: 16px 20px; 
        margin-bottom: 25px; 
        border-radius: 12px;
        font-weight: 500;
        display: flex;
        align-items: center;
        gap: 10px;
        animation: slideIn 0.3s ease-out;
    }
    
    @keyframes slideIn {
        from {
            opacity: 0;
            transform: translateY(-10px);
        }
        to {
            opacity: 1;
            transform: translateY(0);
        }
    }
    
    .flash { 
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px) saturate(180%);
        -webkit-backdrop-filter: blur(10px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.15);
        color: rgba(255, 255, 255, 0.95);
    }
    
    .flash.success { 
        background: rgba(16, 185, 129, 0.15); 
        color: #10b981; 
        border-left: 4px solid var(--success);
        border-color: rgba(16, 185, 129, 0.3);
    }
    .flash.error { 
        background: rgba(239, 68, 68, 0.15); 
        color: #f87171; 
        border-left: 4px solid var(--danger);
        border-color: rgba(239, 68, 68, 0.3);
    }
    .flash.info { 
        background: rgba(59, 130, 246, 0.15); 
        color: #60a5fa; 
        border-left: 4px solid var(--info);
        border-color: rgba(59, 130, 246, 0.3);
    }
    
    .stats-grid { 
        display: grid; 
        grid-template-columns: repeat(auto-fit, minmax(280px, 1fr)); 
        gap: 25px; 
        margin-bottom: 30px; 
    }
    
    .stat-card { 
        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 20px;
        padding: 25px;
        position: relative;
        transition: all 0.3s ease;
        box-shadow: 0 8px 32px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    }
    
    .stat-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 12px 48px rgba(0, 0, 0, 0.5), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        border-color: rgba(255, 255, 255, 0.25);
        background: rgba(255, 255, 255, 0.12);
    }
    
    .stat-icon {
        font-size: 28px;
        margin-bottom: 12px;
        color: rgba(255, 255, 255, 0.9);
    }
    
    .stat-label { 
        font-size: 13px; 
        color: rgba(255, 255, 255, 0.7);
        font-weight: 500;
        margin-bottom: 8px;
    }
    
    .stat-value { 
        font-size: 32px; 
        font-weight: 700;
        color: rgba(255, 255, 255, 0.95);
    }
    
    .nodes-list {
        display: flex;
        flex-wrap: wrap;
        gap: 8px;
        margin-top: 5px;
    }
    
    .node-item {
        display: inline-flex;
        align-items: center;
        gap: 6px;
        padding: 6px 12px;
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(5px);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 8px;
        font-size: 13px;
        transition: all 0.2s;
        color: rgba(255, 255, 255, 0.9);
    }
    
    .node-item:hover {
        background: rgba(255, 255, 255, 0.15);
        transform: translateY(-1px);
    }
    
    .node-item.active {
        background: rgba(16, 185, 129, 0.2);
        border-color: var(--success);
    }
    
    .node-item.inactive {
        background: rgba(239, 68, 68, 0.2);
        border-color: var(--danger);
    }
    
    code {
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(5px);
        padding: 4px 8px;
        border-radius: 6px;
        font-family: 'Monaco', 'Courier New', monospace;
        font-size: 13px;
        color: rgba(255, 255, 255, 0.9);
        border: 1px solid rgba(255, 255, 255, 0.1);
    }
    
    /* SEARCH BOX */
    .search-box {
        position: relative;
        margin-bottom: 20px;
    }
    
    .search-box input {
        width: 100%;
        padding: 12px 16px 12px 45px;
        border: 1px solid rgba(255, 255, 255, 0.2);
        border-radius: 12px;
        font-size: 14px;
        background: rgba(255, 255, 255, 0.1);
        backdrop-filter: blur(10px) saturate(180%);
        -webkit-backdrop-filter: blur(10px) saturate(180%);
        transition: all 0.2s ease;
        color: rgba(255, 255, 255, 0.95);
    }
    
    .search-box input::placeholder {
        color: rgba(255, 255, 255, 0.5);
    }
    
    .search-box input:focus {
        outline: none;
        border-color: var(--primary);
        box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2);
        background: rgba(255, 255, 255, 0.15);
    }
    
    .search-box::before {
        content: '🔍';
        position: absolute;
        left: 15px;
        top: 50%;
        transform: translateY(-50%);
        font-size: 18px;
    }
    
    /* QUICK ACTIONS */
    .quick-actions {
        display: flex;
        gap: 15px;
        flex-wrap: wrap;
        margin-bottom: 25px;
    }
    
    .action-card {
        flex: 1;
        min-width: 200px;
        background: rgba(255, 255, 255, 0.08);
        backdrop-filter: blur(20px) saturate(180%);
        -webkit-backdrop-filter: blur(20px) saturate(180%);
        border: 1px solid rgba(255, 255, 255, 0.15);
        border-radius: 20px;
        padding: 20px;
        text-align: center;
        transition: all 0.3s ease;
        cursor: pointer;
        text-decoration: none;
        color: rgba(255, 255, 255, 0.95);
        box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3), inset 0 1px 0 rgba(255, 255, 255, 0.1);
    }
    
    .action-card:hover {
        transform: translateY(-4px);
        box-shadow: 0 8px 30px rgba(0, 0, 0, 0.4), inset 0 1px 0 rgba(255, 255, 255, 0.2);
        border-color: rgba(255, 255, 255, 0.25);
        background: rgba(255, 255, 255, 0.12);
    }
    
    .action-card-title {
        color: rgba(255, 255, 255, 0.95);
    }
    
    .action-card-desc {
        color: rgba(255, 255, 255, 0.7);
    }
    
    .action-card-icon {
        font-size: 36px;
        margin-bottom: 10px;
    }
    
    .action-card-title {
        font-weight: 600;
        color: var(--primary);
        margin-bottom: 5px;
    }
    
    .action-card-desc {
        font-size: 12px;
        color: var(--gray);
    }
    
    /* LOADING */
    .loading {
        display: inline-block;
        width: 20px;
        height: 20px;
        border: 3px solid rgba(99, 102, 241, 0.3);
        border-radius: 50%;
        border-top-color: var(--primary);
        animation: spin 1s ease-in-out infinite;
    }
    
    @keyframes spin {
        to { transform: rotate(360deg); }
    }
    
    /* TOOLTIP */
    .tooltip {
        position: relative;
    }
    
    .tooltip:hover::after {
        content: attr(data-tooltip);
        position: absolute;
        bottom: 100%;
        left: 50%;
        transform: translateX(-50%);
        padding: 8px 12px;
        background: var(--dark);
        color: white;
        border-radius: 8px;
        font-size: 12px;
        white-space: nowrap;
        z-index: 1000;
        margin-bottom: 5px;
    }
    
    /* RESPONSIVE */
    @media (max-width: 768px) {
        .sidebar {
            transform: translateX(-100%);
        }
        
        .main-content {
            margin-left: 0;
        }
        
        .stats-grid {
            grid-template-columns: 1fr;
        }
    }
</style>
<script>
    // Автообновление статистики
    function updateStats() {
        fetch('/api/dashboard/stats')
            .then(r => r.json())
            .then(data => {
                // Обновляем значения на странице если есть элементы
                const elements = document.querySelectorAll('[data-stat]');
                elements.forEach(el => {
                    const stat = el.getAttribute('data-stat');
                    if (data[stat] !== undefined) {
                        el.textContent = data[stat];
                    }
                });
            })
            .catch(err => console.error('Stats update error:', err));
    }
    
    // Обновляем каждые 30 секунд
    setInterval(updateStats, 30000);
    
    // Поиск в таблицах
    function initTableSearch() {
        const searchInputs = document.querySelectorAll('.table-search');
        searchInputs.forEach(input => {
            input.addEventListener('input', function() {
                const filter = this.value.toLowerCase();
                const table = this.closest('.card').querySelector('table');
                if (!table) return;
                
                const rows = table.querySelectorAll('tr');
                rows.forEach((row, index) => {
                    if (index === 0) return; // Пропускаем заголовок
                    const text = row.textContent.toLowerCase();
                    row.style.display = text.includes(filter) ? '' : 'none';
                });
            });
        });
    }
    
    // Инициализация при загрузке
    document.addEventListener('DOMContentLoaded', function() {
        initTableSearch();
        updateStats();
        
        // Анимация появления карточек
        const cards = document.querySelectorAll('.card, .stat-card');
        cards.forEach((card, index) => {
            card.style.opacity = '0';
            card.style.transform = 'translateY(20px)';
            setTimeout(() => {
                card.style.transition = 'all 0.5s ease-out';
                card.style.opacity = '1';
                card.style.transform = 'translateY(0)';
            }, index * 100);
        });
    });
    
    // Копирование в буфер обмена
    function copyToClipboard(text) {
        navigator.clipboard.writeText(text).then(() => {
            alert('Скопировано в буфер обмена!');
        });
    }
</script>
"""

SIDEBAR_HTML = """
    <div class="sidebar">
        <div class="sidebar-header">
            <h1 style="display: flex; align-items: center; gap: 12px;">
                <div class="sidebar-logo">PP</div>
                <div>
                    <div style="color: white; font-size: 20px; font-weight: 700;">Proxy Panel</div>
                    <div style="color: rgba(255, 255, 255, 0.6); font-size: 11px; text-transform: uppercase; letter-spacing: 1px; margin-top: 2px;">Панель управления</div>
                </div>
            </h1>
        </div>
        <div class="sidebar-menu">
            <a href="/" class="menu-item {% if request.path == '/' %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-home"></i></span>
                <span>Главная</span>
            </a>
            <a href="/users" class="menu-item {% if '/users' in request.path %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-users"></i></span>
                <span>Пользователи</span>
            </a>
            <a href="/nodes" class="menu-item {% if '/nodes' in request.path %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-server"></i></span>
                <span>Ноды</span>
            </a>
            <a href="/assignments" class="menu-item {% if '/assignments' in request.path %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-link"></i></span>
                <span>Назначения</span>
            </a>
            <a href="/stats" class="menu-item {% if '/stats' in request.path %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-chart-bar"></i></span>
                <span>Статистика</span>
            </a>
            <a href="/logs" class="menu-item {% if '/logs' in request.path %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-list"></i></span>
                <span>Логи</span>
            </a>
            <a href="/admin/history" class="menu-item {% if '/admin/history' in request.path %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-history"></i></span>
                <span>История действий</span>
            </a>
            <a href="/settings" class="menu-item {% if '/settings' in request.path %}active{% endif %}">
                <span class="menu-item-icon"><i class="fas fa-cog"></i></span>
                <span>Настройки</span>
            </a>
        </div>
        <div class="sidebar-footer">
            <div class="user-info">
                <div class="user-avatar"><i class="fas fa-user-shield"></i></div>
                <div>
                    <div style="font-weight: 600; font-size: 14px;">Администратор</div>
                    <div style="font-size: 12px; opacity: 0.7;">admin</div>
                </div>
            </div>
            <a href="/logout" class="menu-item" style="color: rgba(239, 68, 68, 0.9);">
                <span class="menu-item-icon"><i class="fas fa-sign-out-alt"></i></span>
                <span>Выход</span>
            </a>
        </div>
    </div>
"""

DASHBOARD_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>Панель управления</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <script src="https://cdn.jsdelivr.net/npm/chart.js@4.4.0/dist/chart.umd.min.js"></script>
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title"><i class="fas fa-chart-line"></i> Дашборд</div>
                    <div class="page-subtitle">Обзор системы и статистика в реальном времени</div>
                </div>
                <div style="display: flex; gap: 10px;">
                    <button onclick="location.reload()" class="btn btn-primary" style="padding: 10px 20px;">
                        <i class="fas fa-sync-alt"></i> Обновить
                    </button>
                </div>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="flash {{ category }}"><i class="fas fa-{{ 'check-circle' if category == 'success' else 'exclamation-circle' if category == 'error' else 'info-circle' }}"></i> {{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <div class="stats-grid">
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-users"></i></div>
                    <div class="stat-label">Всего пользователей</div>
                    <div class="stat-value" data-stat="total_users">{{ total_users }}</div>
                    <div style="font-size: 12px; color: var(--gray); margin-top: 5px;">
                        <i class="fas fa-arrow-up" style="color: var(--success);"></i> Активных: {{ total_users }}
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-server"></i></div>
                    <div class="stat-label">Всего нод</div>
                    <div class="stat-value" data-stat="total_nodes">{{ total_nodes }}</div>
                    <div style="font-size: 12px; color: var(--gray); margin-top: 5px;">
                        <i class="fas fa-check-circle" style="color: var(--success);"></i> Активных: {{ active_nodes }}
                </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-plug"></i></div>
                    <div class="stat-label">Активных сессий</div>
                    <div class="stat-value" data-stat="active_sessions">{{ active_sessions }}</div>
                    <div style="font-size: 12px; color: var(--gray); margin-top: 5px;">
                        <i class="fas fa-signal" style="color: var(--info);"></i> В реальном времени
                    </div>
                </div>
                <div class="stat-card">
                    <div class="stat-icon"><i class="fas fa-chart-area"></i></div>
                    <div class="stat-label">Трафик (7 дней)</div>
                    <div class="stat-value" style="font-size: 28px;">{{ "%.2f"|format(total_traffic / 1024 / 1024 / 1024) }}</div>
                    <div style="font-size: 12px; color: var(--gray); margin-top: 5px;">GB</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-chart-line"></i> Трафик за последние 7 дней</div>
                    <div style="display: flex; gap: 10px;">
                        <button onclick="updateChart('traffic')" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                </div>
                </div>
                <canvas id="trafficChart" style="max-height: 300px;"></canvas>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-users"></i> Активность пользователей</div>
                </div>
                <canvas id="usersChart" style="max-height: 300px;"></canvas>
            </div>
            
            <!-- Виджет уведомлений -->
            <div id="notifications-container" style="margin-bottom: 25px;"></div>
            
            <!-- Виджет мониторинга нод -->
            <div class="card" id="nodes-monitor-card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-server"></i> Мониторинг нод в реальном времени</div>
                    <div style="display: flex; gap: 10px; align-items: center;">
                        <span id="nodes-update-status" style="font-size: 12px; color: rgba(255, 255, 255, 0.6);">
                            <i class="fas fa-circle" style="font-size: 8px; color: var(--success); animation: pulse-dot 2s infinite;"></i> Обновляется...
                        </span>
                        <button onclick="updateNodesMonitor()" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                            <i class="fas fa-sync-alt"></i>
                        </button>
                    </div>
                </div>
                <div id="nodes-monitor-content" style="display: grid; grid-template-columns: repeat(auto-fill, minmax(300px, 1fr)); gap: 15px;">
                    <div style="text-align: center; padding: 40px; color: rgba(255, 255, 255, 0.7);">
                        <i class="fas fa-spinner fa-spin" style="font-size: 24px; margin-bottom: 10px;"></i>
                        <div>Загрузка данных о нодах...</div>
                    </div>
                </div>
            </div>
            
            <div class="quick-actions">
                <a href="/users" class="action-card">
                    <div class="action-card-icon"><i class="fas fa-users"></i></div>
                    <div class="action-card-title">Пользователи</div>
                    <div class="action-card-desc">Управление пользователями</div>
                </a>
                <a href="/nodes" class="action-card">
                    <div class="action-card-icon"><i class="fas fa-server"></i></div>
                    <div class="action-card-title">Ноды</div>
                    <div class="action-card-desc">Управление серверами</div>
                </a>
                <a href="/assignments" class="action-card">
                    <div class="action-card-icon"><i class="fas fa-link"></i></div>
                    <div class="action-card-title">Назначения</div>
                    <div class="action-card-desc">Назначение нод</div>
                </a>
                <a href="/stats" class="action-card">
                    <div class="action-card-icon"><i class="fas fa-chart-bar"></i></div>
                    <div class="action-card-title">Статистика</div>
                    <div class="action-card-desc">Аналитика трафика</div>
                </a>
                <a href="/admin/history" class="action-card">
                    <div class="action-card-icon"><i class="fas fa-history"></i></div>
                    <div class="action-card-title">История</div>
                    <div class="action-card-desc">Действия администратора</div>
                </a>
            </div>
            
            {% if recent_logs %}
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-list"></i> Последние подключения</div>
                    <a href="/logs" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                        <i class="fas fa-external-link-alt"></i> Все логи
                    </a>
                </div>
                <table>
                    <tr>
                        <th>Время</th>
                        <th>Пользователь</th>
                        <th>Нода</th>
                        <th>Назначение</th>
                        <th>Статус</th>
                    </tr>
                    {% for log in recent_logs[:10] %}
                    <tr>
                        <td>{{ log.timestamp[:19] if log.timestamp else '-' }}</td>
                        <td><strong>{{ log.username }}</strong></td>
                        <td>{{ log.node_id or 'N/A' }}</td>
                        <td>{{ log.destination }}</td>
                        <td>
                            {% if log.status == 'CONNECTED' %}
                                <span class="badge badge-success"><i class="fas fa-check-circle"></i> Подключено</span>
                            {% else %}
                                <span class="badge badge-danger"><i class="fas fa-times-circle"></i> Отключено</span>
                            {% endif %}
                        </td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            {% endif %}
        </div>
    </div>
    <script>
        // График трафика
        const trafficCtx = document.getElementById('trafficChart');
        const trafficData = {{ traffic_by_day|tojson }};
        
        new Chart(trafficCtx, {
            type: 'line',
            data: {
                labels: trafficData.map(d => new Date(d.date).toLocaleDateString('ru-RU', {day: 'numeric', month: 'short'})),
                datasets: [{
                    label: 'Трафик (GB)',
                    data: trafficData.map(d => d.traffic),
                    borderColor: 'rgb(99, 102, 241)',
                    backgroundColor: 'rgba(99, 102, 241, 0.1)',
                    tension: 0.4,
                    fill: true,
                    pointRadius: 5,
                    pointHoverRadius: 8
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: true,
                plugins: {
                    legend: {
                        display: true,
                        position: 'top'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            callback: function(value) {
                                return value.toFixed(2) + ' GB';
                            }
                        }
                    }
                }
            }
        });
        
        // График пользователей
        fetch('/api/chart/users')
            .then(r => r.json())
            .then(data => {
                const usersCtx = document.getElementById('usersChart');
                new Chart(usersCtx, {
                    type: 'bar',
                    data: {
                        labels: data.map(d => new Date(d.date).toLocaleDateString('ru-RU', {day: 'numeric', month: 'short'})),
                        datasets: [{
                            label: 'Активных пользователей',
                            data: data.map(d => d.users),
                            backgroundColor: 'rgba(139, 92, 246, 0.6)',
                            borderColor: 'rgb(139, 92, 246)',
                            borderWidth: 2
                        }]
                    },
                    options: {
                        responsive: true,
                        maintainAspectRatio: true,
                        plugins: {
                            legend: {
                                display: true,
                                position: 'top'
                            }
                        },
                        scales: {
                            y: {
                                beginAtZero: true,
                                ticks: {
                                    stepSize: 1
                                }
                            }
                        }
                    }
                });
            });
        
        function updateChart(type) {
            location.reload();
        }
        
        // Мониторинг нод в реальном времени
        function updateNodesMonitor() {
            fetch('/api/nodes/status')
                .then(r => r.json())
                .then(nodes => {
                    const container = document.getElementById('nodes-monitor-content');
                    if (nodes.length === 0) {
                        container.innerHTML = '<div style="text-align: center; padding: 40px; color: rgba(255, 255, 255, 0.7);">Ноды не найдены</div>';
                        return;
                    }
                    
                    container.innerHTML = nodes.map(node => {
                        const statusColor = node.is_online ? 'var(--success)' : 'var(--danger)';
                        const statusIcon = node.is_online ? 'fa-check-circle' : 'fa-times-circle';
                        const loadColor = node.load_percent > 90 ? 'var(--danger)' : node.load_percent > 70 ? 'var(--warning)' : 'var(--success)';
                        const activeColor = node.is_active ? 'var(--success)' : 'var(--gray)';
                        
                        return `
                            <div style="background: rgba(255, 255, 255, 0.08); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 12px; padding: 16px; transition: all 0.3s ease;">
                                <div style="display: flex; justify-content: space-between; align-items: start; margin-bottom: 12px;">
                                    <div>
                                        <div style="font-weight: 600; color: rgba(255, 255, 255, 0.95); font-size: 16px; margin-bottom: 4px;">
                                            <i class="fas fa-server" style="color: ${activeColor}; margin-right: 8px;"></i>
                                            ${node.name}
                                        </div>
                                        <div style="font-size: 12px; color: rgba(255, 255, 255, 0.7); font-family: 'Monaco', monospace;">
                                            ${node.host}:${node.port}
                                        </div>
                                    </div>
                                    <div style="text-align: right;">
                                        <div style="font-size: 12px; color: ${statusColor}; margin-bottom: 4px;">
                                            <i class="fas ${statusIcon}"></i> ${node.is_online ? 'Онлайн' : 'Офлайн'}
                                        </div>
                                        <div style="font-size: 11px; color: rgba(255, 255, 255, 0.6);">
                                            ${node.last_seen_ago}
                                        </div>
                                    </div>
                                </div>
                                <div style="margin-top: 12px; padding-top: 12px; border-top: 1px solid rgba(255, 255, 255, 0.1);">
                                    <div style="display: flex; justify-content: space-between; margin-bottom: 8px;">
                                        <span style="font-size: 12px; color: rgba(255, 255, 255, 0.7);">Нагрузка:</span>
                                        <span style="font-size: 12px; font-weight: 600; color: ${loadColor};">
                                            ${node.current_connections}/${node.max_connections} (${node.load_percent}%)
                                        </span>
                                    </div>
                                    <div style="background: rgba(0, 0, 0, 0.3); border-radius: 8px; height: 8px; overflow: hidden;">
                                        <div style="background: linear-gradient(90deg, ${loadColor} 0%, ${loadColor}dd 100%); height: 100%; width: ${Math.min(node.load_percent, 100)}%; transition: width 0.3s ease;"></div>
                                    </div>
                                </div>
                            </div>
                        `;
                    }).join('');
                })
                .catch(err => {
                    console.error('Ошибка загрузки статуса нод:', err);
                    document.getElementById('nodes-monitor-content').innerHTML = 
                        '<div style="text-align: center; padding: 40px; color: var(--danger);">Ошибка загрузки данных</div>';
                });
        }
        
        // Обновление уведомлений
        function updateNotifications() {
            fetch('/api/notifications')
                .then(r => r.json())
                .then(notifications => {
                    const container = document.getElementById('notifications-container');
                    if (notifications.length === 0) {
                        container.innerHTML = '';
                        return;
                    }
                    
                    container.innerHTML = notifications.map(notif => {
                        const bgColor = notif.type === 'error' ? 'rgba(239, 68, 68, 0.15)' : 'rgba(245, 158, 11, 0.15)';
                        const borderColor = notif.type === 'error' ? 'rgba(239, 68, 68, 0.3)' : 'rgba(245, 158, 11, 0.3)';
                        const icon = notif.type === 'error' ? 'fa-exclamation-circle' : 'fa-exclamation-triangle';
                        
                        return `
                            <div class="flash" style="background: ${bgColor}; border-left: 4px solid ${borderColor}; border-color: ${borderColor};">
                                <i class="fas ${icon}" style="color: ${notif.type === 'error' ? 'var(--danger)' : 'var(--warning)'};"></i>
                                <div>
                                    <div style="font-weight: 600; margin-bottom: 4px;">${notif.title}</div>
                                    <div style="font-size: 13px; opacity: 0.9;">${notif.message}</div>
                                </div>
                            </div>
                        `;
                    }).join('');
                })
                .catch(err => console.error('Ошибка загрузки уведомлений:', err));
        }
        
        // Автообновление каждые 10 секунд
        setInterval(() => {
            updateNodesMonitor();
            updateNotifications();
        }, 10000);
        
        // Первоначальная загрузка
        updateNodesMonitor();
        updateNotifications();
    </script>
</body>
</html>
"""

USERS_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>Пользователи</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title"><i class="fas fa-users"></i> Пользователи</div>
                    <div class="page-subtitle">Управление пользователями системы</div>
                </div>
            </div>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card">
            <div class="card-header">
                <div class="card-title"><i class="fas fa-user-plus"></i> Добавить пользователя</div>
            </div>
            <form method="post" action="/users/add" class="form-inline">
                <div class="form-group">
                    <input type="text" name="username" placeholder="Логин" required>
                </div>
                <div class="form-group">
                    <input type="password" name="password" placeholder="Пароль" required>
                </div>
                <div class="form-group">
                    <input type="number" name="device_limit" placeholder="Лимит устройств" value="1" min="1" required>
                </div>
                <button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Добавить</button>
            </form>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-title"><i class="fas fa-users"></i> Список пользователей</div>
                <div style="display: flex; gap: 10px;">
                    <a href="/export/users/csv" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                        <i class="fas fa-download"></i> CSV
                    </a>
                    <a href="/export/users/json" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                        <i class="fas fa-download"></i> JSON
                    </a>
            </div>
            </div>
            <form method="post" action="/users/bulk-action" style="margin-bottom: 20px; padding: 15px; background: rgba(255, 255, 255, 0.08); backdrop-filter: blur(10px); border: 1px solid rgba(255, 255, 255, 0.15); border-radius: 12px;">
                <div style="display: flex; gap: 15px; align-items: center; flex-wrap: wrap;">
                    <div style="flex: 1; min-width: 200px;">
                        <label style="display: block; margin-bottom: 5px; font-weight: 600; font-size: 13px; color: rgba(255, 255, 255, 0.9);">Массовые действия:</label>
                        <select name="action" required style="width: 100%; padding: 10px; border-radius: 8px; border: 1px solid rgba(255, 255, 255, 0.2); background: rgba(255, 255, 255, 0.1); backdrop-filter: blur(10px); color: rgba(255, 255, 255, 0.95);">
                            <option value="" style="background: #1e293b;">Выберите действие</option>
                            <option value="activate" style="background: #1e293b;">Активировать выбранных</option>
                            <option value="deactivate" style="background: #1e293b;">Деактивировать выбранных</option>
                            <option value="delete" style="background: #1e293b;">Удалить выбранных</option>
                        </select>
                    </div>
                    <button type="submit" class="btn btn-warning" style="margin-top: 20px;">
                        <i class="fas fa-tasks"></i> Применить
                    </button>
                </div>
                <div class="search-box" style="margin-top: 15px;">
                <input type="text" class="table-search" placeholder="Поиск пользователей...">
            </div>
            <table>
                <tr>
                        <th style="width: 30px;"><input type="checkbox" id="selectAll" onclick="toggleSelectAll()"></th>
                    <th>Логин</th>
                    <th>Статус</th>
                    <th>Лимит устройств</th>
                        <th>Квота трафика</th>
                    <th>Назначенные ноды</th>
                    <th>Активные сессии</th>
                    <th>Действия</th>
                </tr>
                {% for user in users_data %}
                <tr>
                        <td><input type="checkbox" name="selected_users" value="{{ user.username }}"></td>
                    <td><strong>{{ user.username }}</strong></td>
                    <td>
                        {% if user.is_active %}
                                <span class="badge badge-success"><i class="fas fa-check-circle"></i> Активен</span>
                        {% else %}
                                <span class="badge badge-danger"><i class="fas fa-times-circle"></i> Неактивен</span>
                        {% endif %}
                    </td>
                    <td>
                        <form method="post" action="/users/{{ user.username }}/limit" style="display: inline;">
                                <input type="number" name="device_limit" value="{{ user.device_limit }}" min="1" style="width: 60px; padding: 5px; border-radius: 6px; border: 1px solid var(--border);">
                                <button type="submit" class="btn btn-primary" style="padding: 5px 10px; font-size: 11px;"><i class="fas fa-save"></i></button>
                        </form>
                    </td>
                        <td>
                            {% if user.quota %}
                                {% set usage_percent = ((user.quota.current_usage_gb / user.quota.monthly_limit_gb * 100) if user.quota.monthly_limit_gb > 0 else 0) %}
                                {% set quota_color = 'var(--danger)' if usage_percent > 80 else ('var(--warning)' if usage_percent > 50 else 'var(--success)') %}
                                <div style="font-size: 12px;">
                                    <div><strong>{{ "%.2f"|format(user.quota.current_usage_gb) }} / {{ "%.2f"|format(user.quota.monthly_limit_gb) }} GB</strong></div>
                                    <div style="width: 100px; height: 6px; background: #e2e8f0; border-radius: 3px; margin-top: 4px;">
                                        <div style="width: {{ usage_percent }}%; height: 100%; background: {{ quota_color }}; border-radius: 3px;"></div>
                                    </div>
                                </div>
                                <form method="post" action="/users/{{ user.username }}/quota" style="display: inline; margin-top: 5px;">
                                    <input type="number" name="quota_gb" value="{{ user.quota.monthly_limit_gb }}" min="0" step="0.1" style="width: 70px; padding: 3px; border-radius: 4px; border: 1px solid var(--border); font-size: 11px;">
                                    <button type="submit" class="btn btn-primary" style="padding: 3px 8px; font-size: 10px;"><i class="fas fa-edit"></i></button>
                                </form>
                            {% else %}
                                <form method="post" action="/users/{{ user.username }}/quota" style="display: inline;">
                                    <input type="number" name="quota_gb" placeholder="GB" min="0" step="0.1" style="width: 70px; padding: 5px; border-radius: 6px; border: 1px solid var(--border);">
                                    <button type="submit" class="btn btn-success" style="padding: 5px 10px; font-size: 11px;"><i class="fas fa-plus"></i> Установить</button>
                                </form>
                            {% endif %}
                        </td>
                    <td>
                        {% for node in user.nodes %}
                            <span class="badge badge-info">{{ node.name }}</span>
                        {% endfor %}
                    </td>
                    <td>{{ user.active_sessions }} / {{ user.device_limit }}</td>
                    <td>
                            <a href="/users/{{ user.username }}/toggle" class="btn btn-warning" style="padding: 6px 12px; font-size: 12px;">
                                <i class="fas fa-{{ 'toggle-on' if user.is_active else 'toggle-off' }}"></i> {% if user.is_active %}Деакт.{% else %}Акт.{% endif %}
                            </a>
                            <a href="/users/{{ user.username }}/delete" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;" onclick="return confirm('Удалить пользователя {{ user.username }}?')">
                                <i class="fas fa-trash"></i>
                            </a>
                    </td>
                </tr>
                {% endfor %}
            </table>
            </form>
            <script>
                function toggleSelectAll() {
                    const selectAll = document.getElementById('selectAll');
                    const checkboxes = document.querySelectorAll('input[name="selected_users"]');
                    checkboxes.forEach(cb => cb.checked = selectAll.checked);
                }
                
                document.querySelectorAll('input[name="selected_users"]').forEach(cb => {
                    cb.addEventListener('change', function() {
                        const allChecked = Array.from(document.querySelectorAll('input[name="selected_users"]')).every(c => c.checked);
                        document.getElementById('selectAll').checked = allChecked;
                    });
                });
            </script>
        </div>
        </div>
    </div>
</body>
</html>
"""

NODES_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>Ноды</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title"><i class="fas fa-server"></i> Ноды</div>
                    <div class="page-subtitle">Управление прокси-серверами и мониторинг</div>
                </div>
                <div style="display: flex; gap: 10px;">
                    <a href="/export/nodes/csv" class="btn btn-primary" style="padding: 10px 20px;">
                        <i class="fas fa-download"></i> Экспорт CSV
                    </a>
                    <button onclick="location.reload()" class="btn btn-primary" style="padding: 10px 20px;">
                        <i class="fas fa-sync-alt"></i> Обновить
                    </button>
                </div>
            </div>
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                    <div class="flash {{ category }}">{{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
        <div class="card">
            <div class="card-header">
                <div class="card-title"><i class="fas fa-plus-circle"></i> Добавить ноду</div>
            </div>
            <form method="post" action="/nodes/add" class="form-inline">
                <div class="form-group">
                    <input type="text" name="node_id" placeholder="ID ноды" required>
                </div>
                <div class="form-group">
                    <input type="text" name="name" placeholder="Название" required>
                </div>
                <div class="form-group">
                    <input type="text" name="host" placeholder="IP/Хост" required>
                </div>
                <div class="form-group">
                    <input type="number" name="port" placeholder="Порт" required>
                </div>
                <div class="form-group">
                    <select name="node_type">
                        <option value="http">HTTP</option>
                        <option value="socks5">SOCKS5</option>
                    </select>
                </div>
                <div class="form-group">
                    <input type="text" name="auth_token" placeholder="Токен аутентификации" required>
                </div>
                <button type="submit" class="btn btn-success"><i class="fas fa-plus"></i> Добавить</button>
            </form>
        </div>
        
        <div class="card">
            <div class="card-header">
                <div class="card-title"><i class="fas fa-server"></i> Список нод ({{ nodes_data|length }})</div>
            </div>
            <div class="search-box">
                <input type="text" class="table-search" placeholder="Поиск нод...">
            </div>
            <table>
                <tr>
                    <th>ID</th>
                    <th>Название</th>
                    <th>Адрес</th>
                    <th>Тип</th>
                    <th>Статус</th>
                    <th>Онлайн</th>
                    <th>Нагрузка</th>
                    <th>Подключений</th>
                    <th>Пользователей</th>
                    <th>Последний раз</th>
                    <th>Действия</th>
                </tr>
                {% for node in nodes_data %}
                <tr>
                    <td><code>{{ node.node_id }}</code></td>
                    <td><strong>{{ node.name }}</strong></td>
                    <td><code>{{ node.host }}:{{ node.port }}</code></td>
                    <td><span class="badge badge-info">{{ node.node_type.upper() }}</span></td>
                    <td>
                        {% if node.is_active %}
                            <span class="badge badge-success"><i class="fas fa-check-circle"></i> Активна</span>
                        {% else %}
                            <span class="badge badge-danger"><i class="fas fa-times-circle"></i> Неактивна</span>
                        {% endif %}
                    </td>
                    <td>
                        {% if node.is_online %}
                            <span class="badge badge-success"><i class="fas fa-circle" style="font-size: 8px; animation: pulse-dot 2s infinite; display: inline-block;"></i> Онлайн</span>
                        {% else %}
                            <span class="badge badge-danger"><i class="fas fa-circle"></i> Офлайн</span>
                        {% endif %}
                    </td>
                    <td>
                        <div style="display: flex; align-items: center; gap: 8px;">
                            <div style="width: 80px; height: 8px; background: #e2e8f0; border-radius: 4px; overflow: hidden;">
                                <div style="width: {{ node.load_percent }}%; height: 100%; background: {% if node.load_percent > 80 %}var(--danger){% elif node.load_percent > 50 %}var(--warning){% else %}var(--success){% endif %}; transition: all 0.3s;"></div>
                            </div>
                            <span style="font-size: 12px; font-weight: 600; color: {% if node.load_percent > 80 %}var(--danger){% elif node.load_percent > 50 %}var(--warning){% else %}var(--success){% endif %};">
                                {{ "%.1f"|format(node.load_percent) }}%
                            </span>
                        </div>
                    </td>
                    <td>
                        <strong style="color: {% if node.active_connections >= node.max_connections %}var(--danger){% elif node.active_connections > node.max_connections * 0.8 %}var(--warning){% else %}var(--success){% endif %};">
                            {{ node.active_connections }} / {{ node.max_connections }}
                        </strong>
                    </td>
                    <td><span class="badge badge-info">{{ node.assigned_users }}</span></td>
                    <td style="font-size: 12px; color: rgba(255, 255, 255, 0.7);">
                        {% if node.is_online %}
                            <i class="fas fa-clock"></i> {{ node.last_seen_ago }} назад
                        {% else %}
                            <i class="fas fa-exclamation-triangle"></i> {{ node.last_seen_ago }}
                        {% endif %}
                    </td>
                    <td>
                        <a href="/nodes/{{ node.node_id }}/toggle" class="btn btn-warning" style="padding: 6px 12px; font-size: 12px;">
                            <i class="fas fa-{{ 'toggle-on' if node.is_active else 'toggle-off' }}"></i> {% if node.is_active %}Деакт.{% else %}Акт.{% endif %}
                        </a>
                        <a href="/nodes/{{ node.node_id }}/delete" class="btn btn-danger" style="padding: 6px 12px; font-size: 12px;" onclick="return confirm('Удалить ноду {{ node.name }}?')">
                            <i class="fas fa-trash"></i>
                        </a>
                    </td>
                </tr>
                {% endfor %}
                {% if not nodes_data %}
                <tr>
                    <td colspan="11" style="text-align: center; padding: 40px; color: rgba(255, 255, 255, 0.7);">
                        <i class="fas fa-server" style="font-size: 48px; margin-bottom: 10px; opacity: 0.3;"></i>
                        <p>Ноды не найдены. Добавьте ноду используя форму выше.</p>
                    </td>
                </tr>
                {% endif %}
            </table>
        </div>
        </div>
    </div>
</body>
</html>
"""

ASSIGNMENTS_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>Назначения</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <style>
        .assignments-grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(400px, 1fr));
            gap: 20px;
            margin-bottom: 30px;
        }
        
        .assignment-form-card {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 16px;
            padding: 25px;
            box-shadow: 0 8px 32px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .assignment-form-card:hover {
            transform: translateY(-2px);
            box-shadow: 0 12px 40px rgba(37, 99, 235, 0.3);
            border-color: rgba(37, 99, 235, 0.4);
        }
        
        .assignment-form-card .card-title {
            font-size: 18px;
            font-weight: 600;
            color: rgba(255, 255, 255, 0.95);
            margin-bottom: 20px;
            display: flex;
            align-items: center;
            gap: 10px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .user-assignment-card {
            background: rgba(30, 41, 59, 0.7);
            backdrop-filter: blur(20px) saturate(180%);
            -webkit-backdrop-filter: blur(20px) saturate(180%);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 16px;
            padding: 20px;
            margin-bottom: 15px;
            box-shadow: 0 4px 20px rgba(0, 0, 0, 0.3);
            transition: all 0.3s ease;
        }
        
        .user-assignment-card:hover {
            transform: translateX(5px);
            box-shadow: 0 8px 30px rgba(37, 99, 235, 0.3);
            border-color: rgba(37, 99, 235, 0.4);
        }
        
        .user-header {
            display: flex;
            align-items: center;
            justify-content: space-between;
            margin-bottom: 15px;
            padding-bottom: 15px;
            border-bottom: 1px solid rgba(255, 255, 255, 0.1);
        }
        
        .user-name {
            font-size: 18px;
            font-weight: 700;
            color: rgba(255, 255, 255, 0.95);
            display: flex;
            align-items: center;
            gap: 10px;
        }
        
        .user-status-badge {
            padding: 6px 12px;
            border-radius: 20px;
            font-size: 12px;
            font-weight: 600;
        }
        
        .nodes-grid {
            display: grid;
            grid-template-columns: repeat(auto-fill, minmax(200px, 1fr));
            gap: 12px;
            margin-top: 15px;
        }
        
        .node-card {
            background: rgba(255, 255, 255, 0.08);
            backdrop-filter: blur(10px);
            border: 1px solid rgba(255, 255, 255, 0.15);
            border-radius: 12px;
            padding: 12px;
            display: flex;
            align-items: center;
            justify-content: space-between;
            transition: all 0.2s ease;
            position: relative;
        }
        
        .node-card:hover {
            background: rgba(255, 255, 255, 0.12);
            border-color: var(--primary);
            transform: translateY(-2px);
            box-shadow: 0 4px 12px rgba(0, 0, 0, 0.3);
        }
        
        .node-card.active {
            border-color: var(--success);
            background: rgba(16, 185, 129, 0.15);
        }
        
        .node-card.inactive {
            border-color: var(--danger);
            background: rgba(239, 68, 68, 0.15);
        }
        
        .node-info {
            flex: 1;
        }
        
        .node-name {
            font-weight: 600;
            color: rgba(255, 255, 255, 0.95);
            font-size: 14px;
            margin-bottom: 4px;
        }
        
        .node-address {
            font-size: 12px;
            color: rgba(255, 255, 255, 0.7);
            font-family: 'Monaco', monospace;
        }
        
        .node-remove {
            width: 24px;
            height: 24px;
            border-radius: 50%;
            background: var(--danger);
            color: white;
            border: none;
            cursor: pointer;
            display: flex;
            align-items: center;
            justify-content: center;
            font-size: 16px;
            transition: all 0.2s ease;
            text-decoration: none;
        }
        
        .node-remove:hover {
            background: #dc2626;
            transform: scale(1.1);
        }
        
        .empty-state {
            text-align: center;
            padding: 60px 20px;
            color: var(--gray);
        }
        
        .empty-state-icon {
            font-size: 64px;
            margin-bottom: 20px;
            opacity: 0.3;
        }
        
        .form-select-modern {
            width: 100%;
            padding: 12px 16px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            font-size: 14px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px) saturate(180%);
            -webkit-backdrop-filter: blur(10px) saturate(180%);
            transition: all 0.2s ease;
            color: rgba(255, 255, 255, 0.95);
        }
        
        .form-select-modern:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2);
            background: rgba(255, 255, 255, 0.15);
        }
        
        .form-select-modern option {
            background: #1e293b;
            color: rgba(255, 255, 255, 0.95);
        }
        
        .multi-select-container {
            position: relative;
        }
        
        .multi-select {
            width: 100%;
            min-height: 200px;
            padding: 12px;
            border: 1px solid rgba(255, 255, 255, 0.2);
            border-radius: 12px;
            font-size: 14px;
            background: rgba(255, 255, 255, 0.1);
            backdrop-filter: blur(10px) saturate(180%);
            -webkit-backdrop-filter: blur(10px) saturate(180%);
            color: rgba(255, 255, 255, 0.95);
        }
        
        .multi-select:focus {
            outline: none;
            border-color: var(--primary);
            box-shadow: 0 0 0 3px rgba(37, 99, 235, 0.2);
            background: rgba(255, 255, 255, 0.15);
        }
        
        .multi-select option {
            background: #1e293b;
            color: rgba(255, 255, 255, 0.95);
        }
        
        .empty-state {
            color: rgba(255, 255, 255, 0.7);
        }
        
        .empty-state h3 {
            color: rgba(255, 255, 255, 0.95);
        }
    </style>
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title"><i class="fas fa-link"></i> Назначения</div>
                    <div class="page-subtitle">Управление назначением нод пользователям</div>
                </div>
            </div>
            
        {% with messages = get_flashed_messages(with_categories=true) %}
            {% if messages %}
                {% for category, message in messages %}
                        <div class="flash {{ category }}"><i class="fas fa-{{ 'check-circle' if category == 'success' else 'exclamation-circle' if category == 'error' else 'info-circle' }}"></i> {{ message }}</div>
                {% endfor %}
            {% endif %}
        {% endwith %}
        
            <div class="assignments-grid">
                <div class="assignment-form-card">
                    <div class="card-title">
                        <i class="fas fa-user-plus" style="color: var(--primary);"></i>
                        Одиночное назначение
            </div>
                    <form method="post" action="/assignments/add">
                <div class="form-group">
                            <label style="display: block; margin-bottom: 8px; font-weight: 600; color: rgba(255, 255, 255, 0.9); font-size: 13px;">Пользователь:</label>
                            <select name="username" required class="form-select-modern">
                        <option value="">Выберите пользователя</option>
                        {% for user in users_list %}
                            <option value="{{ user.username }}">{{ user.username }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                            <label style="display: block; margin-bottom: 8px; font-weight: 600; color: rgba(255, 255, 255, 0.9); font-size: 13px;">Нода:</label>
                            <select name="node_id" required class="form-select-modern">
                        <option value="">Выберите ноду</option>
                        {% for node in nodes_list %}
                            <option value="{{ node.node_id }}">{{ node.name }} ({{ node.host }}:{{ node.port }})</option>
                        {% endfor %}
                    </select>
                </div>
                        <button type="submit" class="btn btn-primary" style="width: 100%; margin-top: 10px;">
                            <i class="fas fa-check"></i> Назначить
                        </button>
            </form>
        </div>
        
                <div class="assignment-form-card">
                    <div class="card-title">
                        <i class="fas fa-layer-group" style="color: var(--primary);"></i>
                        Массовое назначение
            </div>
            <form method="post" action="/assignments/bulk">
                <div class="form-group">
                            <label style="display: block; margin-bottom: 8px; font-weight: 600; color: rgba(255, 255, 255, 0.9); font-size: 13px;">Пользователь:</label>
                            <select name="username" required class="form-select-modern">
                        <option value="">Выберите пользователя</option>
                        {% for user in users_list %}
                            <option value="{{ user.username }}">{{ user.username }}</option>
                        {% endfor %}
                    </select>
                </div>
                <div class="form-group">
                            <label style="display: block; margin-bottom: 8px; font-weight: 600; color: rgba(255, 255, 255, 0.9); font-size: 13px;">Ноды (множественный выбор):</label>
                            <div class="multi-select-container">
                                <select name="node_ids" multiple required class="multi-select">
                        {% for node in nodes_list %}
                            <option value="{{ node.node_id }}">{{ node.name }} - {{ node.host }}:{{ node.port }}</option>
                        {% endfor %}
                    </select>
                </div>
                            <small style="color: rgba(255, 255, 255, 0.6); font-size: 12px; margin-top: 5px; display: block;">
                                <i class="fas fa-info-circle"></i> Удерживайте Ctrl (Cmd на Mac) для выбора нескольких нод
                            </small>
                        </div>
                        <button type="submit" class="btn btn-success" style="width: 100%; margin-top: 10px;">
                            <i class="fas fa-check-double"></i> Назначить выбранные
                        </button>
            </form>
                </div>
        </div>
        
        <div class="card">
            <div class="card-header">
                    <div class="card-title">
                        <i class="fas fa-list-check"></i> Текущие назначения
                        <span style="font-size: 14px; font-weight: 500; color: rgba(255, 255, 255, 0.7); margin-left: 10px;">({{ assignments_data|length }} пользователей)</span>
            </div>
                </div>
                
            {% if assignments_data %}
            <div class="search-box">
                <input type="text" class="table-search" placeholder="Поиск назначений...">
            </div>
                
                <div style="display: flex; flex-direction: column; gap: 15px;">
                {% for assignment in assignments_data %}
                    <div class="user-assignment-card">
                        <div class="user-header">
                            <div class="user-name">
                                <i class="fas fa-user" style="color: var(--primary);"></i>
                                {{ assignment.username }}
                            </div>
                            <div style="display: flex; align-items: center; gap: 10px;">
                        {% if assignment.is_active %}
                                    <span class="user-status-badge badge-success">
                                        <i class="fas fa-check-circle"></i> Активен
                                    </span>
                        {% else %}
                                    <span class="user-status-badge badge-danger">
                                        <i class="fas fa-times-circle"></i> Неактивен
                                    </span>
                        {% endif %}
                        <a href="/assignments/remove-all/{{ assignment.username }}" 
                           class="btn btn-danger" 
                           onclick="return confirm('Удалить все назначения у пользователя {{ assignment.username }}?')"
                                   style="padding: 6px 12px; font-size: 12px;">
                                    <i class="fas fa-trash"></i> Удалить все
                                </a>
                            </div>
                        </div>
                        
                        {% if assignment.nodes|length > 0 %}
                        <div class="nodes-grid">
                            {% for node in assignment.nodes %}
                            <div class="node-card {% if node.node_active %}active{% else %}inactive{% endif %}">
                                <div class="node-info">
                                    <div class="node-name">
                                        <i class="fas fa-server" style="font-size: 12px; margin-right: 6px;"></i>
                                        {{ node.node_name }}
                                    </div>
                                    <div class="node-address">{{ node.host }}:{{ node.port }}</div>
                                </div>
                                <a href="/assignments/remove/{{ assignment.username }}/{{ node.node_id }}" 
                                   onclick="return confirm('Удалить ноду {{ node.node_name }} у пользователя {{ assignment.username }}?')"
                                   class="node-remove" title="Удалить">
                                    <i class="fas fa-times"></i>
                                </a>
                            </div>
                {% endfor %}
                        </div>
            {% else %}
                        <div style="text-align: center; padding: 20px; color: rgba(255, 255, 255, 0.7); font-style: italic;">
                            <i class="fas fa-inbox" style="font-size: 24px; opacity: 0.5; margin-bottom: 10px; display: block;"></i>
                            Ноды не назначены
            </div>
            {% endif %}
        </div>
                    {% endfor %}
    </div>
                {% else %}
                <div class="empty-state">
                    <div class="empty-state-icon">
                        <i class="fas fa-link-slash"></i>
                    </div>
                    <h3 style="font-size: 20px; font-weight: 600; margin-bottom: 10px; color: rgba(255, 255, 255, 0.95);">Нет назначений</h3>
                    <p style="color: rgba(255, 255, 255, 0.7);">Назначьте ноды пользователям используя формы выше</p>
                </div>
                {% endif %}
            </div>
        </div>
    </div>
    <script>
        // Поиск по назначениям
        document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.querySelector('.table-search');
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    const filter = this.value.toLowerCase();
                    const cards = document.querySelectorAll('.user-assignment-card');
                    cards.forEach(card => {
                        const text = card.textContent.toLowerCase();
                        card.style.display = text.includes(filter) ? '' : 'none';
                    });
                });
            }
        });
    </script>
</body>
</html>
"""

STATS_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>Статистика</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title"><i class="fas fa-chart-bar"></i> Статистика</div>
                    <div class="page-subtitle">Статистика трафика и подключений</div>
                </div>
            </div>
            
            {% with messages = get_flashed_messages(with_categories=true) %}
                {% if messages %}
                    {% for category, message in messages %}
                        <div class="flash {{ category }}"><i class="fas fa-{{ 'check-circle' if category == 'success' else 'exclamation-circle' if category == 'error' else 'info-circle' }}"></i> {{ message }}</div>
                    {% endfor %}
                {% endif %}
            {% endwith %}
            
            <!-- Фильтры -->
            <div class="card" style="margin-bottom: 25px;">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-filter"></i> Фильтры</div>
                </div>
                <form method="get" action="/stats" style="display: flex; gap: 15px; flex-wrap: wrap; align-items: end;">
                    <div class="form-group" style="flex: 1; min-width: 200px;">
                        <label>Период (дней):</label>
                        <select name="days" class="form-select-modern" onchange="this.form.submit()">
                            <option value="7" {% if days == 7 %}selected{% endif %}>7 дней</option>
                            <option value="14" {% if days == 14 %}selected{% endif %}>14 дней</option>
                            <option value="30" {% if days == 30 %}selected{% endif %}>30 дней</option>
                            <option value="60" {% if days == 60 %}selected{% endif %}>60 дней</option>
                            <option value="90" {% if days == 90 %}selected{% endif %}>90 дней</option>
                        </select>
                    </div>
                    <div class="form-group" style="flex: 1; min-width: 200px;">
                        <label>Начальная дата:</label>
                        <input type="date" name="start_date" value="{{ start_date }}" class="form-select-modern" style="padding: 12px 16px;">
                    </div>
                    <div class="form-group" style="flex: 1; min-width: 200px;">
                        <label>Конечная дата:</label>
                        <input type="date" name="end_date" value="{{ end_date }}" class="form-select-modern" style="padding: 12px 16px;">
                    </div>
                    <div class="form-group">
                        <button type="submit" class="btn btn-primary">
                            <i class="fas fa-search"></i> Применить
                        </button>
                        <a href="/stats" class="btn btn-secondary" style="margin-left: 10px; background: rgba(255, 255, 255, 0.1);">
                            <i class="fas fa-times"></i> Сбросить
                        </a>
                    </div>
                </form>
            </div>
            
        <div class="card">
            <div class="card-header">
                    <div class="card-title"><i class="fas fa-users"></i> Статистика по пользователям</div>
                    <div style="display: flex; gap: 10px;">
                        <a href="/export/stats/csv" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                            <i class="fas fa-download"></i> CSV
                        </a>
                        <a href="/export/stats/json" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                            <i class="fas fa-download"></i> JSON
                        </a>
                    </div>
            </div>
            <div class="search-box">
                <input type="text" class="table-search" placeholder="Поиск по статистике...">
            </div>
            <table>
                <tr>
                    <th>Пользователь</th>
                    <th>Отправлено</th>
                    <th>Получено</th>
                    <th>Всего</th>
                    <th>Подключений</th>
                </tr>
                    {% if user_stats %}
                {% for username, stat in user_stats.items() %}
                <tr>
                    <td><strong>{{ username }}</strong></td>
                    <td>{{ "%.2f"|format(stat.bytes_sent / 1024 / 1024) }} MB</td>
                    <td>{{ "%.2f"|format(stat.bytes_received / 1024 / 1024) }} MB</td>
                            <td><strong>{{ "%.2f"|format((stat.bytes_sent + stat.bytes_received) / 1024 / 1024) }} MB</strong></td>
                    <td>{{ stat.connections }}</td>
                </tr>
                {% endfor %}
                    {% else %}
                        <tr>
                            <td colspan="5" style="text-align: center; padding: 40px; color: rgba(255, 255, 255, 0.7);">
                                <i class="fas fa-inbox" style="font-size: 48px; opacity: 0.3; margin-bottom: 15px; display: block;"></i>
                                Нет данных за выбранный период
                            </td>
                        </tr>
                    {% endif %}
            </table>
        </div>
        </div>
    </div>
    <script>
        // Поиск в таблице
        document.addEventListener('DOMContentLoaded', function() {
            const searchInput = document.querySelector('.table-search');
            if (searchInput) {
                searchInput.addEventListener('input', function() {
                    const filter = this.value.toLowerCase();
                    const table = this.closest('.card').querySelector('table');
                    if (!table) return;
                    
                    const rows = table.querySelectorAll('tr');
                    rows.forEach((row, index) => {
                        if (index === 0) return; // Пропускаем заголовок
                        const text = row.textContent.toLowerCase();
                        row.style.display = text.includes(filter) ? '' : 'none';
                    });
                });
            }
        });
    </script>
</body>
</html>
"""

LOGS_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>Логи</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title">📋 Логи</div>
                    <div class="page-subtitle">История подключений</div>
                </div>
            </div>
        <div class="card">
            <div class="card-header">
                <div class="card-title">📋 Последние подключения</div>
            </div>
            <div class="search-box">
                <input type="text" class="table-search" placeholder="Поиск в логах...">
            </div>
            <table>
                <tr>
                    <th>Время</th>
                    <th>Пользователь</th>
                    <th>IP клиента</th>
                    <th>Нода</th>
                    <th>Назначение</th>
                    <th>Длительность</th>
                    <th>Трафик</th>
                    <th>Статус</th>
                </tr>
                {% for log in logs_data %}
                <tr>
                    <td>{{ log.timestamp }}</td>
                    <td><strong>{{ log.username }}</strong></td>
                    <td>{{ log.client_ip }}</td>
                    <td>{{ log.node_id or 'N/A' }}</td>
                    <td>{{ log.destination }}</td>
                    <td>{{ "%.2f"|format(log.duration_sec) if log.duration_sec else '-' }} сек</td>
                    <td>{{ "%.2f"|format((log.bytes_sent + log.bytes_received) / 1024) if log.bytes_sent else '-' }} KB</td>
                    <td>
                        {% if log.status == 'CONNECTED' %}
                            <span class="badge badge-success">{{ log.status }}</span>
                        {% else %}
                            <span class="badge badge-danger">{{ log.status }}</span>
                        {% endif %}
                    </td>
                </tr>
                {% endfor %}
            </table>
        </div>
        </div>
    </div>
</body>
</html>
"""

# =================================================================
# НОВЫЕ ФУНКЦИИ
# =================================================================

@app.route('/api/dashboard/stats')
@require_login
def api_dashboard_stats():
    """API для получения статистики дашборда"""
    try:
        users = []
        nodes = []
        active_sessions = 0
        daily_traffic = 0
        
        # Быстрые запросы с таймаутами
        try:
            users = db.get_all_users() if hasattr(db, 'get_all_users') else []
            nodes = db.get_all_nodes() if hasattr(db, 'get_all_nodes') else []
        except:
            pass
        
        conn = None
        try:
            conn = db.get_db_connection()
            conn.execute("PRAGMA busy_timeout = 1000")
            with db.db_lock:
                try:
                    cursor = conn.execute("SELECT COUNT(*) as count FROM active_sessions")
                    result = cursor.fetchone()
                    active_sessions = result['count'] if result else 0
                except:
                    active_sessions = 0
                
                try:
                    cursor = conn.execute("""
                        SELECT COALESCE(SUM(bytes_sent + bytes_received), 0) as total 
                        FROM traffic_stats 
                        WHERE date >= date('now', '-24 hours')
                    """)
                    result = cursor.fetchone()
                    daily_traffic = result['total'] if result else 0
                except:
                    daily_traffic = 0
        except:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
        
        return jsonify({
            'total_users': len(users),
            'total_nodes': len(nodes),
            'active_nodes': sum(1 for n in nodes if n.get('is_active', 0)) if nodes else 0,
            'active_sessions': active_sessions,
            'daily_traffic': daily_traffic
        })
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/settings')
@require_login
def settings():
    """Страница настроек"""
    # Получаем список резервных копий
    backups = []
    if os.path.exists(BACKUP_DIR):
        for f in os.listdir(BACKUP_DIR):
            if f.startswith('proxy_panel_backup_') and f.endswith('.db'):
                filepath = os.path.join(BACKUP_DIR, f)
                stat = os.stat(filepath)
                backups.append({
                    'filename': f,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        backups.sort(key=lambda x: x['created'], reverse=True)
    
    return render_template_string(SETTINGS_TEMPLATE, sidebar_html=SIDEBAR_HTML, backups=backups)

# =================================================================
# НОВЫЕ ФУНКЦИИ АДМИНИСТРАТОРА
# =================================================================

@app.route('/export/users/<format>')
@require_login
def export_users(format):
    """Экспорт пользователей в CSV, JSON или PDF"""
    users = db.get_all_users()
    
    if format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Username', 'Active', 'Device Limit', 'Created At'])
        for user in users:
            writer.writerow([user['username'], user['is_active'], user['device_limit'], user.get('created_at', '')])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=users.csv'}
        )
    elif format == 'json':
        return Response(
            json_lib.dumps(users, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=users.json'}
        )
    elif format == 'pdf':
        if not PDF_AVAILABLE:
            flash('PDF экспорт недоступен. Установите reportlab: pip install reportlab', 'error')
            return redirect(url_for('users'))
        return generate_pdf_report(users, 'users')
    return redirect(url_for('users'))

@app.route('/export/nodes/<format>')
@require_login
def export_nodes(format):
    """Экспорт нод в CSV, JSON или PDF"""
    nodes = db.get_all_nodes()
    
    if format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Node ID', 'Name', 'Host', 'Port', 'Type', 'Active', 'Connections'])
        for node in nodes:
            writer.writerow([
                node['node_id'], node['name'], node['host'], node['port'],
                node['node_type'], node['is_active'], node.get('current_connections', 0)
            ])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=nodes.csv'}
        )
    elif format == 'json':
        return Response(
            json_lib.dumps(nodes, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=nodes.json'}
        )
    elif format == 'pdf':
        if not PDF_AVAILABLE:
            flash('PDF экспорт недоступен. Установите reportlab: pip install reportlab', 'error')
            return redirect(url_for('nodes'))
        return generate_pdf_report(nodes, 'nodes')
    return redirect(url_for('nodes'))

@app.route('/export/stats/<format>')
@require_login
def export_stats(format):
    """Экспорт статистики в CSV, JSON или PDF"""
    stats = db.get_traffic_stats(days=30)
    
    if format == 'csv':
        output = io.StringIO()
        writer = csv.writer(output)
        writer.writerow(['Date', 'Username', 'Node ID', 'Bytes Sent', 'Bytes Received', 'Connections'])
        for stat in stats:
            writer.writerow([
                stat['date'], stat['username'], stat.get('node_id', ''),
                stat['bytes_sent'], stat['bytes_received'], stat['connections_count']
            ])
        
        return Response(
            output.getvalue(),
            mimetype='text/csv',
            headers={'Content-Disposition': 'attachment; filename=stats.csv'}
        )
    elif format == 'json':
        return Response(
            json_lib.dumps(stats, indent=2, default=str),
            mimetype='application/json',
            headers={'Content-Disposition': 'attachment; filename=stats.json'}
        )
    elif format == 'pdf':
        if not PDF_AVAILABLE:
            flash('PDF экспорт недоступен. Установите reportlab: pip install reportlab', 'error')
            return redirect(url_for('stats'))
        return generate_pdf_report(stats, 'statistics')
    return redirect(url_for('stats'))

def generate_pdf_report(data, report_type='statistics'):
    """Генерация PDF отчета"""
    if not PDF_AVAILABLE:
        return None
    
    buffer = io.BytesIO()
    doc = SimpleDocTemplate(buffer, pagesize=A4)
    elements = []
    styles = getSampleStyleSheet()
    
    # Заголовок
    title = Paragraph(f"<b>Proxy Panel - {report_type.title()} Report</b>", styles['Title'])
    elements.append(title)
    elements.append(Paragraph(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", styles['Normal']))
    elements.append(Spacer(1, 0.2*inch))
    
    # Данные в таблице
    if report_type == 'statistics' and data:
        table_data = [['Date', 'Username', 'Bytes Sent (MB)', 'Bytes Received (MB)', 'Total (MB)']]
        for stat in data[:100]:  # Ограничиваем 100 записями
            sent_mb = stat.get('bytes_sent', 0) / (1024 ** 2)
            recv_mb = stat.get('bytes_received', 0) / (1024 ** 2)
            total_mb = sent_mb + recv_mb
            table_data.append([
                stat.get('date', ''),
                stat.get('username', ''),
                f"{sent_mb:.2f}",
                f"{recv_mb:.2f}",
                f"{total_mb:.2f}"
            ])
        
        table = Table(table_data)
        table.setStyle(TableStyle([
            ('BACKGROUND', (0, 0), (-1, 0), colors.grey),
            ('TEXTCOLOR', (0, 0), (-1, 0), colors.whitesmoke),
            ('ALIGN', (0, 0), (-1, -1), 'CENTER'),
            ('FONTNAME', (0, 0), (-1, 0), 'Helvetica-Bold'),
            ('FONTSIZE', (0, 0), (-1, 0), 10),
            ('BOTTOMPADDING', (0, 0), (-1, 0), 12),
            ('BACKGROUND', (0, 1), (-1, -1), colors.beige),
            ('GRID', (0, 0), (-1, -1), 1, colors.black)
        ]))
        elements.append(table)
    
    doc.build(elements)
    buffer.seek(0)
    
    return Response(
        buffer.read(),
        mimetype='application/pdf',
        headers={'Content-Disposition': 'attachment; filename=report.pdf'}
    )

# =================================================================
# РЕЗЕРВНОЕ КОПИРОВАНИЕ БД
# =================================================================

BACKUP_DIR = 'backups'
if not os.path.exists(BACKUP_DIR):
    os.makedirs(BACKUP_DIR)

def create_backup():
    """Создает резервную копию базы данных"""
    try:
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        backup_filename = f'proxy_panel_backup_{timestamp}.db'
        backup_path = os.path.join(BACKUP_DIR, backup_filename)
        
        # Копируем основную БД
        db_path = 'proxy_panel.db'
        if os.path.exists(db_path):
            shutil.copy2(db_path, backup_path)
            
            # Удаляем старые бэкапы (оставляем последние 10)
            backups = sorted([f for f in os.listdir(BACKUP_DIR) if f.startswith('proxy_panel_backup_')], reverse=True)
            for old_backup in backups[10:]:
                try:
                    os.remove(os.path.join(BACKUP_DIR, old_backup))
                except:
                    pass
            
            return backup_path
    except Exception as e:
        print(f"[BACKUP ERROR] {e}")
        return None

@app.route('/backup/create')
@require_login
def backup_create():
    """Создание резервной копии вручную"""
    backup_path = create_backup()
    if backup_path:
        flash(f'Резервная копия создана: {os.path.basename(backup_path)}', 'success')
        if hasattr(db, 'log_admin_action'):
            db.log_admin_action('BACKUP_CREATE', ADMIN_USERNAME, 'system', None, 
                              'Создана резервная копия БД', request.remote_addr)
    else:
        flash('Ошибка создания резервной копии', 'error')
    return redirect(url_for('settings'))

@app.route('/backup/list')
@require_login
def backup_list():
    """Список резервных копий"""
    backups = []
    if os.path.exists(BACKUP_DIR):
        for f in os.listdir(BACKUP_DIR):
            if f.startswith('proxy_panel_backup_') and f.endswith('.db'):
                filepath = os.path.join(BACKUP_DIR, f)
                stat = os.stat(filepath)
                backups.append({
                    'filename': f,
                    'size': stat.st_size,
                    'created': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M:%S')
                })
        backups.sort(key=lambda x: x['created'], reverse=True)
    return jsonify(backups)

@app.route('/backup/download/<filename>')
@require_login
def backup_download(filename):
    """Скачать резервную копию"""
    backup_path = os.path.join(BACKUP_DIR, filename)
    if os.path.exists(backup_path) and filename.startswith('proxy_panel_backup_'):
        return Response(
            open(backup_path, 'rb').read(),
            mimetype='application/octet-stream',
            headers={'Content-Disposition': f'attachment; filename={filename}'}
        )
    flash('Резервная копия не найдена', 'error')
    return redirect(url_for('settings'))

# Автоматическое резервное копирование (каждые 24 часа)
def auto_backup_worker():
    """Фоновая задача для автоматического резервного копирования"""
    while True:
        try:
            time.sleep(24 * 60 * 60)  # 24 часа
            create_backup()
            print(f"[AUTO BACKUP] Резервная копия создана: {datetime.now()}")
        except Exception as e:
            print(f"[AUTO BACKUP ERROR] {e}")

# Запуск автоматического резервного копирования в фоне
backup_thread = threading.Thread(target=auto_backup_worker, daemon=True)
backup_thread.start()

# =================================================================
# МОНИТОРИНГ ПРОИЗВОДИТЕЛЬНОСТИ
# =================================================================

@app.route('/api/system/performance')
@require_login
def api_system_performance():
    """API для получения метрик производительности системы"""
    try:
        metrics = {
            'timestamp': datetime.now().isoformat(),
            'cpu_percent': 0,
            'memory_percent': 0,
            'memory_used_mb': 0,
            'memory_total_mb': 0,
            'disk_usage_percent': 0,
            'disk_free_gb': 0,
            'network_sent_mb': 0,
            'network_recv_mb': 0,
            'network_sent_total_mb': 0,
            'network_recv_total_mb': 0,
            'available': PSUTIL_AVAILABLE
        }
        
        if PSUTIL_AVAILABLE:
            try:
                # CPU
                metrics['cpu_percent'] = psutil.cpu_percent(interval=0.1)
                metrics['cpu_count'] = psutil.cpu_count()
                
                # Memory
                mem = psutil.virtual_memory()
                metrics['memory_percent'] = mem.percent
                metrics['memory_used_mb'] = mem.used / (1024 ** 2)
                metrics['memory_total_mb'] = mem.total / (1024 ** 2)
                metrics['memory_available_mb'] = mem.available / (1024 ** 2)
                
                # Disk
                disk = psutil.disk_usage('/')
                metrics['disk_usage_percent'] = disk.percent
                metrics['disk_free_gb'] = disk.free / (1024 ** 3)
                metrics['disk_used_gb'] = disk.used / (1024 ** 3)
                metrics['disk_total_gb'] = disk.total / (1024 ** 3)
                
                # Network
                net_io = psutil.net_io_counters()
                metrics['network_sent_mb'] = net_io.bytes_sent / (1024 ** 2)
                metrics['network_recv_mb'] = net_io.bytes_recv / (1024 ** 2)
                metrics['network_sent_total_mb'] = net_io.bytes_sent / (1024 ** 2)
                metrics['network_recv_total_mb'] = net_io.bytes_recv / (1024 ** 2)
                metrics['network_packets_sent'] = net_io.packets_sent
                metrics['network_packets_recv'] = net_io.packets_recv
            except Exception as e:
                metrics['error'] = str(e)
        
        return jsonify(metrics)
    except Exception as e:
        return jsonify({'error': str(e), 'available': False}), 500

# =================================================================
# ПЛАНИРОВЩИК ЗАДАЧ
# =================================================================

def scheduled_tasks_worker():
    """Расширенная фоновая задача для выполнения запланированных действий"""
    last_backup = None
    last_cleanup = None
    
    while True:
        try:
            time.sleep(60)  # Проверяем каждую минуту
            now = datetime.now()
            
            # Сброс месячных квот (в первый день месяца в 00:00)
            if now.day == 1 and now.hour == 0 and now.minute < 5:
                if hasattr(db, 'reset_monthly_quotas'):
                    db.reset_monthly_quotas()
                    print(f"[SCHEDULER] Месячные квоты сброшены: {now}")
            
            # Автоматическое резервное копирование (каждые 24 часа)
            if last_backup is None or (now - last_backup).total_seconds() >= 24 * 3600:
                backup_path = create_backup()
                if backup_path:
                    last_backup = now
                    print(f"[SCHEDULER] Автоматическая резервная копия создана: {now}")
            
            # Очистка старых логов (раз в день в 03:00)
            if now.hour == 3 and now.minute < 5:
                if last_cleanup is None or (now.date() - last_cleanup.date()).days >= 1:
                    conn = db.get_db_connection()
                    try:
                        with db.db_lock:
                            cutoff_date = (datetime.now() - timedelta(days=90)).strftime('%Y-%m-%d')
                            cursor = conn.execute("DELETE FROM connection_logs WHERE date(timestamp) < ?", (cutoff_date,))
                            deleted_logs = cursor.rowcount
                            cursor = conn.execute("DELETE FROM traffic_stats WHERE date < ?", (cutoff_date,))
                            deleted_stats = cursor.rowcount
                            conn.commit()
                            if deleted_logs > 0 or deleted_stats > 0:
                                print(f"[SCHEDULER] Очищено логов: {deleted_logs}, статистики: {deleted_stats}")
                                last_cleanup = now
                    finally:
                        conn.close()
            
            # Проверка офлайн нод и отправка уведомлений (каждые 5 минут)
            if now.minute % 5 == 0:
                try:
                    nodes = db.get_all_nodes()
                    for node in nodes:
                        if node.get('is_active') and node.get('last_seen'):
                            try:
                                last_seen = datetime.strptime(node['last_seen'], '%Y-%m-%d %H:%M:%S')
                                time_diff = now - last_seen
                                if time_diff.total_seconds() > 600:  # 10 минут
                                    print(f"[SCHEDULER] Предупреждение: Нода {node['name']} офлайн более 10 минут")
                            except:
                                pass
                except:
                    pass
                
        except Exception as e:
            print(f"[SCHEDULER ERROR] {e}")

# Запуск планировщика задач
scheduler_thread = threading.Thread(target=scheduled_tasks_worker, daemon=True)
scheduler_thread.start()

@app.route('/admin/history')
@require_login
def admin_history():
    """История действий администратора"""
    try:
        actions = db.get_admin_actions(limit=500) if hasattr(db, 'get_admin_actions') else []
    except Exception as e:
        # Если таблицы еще нет, возвращаем пустой список
        actions = []
    return render_template_string(ADMIN_HISTORY_TEMPLATE, sidebar_html=SIDEBAR_HTML, actions=actions)

@app.route('/api/chart/traffic')
@require_login
def api_chart_traffic():
    """API для графика трафика"""
    try:
        days = min(int(request.args.get('days', 7)), 30)  # Ограничиваем 30 днями
        data = []
        conn = None
        
        try:
            conn = db.get_db_connection()
            conn.execute("PRAGMA busy_timeout = 1000")
            with db.db_lock:
                for i in range(days-1, -1, -1):
                    date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                    try:
                        cursor = conn.execute("""
                            SELECT COALESCE(SUM(bytes_sent + bytes_received), 0) as total 
                            FROM traffic_stats 
                            WHERE date = ?
                        """, (date,))
                        result = cursor.fetchone()
                        data.append({
                            'date': date,
                            'traffic': (result['total'] or 0) / (1024 ** 3)  # GB
                        })
                    except:
                        data.append({'date': date, 'traffic': 0})
        except:
            # Возвращаем пустые данные при ошибке
            for i in range(days-1, -1, -1):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                data.append({'date': date, 'traffic': 0})
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/chart/users')
@require_login
def api_chart_users():
    """API для графика пользователей"""
    try:
        data = []
        conn = None
        
        try:
            conn = db.get_db_connection()
            conn.execute("PRAGMA busy_timeout = 1000")
            with db.db_lock:
                for i in range(6, -1, -1):
                    date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                    try:
                        cursor = conn.execute("""
                            SELECT COUNT(DISTINCT username) as count 
                            FROM connection_logs 
                            WHERE date(timestamp) = ?
                        """, (date,))
                        result = cursor.fetchone()
                        data.append({
                            'date': date,
                            'users': result['count'] if result else 0
                        })
                    except:
                        data.append({'date': date, 'users': 0})
        except:
            # Возвращаем пустые данные при ошибке
            for i in range(6, -1, -1):
                date = (datetime.now() - timedelta(days=i)).strftime('%Y-%m-%d')
                data.append({'date': date, 'users': 0})
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
        
        return jsonify(data)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/nodes/status')
@require_login
def api_nodes_status():
    """API для получения статуса всех нод в реальном времени"""
    try:
        nodes = []
        result = []
        
        try:
            nodes = db.get_all_nodes() if hasattr(db, 'get_all_nodes') else []
        except:
            nodes = []
        
        now = datetime.now()
        for node in nodes:
            try:
                # Определяем онлайн/офлайн статус
                is_online = False
                last_seen_ago = "Никогда"
                if node.get('last_seen'):
                    try:
                        last_seen = datetime.strptime(node['last_seen'], '%Y-%m-%d %H:%M:%S')
                        time_diff = now - last_seen
                        is_online = time_diff.total_seconds() < 180  # Увеличили до 3 минут для надежности
                        if time_diff.total_seconds() < 60:
                            last_seen_ago = f"{int(time_diff.total_seconds())} сек"
                        elif time_diff.total_seconds() < 3600:
                            last_seen_ago = f"{int(time_diff.total_seconds() / 60)} мин"
                        elif time_diff.total_seconds() < 86400:
                            last_seen_ago = f"{int(time_diff.total_seconds() / 3600)} ч"
                        else:
                            last_seen_ago = f"{time_diff.days} дн"
                    except:
                        pass
                
                # Вычисляем нагрузку (ограничиваем максимум 100% для отображения)
                max_conn = node.get('max_connections', 100)
                current_conn = node.get('current_connections', 0)
                load_percent = (current_conn / max_conn * 100) if max_conn > 0 else 0
                load_percent = min(load_percent, 100.0)  # Ограничиваем до 100%
                
                result.append({
                    'node_id': node.get('node_id', ''),
                    'name': node.get('name', ''),
                    'host': node.get('host', ''),
                    'port': node.get('port', 0),
                    'is_active': bool(node.get('is_active', 0)),
                    'is_online': is_online,
                    'current_connections': current_conn,
                    'max_connections': max_conn,
                    'load_percent': round(load_percent, 1),
                    'last_seen': node.get('last_seen', ''),
                    'last_seen_ago': last_seen_ago,
                    'node_type': node.get('node_type', 'http')
                })
            except:
                pass
        
        return jsonify(result)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

@app.route('/api/notifications')
@require_login
def api_notifications():
    """API для получения уведомлений"""
    try:
        notifications = []
        nodes = []
        conn = None
        
        try:
            nodes = db.get_all_nodes() if hasattr(db, 'get_all_nodes') else []
        except:
            nodes = []
        
        now = datetime.now()
        
        # Проверяем офлайн ноды
        for node in nodes:
            try:
                if node.get('is_active') and node.get('last_seen'):
                    last_seen = datetime.strptime(node['last_seen'], '%Y-%m-%d %H:%M:%S')
                    time_diff = now - last_seen
                    if time_diff.total_seconds() > 300:  # 5 минут
                        notifications.append({
                            'type': 'warning',
                            'title': f'Нода {node.get("name", "Unknown")} не отвечает',
                            'message': f'Последний heartbeat: {int(time_diff.total_seconds() / 60)} мин назад',
                            'timestamp': now.isoformat()
                        })
            except:
                pass
        
        # Проверяем перегруженные ноды
        for node in nodes:
            try:
                if node.get('is_active'):
                    max_conn = node.get('max_connections', 100)
                    current_conn = node.get('current_connections', 0)
                    if max_conn > 0 and (current_conn / max_conn) > 0.9:
                        notifications.append({
                            'type': 'warning',
                            'title': f'Нода {node.get("name", "Unknown")} перегружена',
                            'message': f'Использовано {current_conn}/{max_conn} подключений ({int(current_conn/max_conn*100)}%)',
                            'timestamp': now.isoformat()
                        })
            except:
                pass
        
        # Проверяем пользователей с превышенными квотами
        try:
            conn = db.get_db_connection()
            conn.execute("PRAGMA busy_timeout = 1000")
            with db.db_lock:
                cursor = conn.execute("""
                    SELECT username, monthly_limit_gb, current_usage_gb 
                    FROM traffic_quotas 
                    WHERE monthly_limit_gb > 0 
                    AND current_usage_gb >= monthly_limit_gb * 0.9
                    LIMIT 50
                """)
                for row in cursor.fetchall():
                    usage_percent = (row['current_usage_gb'] / row['monthly_limit_gb'] * 100) if row['monthly_limit_gb'] > 0 else 0
                    if usage_percent >= 100:
                        notifications.append({
                            'type': 'error',
                            'title': f'Квота пользователя {row["username"]} превышена',
                            'message': f'Использовано {row["current_usage_gb"]:.2f} GB из {row["monthly_limit_gb"]} GB',
                            'timestamp': now.isoformat()
                        })
                    elif usage_percent >= 90:
                        notifications.append({
                            'type': 'warning',
                            'title': f'Квота пользователя {row["username"]} почти исчерпана',
                            'message': f'Использовано {row["current_usage_gb"]:.2f} GB из {row["monthly_limit_gb"]} GB ({int(usage_percent)}%)',
                            'timestamp': now.isoformat()
                        })
        except:
            pass
        finally:
            if conn:
                try:
                    conn.close()
                except:
                    pass
        
        return jsonify(notifications)
    except Exception as e:
        return jsonify({'error': str(e)}), 500

# =================================================================
# REST API ДЛЯ ВНЕШНИХ ИНТЕГРАЦИЙ
# =================================================================

def api_auth_required(f):
    """Декоратор для проверки API ключа"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        api_key = request.headers.get('X-API-Key') or request.args.get('api_key')
        # Простая проверка API ключа (можно улучшить, храня ключи в БД)
        expected_key = os.environ.get('API_KEY', 'default_api_key_change_me')
        if not api_key or api_key != expected_key:
            return jsonify({'error': 'Invalid or missing API key'}), 401
        return f(*args, **kwargs)
    return decorated_function

@app.route('/api/v1/users', methods=['GET'])
@api_auth_required
@rate_limit_decorator(max_requests=100, window=60)
def api_v1_users():
    """REST API: Получить список пользователей"""
    users = db.get_all_users()
    return jsonify({
        'success': True,
        'count': len(users),
        'users': [{
            'username': u['username'],
            'is_active': bool(u['is_active']),
            'device_limit': u['device_limit']
        } for u in users]
    })

@app.route('/api/v1/nodes', methods=['GET'])
@api_auth_required
@rate_limit_decorator(max_requests=100, window=60)
def api_v1_nodes():
    """REST API: Получить список нод"""
    nodes = db.get_all_nodes()
    return jsonify({
        'success': True,
        'count': len(nodes),
        'nodes': [{
            'node_id': n['node_id'],
            'name': n['name'],
            'host': n['host'],
            'port': n['port'],
            'node_type': n['node_type'],
            'is_active': bool(n['is_active']),
            'current_connections': n.get('current_connections', 0),
            'max_connections': n.get('max_connections', 100)
        } for n in nodes]
    })

@app.route('/api/v1/stats', methods=['GET'])
@api_auth_required
@rate_limit_decorator(max_requests=50, window=60)
def api_v1_stats():
    """REST API: Получить статистику"""
    days = int(request.args.get('days', 7))
    username = request.args.get('username')
    
    stats = db.get_traffic_stats(days=days, username=username) if hasattr(db, 'get_traffic_stats') else []
    
    return jsonify({
        'success': True,
        'count': len(stats),
        'stats': stats
    })

@app.route('/api/v1/system/health', methods=['GET'])
@api_auth_required
@rate_limit_decorator(max_requests=100, window=60)
def api_v1_health():
    """REST API: Проверка здоровья системы"""
    health = {
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'database': 'connected',
        'nodes_online': 0,
        'nodes_total': 0
    }
    
    try:
        nodes = db.get_all_nodes()
        health['nodes_total'] = len(nodes)
        health['nodes_online'] = sum(1 for n in nodes if n.get('is_active'))
    except:
        health['status'] = 'degraded'
        health['database'] = 'error'
    
    return jsonify(health)

@app.route('/users/<username>/quota', methods=['POST'])
@require_login
def set_user_quota(username):
    """Установка квоты трафика для пользователя"""
    try:
        limit_gb = float(request.form.get('quota_gb', 0))
        if hasattr(db, 'set_traffic_quota'):
            db.set_traffic_quota(username, limit_gb)
            db.log_admin_action('SET_QUOTA', ADMIN_USERNAME, 'user', username, 
                               f'Установлена квота {limit_gb} GB', request.remote_addr)
            flash(f'Квота для {username} установлена: {limit_gb} GB/месяц', 'success')
        else:
            flash('Функция квот не доступна', 'error')
    except ValueError:
        flash('Неверное значение квоты', 'error')
    return redirect(url_for('users'))

@app.route('/users/bulk-action', methods=['POST'])
@require_login
def bulk_user_action():
    """Массовые действия с пользователями"""
    action = request.form.get('action')
    usernames = request.form.getlist('selected_users')
    
    if not usernames:
        flash('Выберите пользователей', 'error')
        return redirect(url_for('users'))
    
    conn = db.get_db_connection()
    try:
        with db.db_lock:
            if action == 'activate':
                for username in usernames:
                    conn.execute("UPDATE users SET is_active = 1 WHERE username = ?", (username,))
                flash(f'Активировано пользователей: {len(usernames)}', 'success')
            elif action == 'deactivate':
                for username in usernames:
                    conn.execute("UPDATE users SET is_active = 0 WHERE username = ?", (username,))
                flash(f'Деактивировано пользователей: {len(usernames)}', 'success')
            elif action == 'delete':
                for username in usernames:
                    if username != ADMIN_USERNAME:
                        conn.execute("DELETE FROM users WHERE username = ?", (username,))
                flash(f'Удалено пользователей: {len(usernames)}', 'info')
            conn.commit()
    finally:
        conn.close()
    
    if hasattr(db, 'log_admin_action'):
        db.log_admin_action('BULK_ACTION', ADMIN_USERNAME, 'users', ','.join(usernames),
                          f'Массовое действие: {action}', request.remote_addr)
    
    return redirect(url_for('users'))

ADMIN_HISTORY_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>История действий</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title"><i class="fas fa-history"></i> История действий</div>
                    <div class="page-subtitle">Журнал действий администратора</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-list"></i> Последние действия</div>
                </div>
                <div class="search-box">
                    <input type="text" class="table-search" placeholder="Поиск в истории...">
                </div>
                <table>
                    <tr>
                        <th>Время</th>
                        <th>Тип действия</th>
                        <th>Цель</th>
                        <th>Описание</th>
                        <th>IP адрес</th>
                    </tr>
                    {% for action in actions %}
                    <tr>
                        <td>{{ action.timestamp[:19] if action.timestamp else '-' }}</td>
                        <td><span class="badge badge-info">{{ action.action_type }}</span></td>
                        <td>
                            {% if action.target_type %}
                                <strong>{{ action.target_type }}:</strong> {{ action.target_id or '-' }}
                            {% else %}
                                -
                            {% endif %}
                        </td>
                        <td>{{ action.description or '-' }}</td>
                        <td><code>{{ action.ip_address or '-' }}</code></td>
                    </tr>
                    {% endfor %}
                    {% if not actions %}
                    <tr>
                        <td colspan="5" style="text-align: center; padding: 40px; color: rgba(255, 255, 255, 0.7);">
                            <i class="fas fa-inbox" style="font-size: 48px; margin-bottom: 10px; opacity: 0.3;"></i>
                            <p>История действий пуста</p>
                        </td>
                    </tr>
                    {% endif %}
                </table>
            </div>
        </div>
    </div>
</body>
</html>
"""

SETTINGS_TEMPLATE = BASE_STYLE + """
<!DOCTYPE html>
<html>
<head>
    <title>Настройки</title>
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
</head>
<body>
    <div class="app-container">
        {{ sidebar_html|safe }}
        <div class="main-content">
            <div class="top-bar">
                <div>
                    <div class="page-title"><i class="fas fa-cog"></i> Настройки</div>
                    <div class="page-subtitle">Конфигурация системы</div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-shield-alt"></i> Безопасность</div>
                </div>
                <p style="color: rgba(255, 255, 255, 0.7); margin-bottom: 20px;">Управление паролями и безопасностью</p>
                <a href="/logout" class="btn btn-danger"><i class="fas fa-key"></i> Сменить пароль администратора</a>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-info-circle"></i> Система</div>
                </div>
                <p style="color: rgba(255, 255, 255, 0.7); margin-bottom: 20px;">Информация о системе</p>
                <div style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                    <div>
                        <div style="font-size: 12px; color: rgba(255, 255, 255, 0.7); margin-bottom: 5px;">Версия панели</div>
                        <div style="font-weight: 600; color: rgba(255, 255, 255, 0.95);"><i class="fas fa-code-branch"></i> v3.0</div>
                    </div>
                    <div>
                        <div style="font-size: 12px; color: rgba(255, 255, 255, 0.7); margin-bottom: 5px;">База данных</div>
                        <div style="font-weight: 600; color: rgba(255, 255, 255, 0.95);"><i class="fas fa-database"></i> SQLite</div>
                    </div>
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-download"></i> Экспорт данных</div>
        </div>
                <p style="color: rgba(255, 255, 255, 0.7); margin-bottom: 20px;">Экспорт данных в различных форматах</p>
                <div style="display: flex; gap: 15px; flex-wrap: wrap;">
                    <a href="/export/users/csv" class="btn btn-primary"><i class="fas fa-file-csv"></i> Экспорт пользователей (CSV)</a>
                    <a href="/export/users/json" class="btn btn-primary"><i class="fas fa-file-code"></i> Экспорт пользователей (JSON)</a>
                    <a href="/export/nodes/csv" class="btn btn-primary"><i class="fas fa-file-csv"></i> Экспорт нод (CSV)</a>
                    <a href="/export/nodes/json" class="btn btn-primary"><i class="fas fa-file-code"></i> Экспорт нод (JSON)</a>
                    <a href="/export/stats/csv" class="btn btn-primary"><i class="fas fa-file-csv"></i> Экспорт статистики (CSV)</a>
                    <a href="/export/stats/json" class="btn btn-primary"><i class="fas fa-file-code"></i> Экспорт статистики (JSON)</a>
    </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-database"></i> Резервное копирование</div>
                    <a href="/backup/create" class="btn btn-success" style="padding: 8px 16px; font-size: 12px;">
                        <i class="fas fa-plus"></i> Создать копию
                    </a>
                </div>
                <p style="color: rgba(255, 255, 255, 0.7); margin-bottom: 20px;">
                    Автоматическое резервное копирование выполняется каждые 24 часа. Последние 10 копий сохраняются.
                </p>
                <div id="backups-list">
                    {% if backups %}
                        <table>
                            <tr>
                                <th>Имя файла</th>
                                <th>Размер</th>
                                <th>Дата создания</th>
                                <th>Действия</th>
                            </tr>
                            {% for backup in backups[:10] %}
                            <tr>
                                <td><code>{{ backup.filename }}</code></td>
                                <td>{{ "%.2f"|format(backup.size / 1024 / 1024) }} MB</td>
                                <td>{{ backup.created }}</td>
                                <td>
                                    <a href="/backup/download/{{ backup.filename }}" class="btn btn-primary" style="padding: 6px 12px; font-size: 12px;">
                                        <i class="fas fa-download"></i> Скачать
                                    </a>
                                </td>
                            </tr>
                            {% endfor %}
                        </table>
                    {% else %}
                        <div style="text-align: center; padding: 40px; color: rgba(255, 255, 255, 0.7);">
                            <i class="fas fa-inbox" style="font-size: 48px; opacity: 0.3; margin-bottom: 15px; display: block;"></i>
                            Резервные копии не найдены
                        </div>
                    {% endif %}
                </div>
            </div>
            
            <div class="card">
                <div class="card-header">
                    <div class="card-title"><i class="fas fa-tachometer-alt"></i> Мониторинг производительности</div>
                    <button onclick="updatePerformanceMetrics()" class="btn btn-primary" style="padding: 8px 16px; font-size: 12px;">
                        <i class="fas fa-sync-alt"></i> Обновить
                    </button>
                </div>
                <div id="performance-metrics" style="display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 15px;">
                    <div style="text-align: center; padding: 20px; color: rgba(255, 255, 255, 0.7);">
                        <i class="fas fa-spinner fa-spin"></i> Загрузка...
                    </div>
                </div>
            </div>
        </div>
    </div>
    <script>
        function updatePerformanceMetrics() {
            fetch('/api/system/performance')
                .then(r => {
                    if (!r.ok) {
                        throw new Error(`HTTP ${r.status}: ${r.statusText}`);
                    }
                    return r.json();
                })
                .then(data => {
                    const container = document.getElementById('performance-metrics');
                    if (!container) {
                        console.error('Container not found');
                        return;
                    }
                    
                    // Проверяем наличие данных
                    if (data.error) {
                        container.innerHTML = `
                            <div style="text-align: center; padding: 20px; color: var(--danger); grid-column: 1 / -1;">
                                <i class="fas fa-exclamation-triangle"></i> Ошибка: ${data.error}
                            </div>
                        `;
                        return;
                    }
                    
                    if (!data.available) {
                        container.innerHTML = `
                            <div style="text-align: center; padding: 20px; color: rgba(255, 255, 255, 0.7); grid-column: 1 / -1;">
                                <i class="fas fa-info-circle"></i> Установите psutil для мониторинга: pip3 install psutil
                                <br><small style="opacity: 0.6;">Если psutil установлен, перезапустите веб-панель</small>
                            </div>
                        `;
                        return;
                    }
                    
                    const cpuColor = data.cpu_percent > 80 ? 'var(--danger)' : data.cpu_percent > 60 ? 'var(--warning)' : 'var(--success)';
                    const memColor = data.memory_percent > 80 ? 'var(--danger)' : data.memory_percent > 60 ? 'var(--warning)' : 'var(--success)';
                    const diskColor = data.disk_usage_percent > 80 ? 'var(--danger)' : data.disk_usage_percent > 60 ? 'var(--warning)' : 'var(--success)';
                    
                    container.innerHTML = `
                        <div style="background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 20px; text-align: center;">
                            <div style="font-size: 12px; color: rgba(255, 255, 255, 0.7); margin-bottom: 8px;">CPU</div>
                            <div style="font-size: 32px; font-weight: 700; color: ${cpuColor}; margin-bottom: 8px;">${data.cpu_percent.toFixed(1)}%</div>
                            <div style="background: rgba(0, 0, 0, 0.3); border-radius: 8px; height: 8px; overflow: hidden;">
                                <div style="background: ${cpuColor}; height: 100%; width: ${data.cpu_percent}%; transition: width 0.3s;"></div>
                            </div>
                        </div>
                        <div style="background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 20px; text-align: center;">
                            <div style="font-size: 12px; color: rgba(255, 255, 255, 0.7); margin-bottom: 8px;">Память</div>
                            <div style="font-size: 32px; font-weight: 700; color: ${memColor}; margin-bottom: 8px;">${data.memory_percent.toFixed(1)}%</div>
                            <div style="font-size: 11px; color: rgba(255, 255, 255, 0.6);">${(data.memory_used_mb / 1024).toFixed(2)} GB / ${(data.memory_total_mb / 1024).toFixed(2)} GB</div>
                            <div style="background: rgba(0, 0, 0, 0.3); border-radius: 8px; height: 8px; overflow: hidden; margin-top: 8px;">
                                <div style="background: ${memColor}; height: 100%; width: ${data.memory_percent}%; transition: width 0.3s;"></div>
                            </div>
                        </div>
                        <div style="background: rgba(255, 255, 255, 0.05); border-radius: 12px; padding: 20px; text-align: center;">
                            <div style="font-size: 12px; color: rgba(255, 255, 255, 0.7); margin-bottom: 8px;">Диск</div>
                            <div style="font-size: 32px; font-weight: 700; color: ${diskColor}; margin-bottom: 8px;">${data.disk_usage_percent.toFixed(1)}%</div>
                            <div style="font-size: 11px; color: rgba(255, 255, 255, 0.6);">Свободно: ${data.disk_free_gb.toFixed(2)} GB</div>
                            <div style="background: rgba(0, 0, 0, 0.3); border-radius: 8px; height: 8px; overflow: hidden; margin-top: 8px;">
                                <div style="background: ${diskColor}; height: 100%; width: ${data.disk_usage_percent}%; transition: width 0.3s;"></div>
                            </div>
                        </div>
                    `;
                })
                .catch(err => {
                    console.error('Performance metrics error:', err);
                    const container = document.getElementById('performance-metrics');
                    if (container) {
                        container.innerHTML = `
                            <div style="text-align: center; padding: 20px; color: var(--danger); grid-column: 1 / -1;">
                                <i class="fas fa-exclamation-triangle"></i> Ошибка загрузки метрик
                                <br><small style="opacity: 0.6; margin-top: 10px; display: block;">${err.message}</small>
                                <br><small style="opacity: 0.6;">Проверьте консоль браузера (F12) для деталей</small>
                            </div>
                        `;
                    }
                });
        }
        
        // Автообновление каждые 30 секунд
        updatePerformanceMetrics();
        setInterval(updatePerformanceMetrics, 30000);
    </script>
</body>
</html>
"""

if __name__ == '__main__':
    # Проверяем существование БД, но не останавливаемся если её нет
    if not os.path.exists('proxy_panel.db'):
        print("⚠️  ВНИМАНИЕ: База данных не найдена. Некоторые функции могут не работать.")
        print("   Запустите panel_server.py для инициализации БД.")
        print("   Продолжаем запуск панели...")
        # Пытаемся создать БД
        try:
            if hasattr(db, 'setup_database'):
                db.setup_database()
                print("✅ База данных создана автоматически")
        except Exception as e:
            print(f"⚠️  Не удалось создать БД: {e}")
    
    # Выполняем миграцию при запуске (быстро, без блокировки)
    try:
        if hasattr(db, 'migrate_database'):
            db.migrate_database()
    except Exception as e:
        print(f"[WARNING] Ошибка миграции: {e}")
    
    print("\n🚀 Веб-панель запущена: http://127.0.0.1:5000/login")
    print("🔑 Логин: admin")
    print("🔑 Пароль: admin123")
    
    # Исправление предупреждения о semaphore: используем правильное завершение
    import signal
    import atexit
    
    def cleanup():
        """Очистка ресурсов при завершении"""
        pass
    
    atexit.register(cleanup)
    
    # Запуск с правильными параметрами
    app.run(host='0.0.0.0', port=5000, debug=False, use_reloader=False, threaded=True)
