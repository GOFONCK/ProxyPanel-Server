# Быстрый старт Xray ноды

## Проблема: "Connection refused" на порту 10808

Если вы видите ошибку:
```
Error connecting to SOCKS5 proxy 127.0.0.1:10808: [Errno 111] Connection refused
```

Это означает, что **Xray не запущен**. Нода работает, но не может подключиться к Xray.

## Решения

### Решение 1: Автоматический запуск Xray (РЕКОМЕНДУЕТСЯ) ⭐

1. **Откройте `xray_node.py` и найдите строки:**

```python
AUTO_START_XRAY = False  # Измените на True
XRAY_BINARY_PATH = '/usr/local/bin/xray'  # Проверьте путь
XRAY_CONFIG_PATH = None  # Или укажите путь к вашему конфигу
```

2. **Измените на:**

```python
AUTO_START_XRAY = True  # Включить автоматический запуск
XRAY_BINARY_PATH = '/usr/local/bin/xray'  # Путь к Xray
XRAY_CONFIG_PATH = None  # Базовый конфиг будет создан автоматически
```

3. **Если у вас есть свой конфиг (например, `xray_config.json`):**

```python
AUTO_START_XRAY = True
XRAY_BINARY_PATH = '/usr/local/bin/xray'
XRAY_CONFIG_PATH = '/opt/xray_config.json'  # Укажите полный путь
```

4. **Перезапустите ноду:**

```bash
# Остановите текущую (Ctrl+C)
# Запустите снова
python3 xray_node.py
```

Теперь Xray будет запускаться автоматически при старте ноды!

### Решение 2: Запуск Xray вручную (если автоматический не работает)

#### Вариант A: Базовый конфиг Xray

1. **Создайте конфиг Xray:**

```bash
cat > /tmp/xray_config.json << 'EOF'
{
  "log": {
    "loglevel": "warning"
  },
  "inbounds": [
    {
      "port": 10808,
      "listen": "127.0.0.1",
      "protocol": "socks",
      "settings": {
        "auth": "noauth",
        "udp": true
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
EOF
```

2. **Запустите Xray:**

```bash
/usr/local/bin/xray run -config /tmp/xray_config.json
```

3. **В другом терминале запустите ноду:**

```bash
source venv/bin/activate
python3 xray_node.py
```

#### Вариант B: Использование вашего конфига

Если у вас есть конфиг с VLESS-TCP-REALITY:

```bash
# Запустите Xray с вашим конфигом
/usr/local/bin/xray run -config /opt/xray_config.json
```

**Важно:** Убедитесь, что в вашем конфиге есть SOCKS5 inbound на порту 10808, или нода автоматически добавит его при загрузке.

## Проверка работы

После запуска Xray проверьте:

```bash
# Проверьте, что Xray запущен
ps aux | grep xray

# Проверьте, что порт 10808 слушается
netstat -an | grep 10808
# или
ss -tulpn | grep 10808
```

Вы должны увидеть процесс Xray и порт 10808 в состоянии LISTEN.

## Использование вашего конфига с VLESS-TCP-REALITY

Если у вас есть конфиг как в файле `xray_config_example.json`:

1. **Сохраните конфиг:**

```bash
nano /opt/xray_config.json
# Вставьте ваш конфиг, сохраните (Ctrl+O, Enter, Ctrl+X)
```

2. **В `xray_node.py` укажите:**

```python
AUTO_START_XRAY = True
XRAY_CONFIG_PATH = '/opt/xray_config.json'
```

3. **Запустите ноду:**

```bash
python3 xray_node.py
```

Нода автоматически:
- Загрузит ваш конфиг
- Добавит SOCKS5 inbound на порт 10808 (если его нет)
- Запустит Xray

## Проблема: Панель управления не запущена

Если вы видите:
```
ERROR: [XRAY NODE] Не удалось подключиться к панели
```

Это означает, что панель управления (`panel_server.py`) не запущена на порту 3333.

**Запустите панель управления:**

```bash
# В отдельном терминале
source venv/bin/activate
python3 panel_server.py
```

Или если панель на другом сервере, укажите IP в `xray_node.py`:

```python
PANEL_HOST = '178.158.227.243'  # IP панели управления
PANEL_PORT = 3333
```

## Быстрая проверка

1. **Xray запущен?**
```bash
ps aux | grep xray
```

2. **Порт 10808 открыт?**
```bash
ss -tulpn | grep 10808
```

3. **Нода подключается?**
Смотрите логи ноды - не должно быть ошибок "Connection refused"

## Troubleshooting

### Ошибка: "Xray не найден"

Проверьте путь к Xray:
```bash
which xray
ls -la /usr/local/bin/xray
```

Если Xray в другом месте, укажите путь в `XRAY_BINARY_PATH`.

### Ошибка: "Ошибка запуска Xray"

Проверьте логи - обычно Xray выводит ошибку конфигурации. Убедитесь, что:
- Конфиг валидный JSON
- Порты не заняты
- Права на выполнение у Xray

### Ошибка: "Порт 10808 уже занят"

Проверьте, что не запущен другой Xray:
```bash
lsof -i :10808
# Убейте процесс или измените порт
```

Или измените порт в конфиге и в `xray_node.py`:
```python
XRAY_SOCKS5_PORT = 10809  # Другой порт
```

