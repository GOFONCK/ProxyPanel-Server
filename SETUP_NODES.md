# Настройка нод на 185.120.59.171

## У вас 2 ноды на одном IP: 185.120.59.171

Для работы нескольких нод на одном IP нужно использовать разные порты.

## Вариант 1: Две ноды на разных портах

### Нода 1:
- **IP:** 185.120.59.171
- **Порт:** 1080
- **ID:** `node-185-1`

### Нода 2:
- **IP:** 185.120.59.171
- **Порт:** 1081
- **ID:** `node-185-2`

## Настройка node_client.py для каждой ноды

### На сервере 185.120.59.171 создайте два файла:

#### node_client_1.py (порт 1080):
```python
NODE_ID = 'node-185-1'
NODE_NAME = 'Node 185-1'
NODE_HOST = '185.120.59.171'
NODE_PORT = 1080
NODE_TYPE = 'socks5'
AUTH_TOKEN = 'node_secret_token_185_1'
PANEL_HOST = '178.158.227.243'
```

#### node_client_2.py (порт 1081):
```python
NODE_ID = 'node-185-2'
NODE_NAME = 'Node 185-2'
NODE_HOST = '185.120.59.171'
NODE_PORT = 1081
NODE_TYPE = 'socks5'
AUTH_TOKEN = 'node_secret_token_185_2'
PANEL_HOST = '178.158.227.243'
```

## Запуск нод

На сервере 185.120.59.171:

```bash
# Терминал 1 - Нода 1
python node_client_1.py

# Терминал 2 - Нода 2
python node_client_2.py
```

Или в фоне:
```bash
nohup python node_client_1.py > node1.log 2>&1 &
nohup python node_client_2.py > node2.log 2>&1 &
```

## Добавление нод в веб-панели

1. Откройте http://178.158.227.243:5000/login
2. Перейдите в раздел **"Ноды"**
3. Добавьте первую ноду:
   - ID: `node-185-1`
   - Название: `Node 185-1`
   - IP/Хост: `185.120.59.171`
   - Порт: `1080`
   - Тип: `SOCKS5`
   - Токен: `node_secret_token_185_1`

4. Добавьте вторую ноду:
   - ID: `node-185-2`
   - Название: `Node 185-2`
   - IP/Хост: `185.120.59.171`
   - Порт: `1081`
   - Тип: `SOCKS5`
   - Токен: `node_secret_token_185_2`

## Назначение нод пользователям

1. Перейдите в раздел **"Назначения"**
2. Выберите пользователя
3. Выберите обе ноды (можно выбрать несколько, удерживая Ctrl)
4. Нажмите **"Назначить выбранные ноды"**

Теперь пользователь будет использовать обе ноды с балансировкой нагрузки!

## Автоматический скрипт для создания нод

Создайте файл `create_nodes.py`:

```python
import subprocess
import sys

nodes = [
    {'id': 'node-185-1', 'name': 'Node 185-1', 'port': 1080, 'token': 'node_secret_token_185_1'},
    {'id': 'node-185-2', 'name': 'Node 185-2', 'port': 1081, 'token': 'node_secret_token_185_2'},
]

for node in nodes:
    content = f'''import socket
import threading
import select
import struct
import time
import requests
import logging
import sys

NODE_ID = '{node["id"]}'
NODE_NAME = '{node["name"]}'
NODE_HOST = '185.120.59.171'
NODE_PORT = {node["port"]}
NODE_TYPE = 'socks5'
AUTH_TOKEN = '{node["token"]}'
PANEL_HOST = '178.158.227.243'
PANEL_PORT = 3333
PANEL_URL = f'http://{{PANEL_HOST}}:{{PANEL_PORT}}'

logging.basicConfig(level=logging.INFO, format='[%(asctime)s] %(levelname)s: %(message)s')
logger = logging.getLogger(__name__)

# ... (остальной код из node_client.py)
'''
    with open(f'node_client_{node["port"]}.py', 'w') as f:
        f.write(content)
    print(f"Создан файл node_client_{node['port']}.py")
```

## Проверка работы

После запуска нод проверьте:

1. В веб-панели раздел **"Ноды"** - обе ноды должны быть активны
2. В разделе **"Назначения"** - назначьте обе ноды пользователю
3. Подключитесь к прокси и проверьте IP:
   ```bash
   curl --socks5-hostname user1:pass1@178.158.227.243:8090 https://api.ipify.org
   ```
   
   IP должен быть `185.120.59.171` (балансировка между нодами)

## Масштабирование для тысяч нод

Для работы с тысячами нод рекомендуется:

1. **Использовать базу данных PostgreSQL** вместо SQLite
2. **Добавить пагинацию** в веб-панели
3. **Использовать кэширование** для списка нод
4. **Оптимизировать запросы** к БД
5. **Использовать connection pooling**

Текущая версия поддерживает работу с большим количеством нод, но для оптимальной производительности при тысячах нод нужны дополнительные оптимизации.

