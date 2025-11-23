# Установка зависимостей Python

## Проблема: externally-managed-environment

Если вы получили ошибку `externally-managed-environment`, это защита Python от установки пакетов в системное окружение.

## Решения

### Решение 1: Виртуальное окружение (РЕКОМЕНДУЕТСЯ) ⭐

Это самый безопасный и правильный способ:

```bash
# 1. Создайте виртуальное окружение
python3 -m venv venv

# 2. Активируйте его
source venv/bin/activate

# 3. Установите зависимости
pip install -r requirements.txt

# 4. Теперь запускайте скрипты через виртуальное окружение
python3 xray_node.py

# Для деактивации виртуального окружения (когда закончите работу):
# deactivate
```

**Важно:** Каждый раз при работе с проектом активируйте виртуальное окружение:
```bash
source venv/bin/activate
```

### Решение 2: Использование pipx (для системных приложений)

Если вы хотите установить как системное приложение:

```bash
# Установите pipx (если нет)
sudo apt install pipx

# Установите зависимости через pipx
pipx install PySocks
pipx inject <пакет> Flask pyjwt requests
```

### Решение 3: Установка через apt (если доступно)

Некоторые пакеты доступны через системный менеджер пакетов:

```bash
# Проверьте доступные пакеты
apt search python3-pysocks
apt search python3-flask
apt search python3-jwt
apt search python3-requests

# Установите доступные
sudo apt install python3-pysocks python3-flask python3-jwt python3-requests
```

**Ограничение:** Версии могут быть старыми.

### Решение 4: --break-system-packages (НЕ РЕКОМЕНДУЕТСЯ)

Можно обойти защиту, но это может сломать систему:

```bash
pip3 install --break-system-packages -r requirements.txt
```

⚠️ **Внимание:** Используйте только если понимаете риски!

## Рекомендуемая установка для проекта

Для проекта Proxy Panel рекомендуется использовать виртуальное окружение:

```bash
# Перейдите в директорию проекта
cd /path/to/proxypanel

# Создайте виртуальное окружение
python3 -m venv venv

# Активируйте его
source venv/bin/activate

# Установите все зависимости
pip install --upgrade pip
pip install -r requirements.txt

# Проверьте установку
python3 -c "import PySocks; import flask; import jwt; import requests; print('Все пакеты установлены!')"
```

## Автоматическая активация виртуального окружения

Создайте скрипт для запуска ноды с автоматической активацией:

### Файл: `run_xray_node.sh`

```bash
#!/bin/bash
# Скрипт для запуска xray_node.py с виртуальным окружением

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

# Активируем виртуальное окружение
if [ ! -d "venv" ]; then
    echo "Виртуальное окружение не найдено. Создаю..."
    python3 -m venv venv
    source venv/bin/activate
    pip install --upgrade pip
    pip install -r requirements.txt
else
    source venv/bin/activate
fi

# Запускаем ноду
python3 xray_node.py
```

Сделайте исполняемым:
```bash
chmod +x run_xray_node.sh
./run_xray_node.sh
```

## Для каждого компонента проекта

### panel_server.py

```bash
source venv/bin/activate
python3 panel_server.py
```

### web_panel.py

```bash
source venv/bin/activate
python3 web_panel.py
```

### xray_node.py

```bash
source venv/bin/activate
python3 xray_node.py
```

## Установка в системные пакеты (альтернатива)

Если вы хотите установить глобально и готовы использовать `--break-system-packages`:

```bash
# Установите все зависимости
pip3 install --break-system-packages -r requirements.txt

# Или по отдельности
pip3 install --break-system-packages Flask pyjwt requests PySocks
```

⚠️ **Используйте с осторожностью!**

## Проверка установки

После установки проверьте:

```bash
# Если используете venv, активируйте его сначала
source venv/bin/activate

# Проверьте импорты
python3 -c "import PySocks; print('PySocks:', PySocks.__version__)"
python3 -c "import flask; print('Flask:', flask.__version__)"
python3 -c "import jwt; print('JWT установлен')"
python3 -c "import requests; print('Requests:', requests.__version__)"
```

## Troubleshooting

### Ошибка: "python3 -m venv: command not found"

Установите пакет для создания виртуальных окружений:

```bash
# Debian/Ubuntu
sudo apt install python3-venv

# CentOS/RHEL
sudo yum install python3-venv

# Fedora
sudo dnf install python3-venv
```

### Ошибка: "No module named 'pip'"

Установите pip в виртуальное окружение:

```bash
python3 -m ensurepip --upgrade
```

### Ошибка: "Permission denied"

Убедитесь, что у вас есть права на создание директории venv:

```bash
# Создайте в домашней директории или используйте sudo для системных пакетов
cd ~
# или
sudo pip3 install --break-system-packages -r requirements.txt
```

## Итоговая рекомендация

**Используйте виртуальное окружение** - это безопасно, правильно и не конфликтует с системными пакетами.

```bash
python3 -m venv venv
source venv/bin/activate
pip install -r requirements.txt
```

