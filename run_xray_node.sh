#!/bin/bash
# Скрипт для запуска xray_node.py с автоматической активацией виртуального окружения

SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "========================================="
echo "Запуск Xray ноды"
echo "========================================="

# Увеличение лимитов системы для больших нагрузок (100-1000+ пользователей)
echo "[INFO] Настраиваю системные лимиты для больших нагрузок..."
ulimit -n 65536 2>/dev/null && echo "[OK] Лимит файловых дескрипторов установлен: 65536" || echo "[WARN] Не удалось увеличить ulimit -n (может потребоваться настройка /etc/security/limits.conf или запуск через systemd)"
ulimit -u 32768 2>/dev/null && echo "[OK] Лимит процессов установлен: 32768" || echo "[WARN] Не удалось увеличить ulimit -u (может потребоваться настройка /etc/security/limits.conf или запуск через systemd)"

# Проверяем наличие виртуального окружения
if [ ! -d "venv" ]; then
    echo "[INFO] Виртуальное окружение не найдено. Создаю..."
    python3 -m venv venv || {
        echo "[ERROR] Не удалось создать виртуальное окружение."
        echo "[INFO] Установите python3-venv: sudo apt install python3-venv"
        exit 1
    }
    
    echo "[INFO] Активирую виртуальное окружение..."
    source venv/bin/activate
    
    echo "[INFO] Обновляю pip..."
    pip install --upgrade pip
    
    echo "[INFO] Устанавливаю зависимости..."
    pip install -r requirements.txt || {
        echo "[ERROR] Не удалось установить зависимости."
        exit 1
    }
    
    echo "[INFO] Зависимости установлены успешно!"
else
    echo "[INFO] Активирую виртуальное окружение..."
    source venv/bin/activate
fi

# Проверяем наличие необходимых модулей
echo "[INFO] Проверяю зависимости..."
python3 -c "import PySocks" 2>/dev/null || {
    echo "[ERROR] PySocks не установлен. Устанавливаю..."
    pip install PySocks
}

python3 -c "import requests" 2>/dev/null || {
    echo "[ERROR] requests не установлен. Устанавливаю..."
    pip install requests
}

echo "[INFO] Все зависимости установлены!"
echo "========================================="
echo ""

# Запускаем ноду
python3 xray_node.py

