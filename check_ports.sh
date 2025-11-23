#!/bin/bash

# Скрипт для проверки занятых портов

echo "🔍 Проверка портов панели управления:"
echo ""

ports=(3333 8000 8080 8090 5000)
port_names=("Node API" "Client API" "HTTP Proxy" "SOCKS5 Proxy" "Web Panel")

for i in "${!ports[@]}"; do
    port=${ports[$i]}
    name=${port_names[$i]}
    pid=$(lsof -ti :$port 2>/dev/null)
    
    if [ ! -z "$pid" ]; then
        process=$(ps -p $pid -o comm= 2>/dev/null)
        echo "⚠️  Порт $port ($name): ЗАНЯТ процессом $pid ($process)"
    else
        echo "✅ Порт $port ($name): СВОБОДЕН"
    fi
done

echo ""
echo "Для освобождения портов используйте: ./stop_server.sh"



