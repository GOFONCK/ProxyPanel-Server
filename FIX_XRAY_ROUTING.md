# Исправление маршрутизации трафика через Shadowsocks

## Проблема

При подключении через панель (порт 8090) вы получаете IP ноды (185.120.59.171) вместо IP из Shadowsocks outbound.

**Причина:** В конфиге Xray routing настроен только для VLESS inbound, а трафик из SOCKS5 inbound (который использует нода) идет через DIRECT outbound.

## Решение

### Вариант 1: Использовать ваш конфиг с Shadowsocks (РЕКОМЕНДУЕТСЯ) ⭐

1. **Создайте или отредактируйте ваш конфиг Xray** (например, `/opt/xray_config.json`):

```json
{
  "log": {
    "loglevel": "none"
  },
  "inbounds": [
    {
      "tag": "VLESS_TCP_REALITY_testt",
      "port": 450,
      "listen": "0.0.0.0",
      "protocol": "vless",
      "settings": {
        "clients": [],
        "decryption": "none"
      },
      "sniffing": {
        "enabled": true,
        "destOverride": ["http", "tls", "quic"]
      },
      "streamSettings": {
        "network": "raw",
        "security": "reality",
        "realitySettings": {
          "show": false,
          "xver": 0,
          "target": "yahoo.com:443",
          "shortIds": [""],
          "privateKey": "ваш_приватный_ключ",
          "serverNames": ["yahoo.com", "www.yahoo.com"]
        }
      }
    }
  ],
  "outbounds": [
    {
      "tag": "DIRECT",
      "protocol": "freedom"
    },
    {
      "tag": "BLOCK",
      "protocol": "blackhole"
    },
    {
      "tag": "SHADOWSOCKS_REMOTE",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [
          {
            "port": 990,
            "method": "chacha20-ietf-poly1305",
            "address": "212.102.54.45",
            "password": "ARgvGZywA+gacgGV26Bvmu05+wZmRW/j+AdU+Z8Bt44="
          }
        ]
      },
      "streamSettings": {
        "network": "tcp"
      }
    }
  ],
  "routing": {
    "rules": [
      {
        "ip": ["geoip:private"],
        "type": "field",
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "domain": ["geosite:private"],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "protocol": ["bittorrent"],
        "outboundTag": "BLOCK"
      },
      {
        "type": "field",
        "network": "tcp,udp",
        "inboundTag": ["VLESS_TCP_REALITY_testt"],
        "outboundTag": "SHADOWSOCKS_REMOTE"
      },
      {
        "type": "field",
        "inboundTag": ["socks5-for-node"],
        "outboundTag": "SHADOWSOCKS_REMOTE"
      }
    ],
    "domainStrategy": "AsIs"
  }
}
```

**Важно:** Добавьте последнее правило в routing.rules - оно направляет трафик из SOCKS5 inbound (который использует нода) через Shadowsocks outbound.

2. **В `xray_node.py` укажите путь к конфигу:**

```python
AUTO_START_XRAY = True
XRAY_BINARY_PATH = '/usr/local/bin/xray'
XRAY_CONFIG_PATH = '/opt/xray_config.json'  # Путь к вашему конфигу
```

3. **Перезапустите ноду:**

```bash
# Остановите текущую (Ctrl+C)
python3 xray_node.py
```

**Нода автоматически:**
- Загрузит ваш конфиг
- Добавит SOCKS5 inbound на порт 10808 (если его нет)
- Добавит routing rule для SOCKS5 → Shadowsocks (если его нет)
- Запустит Xray

4. **Проверьте:**

```bash
curl --socks5 pro:pro@192.168.1.122:8090 http://ifconfig.me
```

Теперь должен показаться IP из Shadowsocks outbound (212.102.54.45)!

### Вариант 2: Автоматическое добавление routing rule

Код уже обновлен, чтобы автоматически добавлять routing rule для SOCKS5 inbound. Но для этого нужен ваш конфиг с Shadowsocks outbound.

**Просто:**
1. Создайте конфиг с Shadowsocks outbound (см. выше)
2. Укажите путь в `XRAY_CONFIG_PATH`
3. Перезапустите ноду
4. Routing rule добавится автоматически

### Вариант 3: Ручное добавление правила в конфиг

Если вы уже используете конфиг, просто добавьте в `routing.rules`:

```json
{
  "type": "field",
  "inboundTag": ["socks5-for-node"],
  "outboundTag": "SHADOWSOCKS_REMOTE"
}
```

## Проверка конфигурации

После перезапуска ноды проверьте логи:

```
[XRAY] Конфигурация загружена из: /opt/xray_config.json
[XRAY] SOCKS5 inbound добавлен на порт 10808
[XRAY] Добавлено routing rule: SOCKS5 inbound → SHADOWSOCKS_REMOTE
[XRAY] Xray успешно запущен (PID: ...)
```

## Проверка работы

```bash
# Должен показать IP из Shadowsocks outbound
curl --socks5 pro:pro@192.168.1.122:8090 http://ifconfig.me

# Должен показать IP сервера Shadowsocks
# Ожидаемый IP: 212.102.54.45 (или IP вашего Shadowsocks сервера)
```

## Troubleshooting

### Проблема: Все еще показывается IP ноды

**Причина 1:** Routing rule не добавился
- Проверьте логи ноды - должно быть сообщение о добавлении routing rule
- Проверьте конфиг Xray - должно быть правило для "socks5-for-node"

**Причина 2:** Shadowsocks outbound не найден
- Убедитесь, что в конфиге есть outbound с protocol "shadowsocks"
- Убедитесь, что у outbound есть tag "SHADOWSOCKS_REMOTE"

**Причина 3:** Используется старый конфиг
- Убедитесь, что указан правильный путь в `XRAY_CONFIG_PATH`
- Перезапустите ноду полностью (Ctrl+C и запуск заново)

### Проблема: Ошибка "Invalid outbound tag"

**Причина:** В routing rule указан несуществующий outbound tag

**Решение:** Проверьте, что tag в routing rule совпадает с tag в outbound:
- Routing rule: `"outboundTag": "SHADOWSOCKS_REMOTE"`
- Outbound: `"tag": "SHADOWSOCKS_REMOTE"`

### Проблема: Xray не запускается

**Причина:** Ошибка в конфиге JSON

**Решение:** Проверьте валидность JSON:
```bash
cat /opt/xray_config.json | python3 -m json.tool
```

## Структура правильной конфигурации

```
Клиент → Панель (8090) → Нода (1080) → Xray SOCKS5 (10808)
                                                      ↓
                                              Routing rule
                                          (socks5-for-node → SHADOWSOCKS_REMOTE)
                                                      ↓
                                           Shadowsocks outbound
                                                    ↓
                                          Shadowsocks сервер (212.102.54.45)
                                                    ↓
                                                  Интернет
```

IP, который увидит клиент = IP Shadowsocks сервера (212.102.54.45), а не IP ноды (185.120.59.171).

