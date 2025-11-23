# Генерация ключей для REALITY протокола

Для работы REALITY протокола в Xray **обязательно нужен** `privateKey`. Это приватный ключ сервера, который используется для шифрования.

## Что такое REALITY ключи?

REALITY использует пару ключей:
- **privateKey** (приватный ключ) - используется на **сервере** (в вашем конфиге Xray)
- **publicKey** (публичный ключ) - используется на **клиенте** (в клиентском приложении)

## Способы генерации ключей

### Способ 1: Используя Xray (рекомендуется)

Если Xray уже установлен, используйте встроенную команду:

```bash
# Генерация пары ключей
/usr/local/bin/xray x25519

# Вывод будет примерно таким:
# Private key: xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
# Public key:  yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
```

**Используйте:**
- `Private key` → в конфиге сервера как `"privateKey"`
- `Public key` → в конфиге клиента как `"publicKey"`

### Способ 2: Используя OpenSSL

```bash
# Генерация приватного ключа
openssl genpkey -algorithm x25519 -out private_key.pem

# Извлечение приватного ключа в формате base64
openssl pkey -in private_key.pem -noout -text | grep -A 1 "priv:" | tail -1 | tr -d ' :\n'

# Генерация публичного ключа из приватного
openssl pkey -in private_key.pem -pubout -outform DER | tail -c +13 | base64
```

### Способ 3: Используя Python скрипт

Создайте файл `generate_reality_keys.py`:

```python
#!/usr/bin/env python3
import base64
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey

# Генерация приватного ключа
private_key = X25519PrivateKey.generate()
private_bytes = private_key.private_bytes_raw()
private_key_b64 = base64.b64encode(private_bytes).decode('utf-8')

# Генерация публичного ключа
public_key = private_key.public_key()
public_bytes = public_key.public_bytes_raw()
public_key_b64 = base64.b64encode(public_bytes).decode('utf-8')

print("Private key (для сервера):", private_key_b64)
print("Public key (для клиента):", public_key_b64)
```

Запустите:
```bash
# Установите библиотеку если нужно
pip install cryptography

# Запустите скрипт
python3 generate_reality_keys.py
```

### Способ 4: Онлайн генератор (не рекомендуется для продакшена)

Можно использовать онлайн генераторы, но **не рекомендуется** для продакшена из-за безопасности:
- https://github.com/XTLS/Xray-core/issues/1586 (примеры генераторов в issues)

## Пример использования

### 1. Сгенерируйте ключи

```bash
/usr/local/bin/xray x25519
```

Вывод:
```
Private key: aK9V3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z2
Public key:  bL0W4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z2A3
```

### 2. Добавьте в конфиг сервера (xray_config.json)

```json
{
  "inbounds": [
    {
      "tag": "VLESS_TCP_REALITY_testt",
      "port": 450,
      "protocol": "vless",
      "streamSettings": {
        "security": "reality",
        "realitySettings": {
          "privateKey": "aK9V3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z2",
          "serverNames": ["yahoo.com", "www.yahoo.com"],
          "target": "yahoo.com:443"
        }
      }
    }
  ]
}
```

### 3. Используйте в клиентском конфиге

```json
{
  "outbounds": [
    {
      "protocol": "vless",
      "settings": {
        "vnext": [
          {
            "address": "your-server-ip",
            "port": 450,
            "users": [
              {
                "id": "your-uuid",
                "encryption": "none"
              }
            ]
          }
        ]
      },
      "streamSettings": {
        "security": "reality",
        "realitySettings": {
          "publicKey": "bL0W4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z2A3",
          "serverName": "yahoo.com",
          "shortId": ""
        }
      }
    }
  ]
}
```

## Важные моменты

1. **privateKey** должен быть **секретным** - не публикуйте его нигде
2. **publicKey** можно безопасно передавать клиентам
3. Ключи должны быть в формате **base64** (обычно 43-44 символа)
4. Один **privateKey** может использоваться для генерации множества **publicKey** (но обычно используется одна пара)

## Проверка ключей

После генерации проверьте формат:

```bash
# Ключ должен быть base64 строкой длиной примерно 43-44 символа
echo "aK9V3X4Y5Z6A7B8C9D0E1F2G3H4I5J6K7L8M9N0O1P2Q3R4S5T6U7V8W9X0Y1Z2" | wc -c
# Должно быть примерно 43-44 (включая перевод строки)
```

## Безопасность

- ✅ Генерируйте ключи на **безопасном сервере**
- ✅ Храните **privateKey** в секрете
- ✅ Используйте **сильные случайные ключи**
- ❌ Не используйте один и тот же ключ для разных серверов
- ❌ Не публикуйте privateKey в публичных репозиториях

## Быстрая генерация (одна команда)

```bash
# Если Xray установлен
/usr/local/bin/xray x25519 > reality_keys.txt

# Затем откройте файл
cat reality_keys.txt

# Скопируйте ключи в конфиг
```

## Troubleshooting

### Ошибка: "xray: command not found"
Установите Xray или используйте другой способ генерации (Python скрипт или OpenSSL).

### Ошибка: "Invalid private key"
Убедитесь, что ключ в формате base64 и имеет правильную длину (43-44 символа).

### Ошибка: "Key mismatch"
Убедитесь, что publicKey на клиенте соответствует privateKey на сервере (они должны быть парой).

