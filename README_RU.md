🌐 [English](README.md) | [中文](README_CN.md)

# AIVPN

[![CI](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml/badge.svg?branch=master)](https://github.com/infosave2007/aivpn/actions/workflows/ci.yml)
[![Crates.io Server](https://img.shields.io/crates/v/aivpn-server.svg?label=aivpn-server)](https://crates.io/crates/aivpn-server)
[![Crates.io Client](https://img.shields.io/crates/v/aivpn-client.svg?label=aivpn-client)](https://crates.io/crates/aivpn-client)
![Rust](https://img.shields.io/badge/rust-1.75%2B-blue.svg)
![Platforms](https://img.shields.io/badge/platforms-Linux%20%7C%20macOS%20%7C%20Windows%20%7C%20Android%20%7C%20iOS%20%7C%20MikroTik-informational)

---

## Обзор

AIVPN — VPN-система на базе UDP, совмещающая шифрование туннеля с **мимикрией трафика**: исходящие пакеты маскируются под известные прикладные протоколы (WebRTC, QUIC, DNS-over-UDP), и соединение становится статистически неотличимым от обычного приложения для пассивного наблюдателя.

Ключевые технические характеристики:

- **Zero-RTT** — зашифрованный трафик может пойти с первого пакета, обязательного рукопожатия нет.
- **O(1) поиск сессий** — идентификатор сессии не передаётся в открытом виде. Каждый пакет несёт 8-байтовый *резонансный тег*, выведенный из временной метки и ключа сессии. Сервер находит сессию за константное время через `DashMap`.
- **Совершенная прямая секретность** — ротация ключей сессии по X25519 в режиме рэтчет. Компрометация ключа сервера не раскрывает прошлый трафик.
- **Модуль Neural Resonance** — micro-MLP (~66 КБ) на каждую маску следит за статистикой трафика; высокая ошибка реконструкции (MSE) запускает автоматическую ротацию маски без разрыва соединения клиента.
- **Генеративные распределения масок** — маски, авто-записанные из реального трафика, моделируют мультимодальное поведение размеров пакетов и межпакетных интервалов смесью гауссиан (число мод по BIC; направление §4 «нейро-генерируемые маски»), воспроизводя реальные распределения DNS/QUIC/WebRTC значительно точнее унимодальной модели. Это внутреннее представление, которое каждый клиент сэмплирует прозрачно, а не отдельный тип маски.
- **Написан на Rust** — нет GC, нет утечек памяти. Клиентский бинарник ≈ 2,5 МБ. Работает на VPS за $5.

---

## Архитектура

### Структура воркспейса

```
crates/aivpn-common/     — общая крипто, протокол, маски (без I/O)
crates/aivpn-server/     — VPN-шлюз и управляющий CLI (только Linux)
crates/aivpn-client/     — кроссплатформенный клиент (Linux / macOS / Windows)
crates/aivpn-android-core/ — JNI-мост для Android (Rust → Kotlin via C FFI)
crates/aivpn-ios-core/   — iOS Rust staticlib (C FFI), линкуется в PacketTunnelProvider
crates/aivpn-windows/    — Windows GUI (egui/eframe 0.31, управляет subprocess aivpn-client.exe)
crates/aivpn-linux/      — Linux GUI (iced 0.13, обёртка над subprocess aivpn-client)
platforms/android/       — Android Kotlin (MVVM: MainViewModel + RecyclerView)
platforms/ios/           — iOS SwiftUI + NetworkExtension PacketTunnelProvider
platforms/macos/         — macOS SwiftUI в строке меню + привилегированный демон
platforms/aivpn-web/     — Веб-панель управления (Hono 4 + SvelteKit 2, SQLite/PostgreSQL)
platforms/linux/         — упаковка для Linux (AppImage, .desktop)
platforms/linux-kernel/  — необязательный модуль ядра для пути данных
platforms/openwrt/       — пакет для OpenWrt
platforms/mikrotik/      — контейнер для MikroTik RouterOS
assets/masks/            — встроенные профили мимикрии (JSON)
assets/brand/            — иконки и брендовые материалы
deploy/                  — установщик сервера, systemd-юнит, Dockerfile
deploy/ci/               — гейты CI, запускаемые из Makefile (см. `make help`)
```

### Ключевые модули

| Модуль | Расположение | Назначение |
|--------|-------------|-----------|
| `crypto.rs` | `aivpn-common` | X25519, ChaCha20-Poly1305, BLAKE3/HMAC, генерация резонансных тегов |
| `protocol.rs` | `aivpn-common` | Wire-формат: `[8-byte tag][pad_len][inner_header][encrypted payload][poly1305 tag]` |
| `mask.rs` | `aivpn-common` | `MaskProfile` — шейпинг трафика: шаблоны заголовков, FSM, IAT-распределения |
| `gateway.rs` | `aivpn-server` | Центральный event loop: UDP-приём, диспетчер сессий, NAT, нейронные проверки |
| `session.rs` | `aivpn-server` | `SessionManager` — O(1) через `DashMap`, окно воспроизведения на 256 записей |
| `neural.rs` | `aivpn-server` | Neural Resonance: MLP 64→128→64 на маску, порог MSE 0,35, авто-ротация |
| `client.rs` | `aivpn-client` | Машина состояний: Unprovisioned → Connecting → Connected |
| `tunnel.rs` | `aivpn-client` | TUN: `/dev/net/tun` (Linux), `utun` (macOS), Wintun (Windows) |
| `mimicry.rs` | `aivpn-client` | `MimicryEngine` — применяет `MaskProfile` к исходящим пакетам |

### Синхронизация пула

Синхронизация клиентских баз между серверами пула использует `ControlPayload::PoolSync` внутри обычных VPN UDP-пакетов — неотличима от клиентского трафика. Отдельный TCP-порт и правило файрволла не нужны.

---

## Поддерживаемые платформы

| Платформа | Сервер | Клиент | GUI | TUN-драйвер |
|-----------|:------:|:------:|:---:|-------------|
| Linux CLI | ✅ | ✅ | — | `/dev/net/tun` |
| Linux GUI | — | ✅ | ✅ iced AppImage + трей | `/dev/net/tun` |
| macOS | — | ✅ | ✅ строка меню | `utun` |
| Windows | — | ✅ | ✅ egui GUI | [Wintun](https://www.wintun.net/) |
| Android | — | ✅ | ✅ нативный Kotlin | `VpnService` API |
| iOS | — | ✅ | ✅ SwiftUI | `NetworkExtension` |
| MikroTik RouterOS 7.6+ | — | ✅ | — | контейнер veth + TUN |
| Entware-роутеры (ARMv7 / MIPSel) | — | ✅ | — | статический musl-бинарник |

### Таблица функциональных возможностей

| Функция | Linux CLI | Linux GUI | Win | Mac | Android | iOS |
|---------|:---------:|:---------:|:---:|:---:|:-------:|:---:|
| Маскировка трафика | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Адаптивный режим (4 уровня) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Качество соединения (live) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Split Tunnel | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| DNS Proxy | ✅ | ✅ | ✅ | ✅ | Н/Д* | ❌ |
| Kill Switch | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| mTLS сертификат | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| FEC (помехоустойчивость) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Запись трафика | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Device Key / JIT | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| SOCKS5 Proxy | ✅ | ✅ | ✅ | ✅ | ❌ | ❌ |
| Полный туннель | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Диагностика / тест | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Обнаружение bootstrap-дескрипторов | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Полиморфные маски | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Краудсорсинговая обратная связь по маскам (опционально) | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| Живые графики метрик† | — | — | — | — | — | — |

\* API `VpnService` в Android маршрутизирует весь трафик устройства (включая DNS) через зашифрованный туннель по умолчанию — отдельный локальный DNS-прокси не нужен, утечки DNS на этой платформе невозможны.

† Живые графики метрик — функция сервера и [веб-панели управления](#веб-панель-управления), а не возможность клиента: требует сборки сервера с `--features metrics` и просматривается в веб-дашборде, а не в клиентах из этой таблицы.

---

## Веб-панель управления

`platforms/aivpn-web/` — полнофункциональный веб-интерфейс для управления aivpn-сервером.

**Стек:** Hono 4 + Bun (бэкенд) · SvelteKit 2 + Svelte 5 + TailwindCSS 4 (фронтенд) · Layerchart · SQLite (по умолчанию) или PostgreSQL

**Возможности:**
- JWT-аутентификация (access-токен 15 мин + refresh httpOnly cookie 7 дней), пароли на argon2id
- TOTP 2FA (секреты шифруются AES-256-GCM) и WebAuthn passkeys
- Роли: `admin` (полный доступ) и `viewer` (только чтение)
- Страницы: Dashboard (live-графики), Clients, Config, Masks, Backup, Logs, Settings
- Все `/api/v1/*` проксируются к Unix-сокету aivpn (`/run/aivpn/api.sock`)
- Realtime SSE-поток событий на `/web/events`
- **Живые графики метрик** — Dashboard отображает live time-series графики (активные сессии, входящая/исходящая полоса пропускания, скорость пакетов, задержка p50/p95 обработки пакетов), а также пульсирующие бейджи ротаций маски/ключа и счётчика обнаруженных DPI-атак; всё это передаётся через тот же поток `/web/events` SSE из кольцевого буфера в памяти (~10 минут), без новой постоянной БД. Требует сборки сервера с `--features metrics` (см. [Опциональные возможности (Cargo features)](#опциональные-возможности-cargo-features)); если у сервера нет этой фичи, вместо графиков дашборд показывает подсказку.

**Быстрый старт:**

```bash
# 1. Сгенерировать секреты
JWT_SECRET=$(openssl rand -base64 48)
TOTP_KEY=$(openssl rand -base64 32)

# 2. Запустить через Docker (самый простой способ)
docker run -d --name aivpn-web \
  -v /run/aivpn:/run/aivpn \
  -e JWT_SECRET="$JWT_SECRET" \
  -e TOTP_ENCRYPTION_KEY="$TOTP_KEY" \
  -e ORIGIN=https://vpn.example.com \
  -p 8080:8080 \
  ghcr.io/infosave2007/aivpn-web:latest

# 3. Получить одноразовый пароль администратора из лога запуска
docker logs aivpn-web 2>&1 | grep -A4 "FIRST-TIME SETUP"

# 4. Открыть https://vpn.example.com, войти с логином "admin"
```

Или через `docker compose up -d aivpn-web` (секреты указываются в `platforms/aivpn-web/.env`).

**Запуск (Bun, из исходников):**
```bash
cd platforms/aivpn-web
cp .env.example .env          # заполнить JWT_SECRET, TOTP_ENCRYPTION_KEY, ORIGIN
bun install && bun run build
bun run start                 # слушает PORT (по умолчанию 8080)
```

**Основные переменные окружения:**

| Переменная | По умолчанию | Описание |
|------------|-------------|---------|
| `DATABASE_URL` | `file:./data/aivpn-web.db` | Путь к SQLite или `postgres://...` |
| `JWT_SECRET` | — | Длинная случайная строка для подписи токенов |
| `TOTP_ENCRYPTION_KEY` | — | 32-байтный base64-ключ (`openssl rand -base64 32`) |
| `ORIGIN` | — | Публичный HTTPS-URL (обязателен для WebAuthn / CSRF) |
| `UNIX_SOCK` | `/run/aivpn/api.sock` | Путь к сокету управления aivpn |
| `PORT` | `8080` | HTTP-порт |

**Цели Makefile:**
```bash
make web           # установить зависимости + собрать фронтенд
make web-docker    # собрать Docker-образ aivpn-web:latest
make web-dev       # запустить dev-серверы (hot reload)
```

Пример конфигурации nginx-реверс-прокси: `deploy/nginx/aivpn-web.conf`.

**Учётные данные по умолчанию (первый запуск):**

При первом старте с пустой базой данных генерируется случайный пароль администратора и выводится **один раз** в консоль сервера:

```
╔══════════════════════════════════════════════════╗
║         FIRST-TIME SETUP — SAVE THESE NOW        ║
╠══════════════════════════════════════════════════╣
║  Username : admin                                 ║
║  Password : <случайная строка ~22 символа>        ║
╚══════════════════════════════════════════════════╝
```

Сохраните этот пароль немедленно — он отображается только один раз. После входа смените пароль в **Настройки → Безопасность** или зарегистрируйте passkey.

**OIDC / SSO (опционально):**

| Переменная | Описание |
|------------|---------|
| `OIDC_ISSUER` | Базовый URL IdP (например `https://accounts.google.com`) |
| `OIDC_CLIENT_ID` | OAuth2 Client ID |
| `OIDC_CLIENT_SECRET` | Секрет клиента (не нужен для публичных PKCE-клиентов) |
| `OIDC_MODE` | `disabled` (по умолчанию) · `enabled` (добавляет кнопку SSO) · `exclusive` (только SSO) |
| `OIDC_ROLE_CLAIM` | Claim ID-токена, из которого читается роль (например `role`) |
| `OIDC_ADMIN_VALUE` | Значение claim для роли `admin` (по умолчанию: `admin`) |

Роль из OIDC применяется только при **первом** SSO-входе; в дальнейшем администратор может изменить её через веб-панель.

---

## Быстрый старт

### Сервер (Linux)

#### Docker (рекомендуется)

```bash
mkdir -p config
docker compose up -d aivpn-server
```

Контейнер автоматически генерирует `server.key` и `server.json` при первом запуске. Работает в режиме `network_mode: host`, монтирует `./config` → `/etc/aivpn`.

Открыть UDP-порт 443:

```bash
# UFW
sudo ufw allow 443/udp
# firewalld
sudo firewall-cmd --add-port=443/udp --permanent && sudo firewall-cmd --reload
```

#### Bare metal

```bash
sudo mkdir -p /etc/aivpn
openssl rand 32 | sudo tee /etc/aivpn/server.key > /dev/null
sudo chmod 600 /etc/aivpn/server.key
sudo ./aivpn-server --listen 0.0.0.0:443 --key-file /etc/aivpn/server.key
```

Сервер автоматически включает переадресацию IPv4 и устанавливает NAT-правила (nftables при наличии, иначе iptables). Ручная настройка файрволла для туннеля не нужна.

#### Добавить клиента

```bash
# Docker
docker compose exec aivpn-server aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip ВАШ_ПУБЛИЧНЫЙ_IP:443

# Bare metal
aivpn-server \
    --add-client "Alice Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip ВАШ_ПУБЛИЧНЫЙ_IP:443
```

Вывод содержит ключ подключения (`aivpn://…`) — передать клиенту.

Другие команды управления: `--list-clients`, `--show-client`, `--remove-client`.

---

### Клиент — Linux

```bash
sudo ./aivpn-client -k "aivpn://..."
# Полный туннель (весь трафик через VPN)
sudo ./aivpn-client -k "aivpn://..." --full-tunnel
```

### Клиент — macOS

Скачать `aivpn-macos.dmg` из [Releases](https://github.com/infosave2007/aivpn/releases), перетащить **Aivpn.app** в Applications, запустить — появится в строке меню. Вставить ключ подключения и нажать **Connect**.

CLI:
```bash
sudo ./aivpn-client -k "aivpn://..."
```

> Приложение запрашивает пароль через `sudo` для создания интерфейса `utun`.

### Клиент — Windows

**Установщик (рекомендуется):** скачать `aivpn-windows-installer.exe`, запустить от имени Администратора, открыть **AIVPN** из меню Пуск.

**Portable:** извлечь `aivpn-windows-package.zip` (содержит `aivpn.exe`, `aivpn-client.exe`, `wintun.dll`). Запустить `aivpn.exe` от Администратора.

CLI (PowerShell, с правами Администратора):
```powershell
.\aivpn-client.exe -k "aivpn://..."
```

> Требуются права Администратора для создания сетевого адаптера Wintun.

### Клиент — Android

1. Установить `aivpn-client.apk`
2. Вставить ключ подключения (`aivpn://…`)
3. Нажать **Connect**

### Клиент — iOS

Сборка на macOS (требуется Xcode 15+):

```bash
make ios TEAM_ID=ВАШ_TEAM_ID
```

Установка `releases/aivpn-ios.ipa`:
```bash
xcrun devicectl device install app --device <UDID> releases/aivpn-ios.ipa
```

> Достаточно бесплатного Apple Developer аккаунта. Сайдлоад-сборки истекают через 7 дней.

### Клиент — Entware-роутеры (ARMv7 / MIPSel)

```bash
scp aivpn-client-linux-armv7-musleabihf root@router:/opt/bin/aivpn-client
ssh root@router 'chmod +x /opt/bin/aivpn-client && /opt/bin/aivpn-client -k "aivpn://..."'
```

### Клиент — MikroTik RouterOS 7.6+

```routeros
/system/device-mode/update container=yes   # затем перезагрузка
/interface/veth/add name=veth-aivpn address=172.31.0.2/30 gateway=172.31.0.1
/ip/address/add address=172.31.0.1/30 interface=veth-aivpn
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
/container/envs/add list=aivpn-env name=AIVPN_KEY value="aivpn://..."
/container/add remote-image=infosave2007/aivpn-mikrotik:latest \
    interface=veth-aivpn start-on-boot=yes envlist=aivpn-env mounts=aivpn-tun
/container/start [find remote-image~"aivpn-mikrotik"]
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2
```

Подробнее: [platforms/mikrotik/README.md](platforms/mikrotik/README.md).

### Режим SOCKS5-прокси (без root)

```bash
aivpn-client -k "aivpn://..." --proxy-listen 127.0.0.1:1080
```

Настроить Firefox / Chrome / curl на `SOCKS5 127.0.0.1:1080`. TUN-устройство и права Администратора не нужны.

---

## Формат ключа подключения

Ключ подключения кодирует все параметры сервера и клиента в одну строку:

```
aivpn://<base64url(JSON)>
```

Поля JSON:

| Поле | Тип | Описание |
|------|-----|---------|
| `s` | `string` | Адрес сервера, напр. `"1.2.3.4:443"` |
| `k` | `string` | Публичный ключ X25519 сервера (base64) |
| `p` | `string` | Предварительный общий ключ (PSK) клиента (base64) |
| `i` | `string` | Статический VPN-IP клиента, напр. `"10.0.0.2"` |
| `n` | `object` | *(необязательно)* Bootstrap `network_config` (см. ниже) |

Объект `network_config` (`n`):

| Поле | Описание |
|------|---------|
| `client_ip` | TUN-IP клиента |
| `server_vpn_ip` | TUN-IP сервера |
| `prefix_len` | Длина префикса подсети |
| `mtu` | Внутренний MTU |

Приоритет при подключении:

1. Параметры из `ServerHello` (авторитетный источник)
2. Bootstrap `network_config` из ключа
3. Устаревший фолбэк `10.0.0.0/24`

Ключи без `network_config` полностью поддерживаются.

Выпустить ключ:
```bash
aivpn-server --add-client "Имя" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

Повторно показать существующий ключ:
```bash
aivpn-server --show-client "Имя" --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json --server-ip IP:PORT
```

---

## Справочник конфигурации сервера

Пути конфига: `config/server.json` (локально) или `/etc/aivpn/server.json`. CLI-флаги перекрывают значения файла.

```json
{
  "listen_addr": "0.0.0.0:443",
  "tun_name": "aivpn0",
  "tun_mtu": "auto",
  "mask_dir": "/var/lib/aivpn/masks",
  "bootstrap_mask_files": [],
  "session_timeout_secs": 0,
  "idle_timeout_secs": 300,
  "allow_peer_routing": false,
  "network_config": {
    "server_vpn_ip": "10.0.0.1",
    "prefix_len": 24,
    "mtu": 1346,
    "keepalive_secs": 8,
    "ipv6_enabled": false,
    "ipv6_prefix": "fd10:cafe::/48"
  },
  "pool": {
    "peers": [],
    "sync_key": ""
  }
}
```

| Параметр | По умолчанию | Описание |
|----------|-------------|---------|
| `listen_addr` | `0.0.0.0:443` | UDP-адрес. Порт автоматически встраивается в ключи подключения |
| `tun_name` | случайное | Имя TUN-интерфейса |
| `tun_mtu` | _(не задан)_ | `"auto"` = физический MTU минус 64 байта накладных расходов (фолбэк 1346); или целое число |
| `mask_dir` | `/var/lib/aivpn/masks` | Директория с `.json` профилями масок |
| `bootstrap_mask_files` | `[]` | Маски, предзагружаемые при старте |
| `session_timeout_secs` | `0` | Жёсткий лимит сессии; `0` = без лимита |
| `idle_timeout_secs` | `300` | Разрыв молчащих сессий (секунды) |
| `allow_peer_routing` | `false` | Маршрутизация пакетов между VPN-клиентами |
| `network_config.server_vpn_ip` | `10.0.0.1` | TUN-IP сервера |
| `network_config.prefix_len` | `24` | Префикс VPN-подсети |
| `network_config.mtu` | `1346` | Внутренний MTU, отправляемый клиентам в `ServerHello` |
| `network_config.keepalive_secs` | `8` | Интервал keepalive |
| `network_config.ipv6_enabled` | `false` | Включить IPv6 NAT66 |
| `network_config.ipv6_prefix` | `fd10:cafe::/48` | ULA /48 префикс для клиентских IPv6-адресов |
| `pool.peers` | `[]` | Адреса узлов пула для синхронизации БД |
| `pool.sync_key` | `""` | Общий 32-байтный ключ BLAKE3 (base64). Генерация: `openssl rand -base64 32` |

### Опциональные возможности (Cargo features)

| Feature | Что включает |
|---------|-------------|
| `neural` | Модуль Neural Resonance (ротация маски по MSE) |
| `management-api` | HTTP API на Unix-сокете `/run/aivpn/api.sock` |
| `metrics` | Экспортёр Prometheus, а также живые метрики времени выполнения (активные сессии, полоса пропускания, ротации маски/ключа, обнаруженные DPI-атаки, задержка обработки пакетов) через SSE `/web/events` для [живых графиков веб-панели](#веб-панель-управления) |
| `passive-distribution` | Каналы распространения bootstrap-дескрипторов |
| `bootstrap-publish` | Авто-публикация ротированных bootstrap-дескрипторов в S3/GitHub/Telegram (см. [Распространение bootstrap-дескрипторов](#распространение-bootstrap-дескрипторов)) |

```bash
cargo build --release --bin aivpn-server --features "management-api,metrics,neural"
```

---

## Сборка из исходников

Требования: Rust 1.75+, `cargo`, `make`.

```bash
git clone https://github.com/infosave2007/aivpn
cd aivpn
make help          # показать все доступные цели
```

### Серверные сборки (Linux)

```bash
make server        # x86_64 → releases/aivpn-server-linux-x86_64
make server-arm64  # ARM64  → releases/aivpn-server-linux-arm64
make server-docker # через Docker (минимальные зависимости на хосте)
```

### Клиентские сборки

```bash
make client        # Linux x86_64
```

### Статические musl-сборки (для роутеров)

```bash
make server-musl-armv7    # ARMv7
make server-musl-mipsel   # MIPSel
make server-musl-aarch64  # AArch64
```

### Платформенные сборки

```bash
make windows              # Windows GUI + zip (кросс-компиляция с Linux)
make windows-docker       # Windows GUI через Docker (без mingw-w64)
make ios [TEAM_ID=XX]     # iOS IPA (только macOS + Xcode 15+)
make macos                # macOS .app + .pkg + .dmg (только macOS)
make linux                 # Linux GUI бинарник (без доп. инструментов)
make linux-appimage        # Linux GUI как AppImage (требует appimagetool)
```

### Деплой

```bash
make deploy               # VPS: скачать бинарник + запустить docker compose
make server-deploy HOST=vps.example.com  # SSH: загрузить локальный бинарник на VPS
```

### Тесты и разработка

```bash
make test           # cargo test --workspace
make clippy         # cargo clippy
make check          # cargo check (быстро)
make test-docker    # интеграционный тест: сервер + клиент в Docker
```

### Android

```bash
export ANDROID_SDK_ROOT=/opt/android-sdk
export ANDROID_NDK_ROOT=/opt/android-ndk
echo "sdk.dir=$ANDROID_SDK_ROOT" > platforms/android/local.properties

make android
```

Подписанная сборка: создать `platforms/android/keystore.properties` перед запуском скрипта.

### Установка из crates.io

```bash
cargo install aivpn-client
cargo install aivpn-server
```

---

## Расширенные возможности

### Привязка устройства (JIT-зачисление)

Ключ подключения может быть одноразовым: первое подключившееся устройство привязывает свой статический X25519-ключ, последующие подключения с другого устройства отклоняются.

```bash
# Создать слот зачисления
aivpn-server --add-client-one-time "Alice-Phone" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip IP:PORT

# Сбросить привязку (повторное зачисление)
aivpn-server --reset-device "Alice-Phone" \
    --clients-db /etc/aivpn/clients.json
```

Хранение ключа устройства:

| Платформа | Путь |
|-----------|------|
| Linux / macOS | `~/.config/aivpn/device.key` (режим 600, автогенерация) |
| Windows | `%APPDATA%\aivpn\device.key` |
| Android | Android Keystore через `EncryptedSharedPreferences` |
| iOS | Keychain, `kSecAttrAccessibleAfterFirstUnlock` |

### Оценка качества соединения и адаптивный режим

AIVPN непрерывно вычисляет **оценку качества 0–100** из RTT (40 пт), джиттера (20 пт), потерь пакетов (30 пт) и Neural MSE (10 пт). Адаптивный режим автоматически регулирует keepalive и размер FEC-группы:

| Оценка | Уровень | Keepalive | FEC-группа |
|--------|---------|-----------|-----------|
| 80–100 | Выкл. | 8 с | выключено |
| 50–79 | Лёгкий | 6 с | 1/16 |
| 20–49 | Агрессивный | 4 с | 1/8 |
| 0–19 | Спутниковый | 15 с | 1/4 |

```bash
aivpn-client -k "aivpn://..." --adaptive
```

### Прямая коррекция ошибок (FEC)

Каждые N uplink-пакетов отправляется один XOR-ремонтный пакет. При потере ровно одного пакета из группы сервер восстанавливает его немедленно без повторной передачи. N управляется адаптивным режимом. На качественном канале FEC отключён.

### Синхронизация пула (multi-server)

```json
{
  "pool": {
    "peers": ["node2.example.com:443"],
    "sync_key": "<base64-32-byte-key>"
  }
}
```

### Многоузловая цепочка (multi-hop)

Клиент подключается только к входному узлу; интернет видит IP выходного узла.

**Входной узел:**
```json
{ "pool": { "sync_key": "<ключ>", "exit_node": "exit.example.com:443" } }
```
**Выходной узел:**
```json
{ "pool": { "sync_key": "<тот же ключ>", "exit_node_enabled": true } }
```

### Распространение bootstrap-дескрипторов

Подписанные (ed25519) bootstrap-дескрипторы позволяют совершенно новому клиенту — у которого ещё нет рабочего ключа `aivpn://` — найти рабочую конфигурацию маски через те же резервные каналы (CDN/GitHub/Telegram), которые клиентский `bootstrap_loader.rs` уже умеет опрашивать. Сервер собирает, подписывает и ротирует эти дескрипторы каждые 24 часа автоматически, рассылая свежие копии уже подключённым клиентам прямо в рамках активной сессии.

**Экспорт через CLI** — вывести или сохранить текущие подписанные дескрипторы предыдущей/текущей/следующей эпохи в формате JSON для ручной загрузки на любой хостинг:
```bash
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key
aivpn-server --export-bootstrap-descriptor --key-file /etc/aivpn/server.key --bootstrap-output /path/to/bootstrap.json
```
Требуется настоящий `--key-file` — эфемерный (случайный) ключ сервера отклоняется, поскольку ни один клиент не станет доверять дескриптору, подписанному одноразовым ключом.

**Экспорт через management API** — тот же JSON-массив доступен по адресу `GET /api/v1/bootstrap/export` (фича `management-api`, та же модель аутентификации через Unix-сокет, что и у остальных эндпоинтов API). В любом прокси-слое веб-панели этот эндпоинт следует считать доступным только администратору — как и `/config`, `/backup/*`.

**Авто-публикация при ротации** — соберите сервер с `--features bootstrap-publish` и добавьте секцию `bootstrap_publish` в `server.json`, чтобы автоматически публиковать свежеротированные дескрипторы при каждом реальном продвижении 24-часовой эпохи:
```json
{
  "bootstrap_publish": {
    "enabled": true,
    "channels": [
      { "type": "s3", "endpoint": "https://s3.us-east-1.amazonaws.com", "region": "us-east-1", "bucket": "my-aivpn-bootstrap", "key": "bootstrap.json", "access_key": "...", "secret_key": "..." },
      { "type": "github", "repo": "owner/repo", "asset_name": "bootstrap-descriptors.json", "tag_name": "bootstrap", "token": "..." },
      { "type": "telegram", "bot_token": "...", "chat_id": "..." }
    ]
  }
}
```

- **S3** — любой S3-совместимый провайдер (AWS S3, Cloudflare R2, MinIO), адресация в path-style (`{endpoint}/{bucket}/{key}`), подпись AWS SigV4.
- **GitHub** — публикуется как release-ассет под фиксированным `tag_name` (обновляется при каждой ротации, поскольку клиенты всегда запрашивают `/releases/latest`). Используйте fine-grained personal access token с доступом только к этому одному репозиторию.
- **Telegram** — отправляется как документ через бота (`sendDocument`). Ограничьте бота одним чатом/каналом.

Каждый канал независим (сбой одного не блокирует остальные) и повторяет попытку 3 раза с задержкой (5с / 30с / 120с) перед тем как залогировать ошибку. Без фичи `bootstrap-publish` значение `enabled: true` просто логирует предупреждение и ничего не делает — сама секция конфига при этом всегда остаётся валидным JSON, поэтому конфиги переносимы между сборками.

**Замечание по безопасности:** если приватный ключ сервера скомпрометирован, атакующий и так может подделать валидные bootstrap-дескрипторы (ключ подписи детерминированно выводится из него). Учётные данные авто-публикации не добавляют этой возможности подделки, но позволяют скомпрометированному серверу протолкнуть поддельный дескриптор через реальные, доверенные каналы распространения оператора — то есть достичь не только уже подключённых, но и совершенно новых пользователей. Относитесь к этим данным в `server.json` с той же осторожностью, что и к любому другому секрету (права `0600`, доступ только пользователю, от которого запущен `aivpn-server`).

### Локальный DNS-прокси

```bash
aivpn-client -k "aivpn://..." --dns-proxy 127.0.0.1:5300 --dns-upstream 1.1.1.1:53
```

### Запись трафика — создание собственных масок

```bash
aivpn-client record start --service myapp
# ... работать с приложением 60+ секунд ...
aivpn-client record stop
```

Сервер анализирует гистограммы размеров пакетов и IAT, генерирует `MaskProfile`, валидирует через самотестирование и распространяет на активные сессии.

### Полиморфные маски

Каждая сессия может использовать уникально искажённый лично для неё вариант базовой маски, чтобы наблюдатель, сравнивающий трафик разных пользователей и сессий, не мог отфингерпринтить один статический профиль маски. Сервер детерминированно выводит вариант из ключевого материала самой сессии и отправляет его клиенту через существующий канал `MaskUpdate` — клиент лишь применяет его, новой криптографии на стороне клиента не требуется. Искажение ограничено для каждой маски (масштаб джиттера IAT, сдвиг паддинга, байты зазора заголовка, масштаб времени пребывания FSM), так что трафик по-прежнему правдоподобно соответствует имитируемому протоколу; граф состояний FSM, имитируемый протокол и длина эфемерного ключа никогда не изменяются. Начальное рукопожатие всегда использует резервную bootstrap-маску (а не именованный пресет), поэтому его нельзя отфингерпринтить до отправки варианта для конкретной сессии.

```bash
aivpn-client -k "aivpn://..." --polymorphic-base webrtc_yandex_telemost_v1
```

Соответствующий чекбокс «Polymorphic» доступен в GUI на Linux, Windows, macOS, iOS и Android рядом с выбором маски.

Профили масок могут опционально задавать `perturbation_bounds`, ограничивая, насколько далеко полиморфный вариант может отклониться от базового профиля:

```json
{
  "mask_id": "webrtc_yandex_telemost_v1",
  "perturbation_bounds": {
    "iat_jitter_scale": 0.15,
    "padding_shift_bytes": 8,
    "header_gap_bytes": 4,
    "fsm_dwell_scale": 0.2
  }
}
```

### Краудсорсинговая обратная связь по маскам (опционально)

Клиенты могут по желанию (по умолчанию выключено) делиться тем, какие маски у них сработали, и получать от сервера подсказки о масках, хорошо работающих в их регионе. Отчёты агрегируются по грубому, задаваемому пользователем двухбуквенному коду страны ISO-3166 — более точное местоположение никогда не покидает клиент. Сервер агрегирует отчёт по маске/региону только после того, как накопится минимум K=20 уникальных источников (отслеживается через HyperLogLog-скетч, не хранящий идентичность источников), сворачивая малочисленные страны до уровня континента, как только соседние страны того же континента преодолевают порог k-анонимности; память для агрегатов ограничена жёстким лимитом с вытеснением и периодической зачисткой. Лимит «голосов» на одного источника дополнительно ограничивает, насколько сильно один источник может исказить рейтинг региона.

Десктопные клиенты фиксируют как *успешные, так и неудачные* применения масок: неудачные попытки подключения до хендшейка накапливаются пакетом, привязываются к использовавшейся маске, сохраняются на диске между перезапусками в `~/.config/aivpn/mask_feedback.json` и передаются агрегированно при следующем успешном подключении. Когда включён `--receive-mask-hints`, клиент мягко смещает выбор начальной маски в сторону маски с наивысшей оценкой, полученной для его региона — это никогда не переопределяет явные `--preferred-mask`/`--polymorphic-base` и никогда не применяется, если начальная маска обязана оставаться подписанным bootstrap-дескриптором (например, в сборках `--no-fallback`/production-secure), так что безопасность bootstrap-механизма не ослабляется. `--share-mask-feedback` и `--receive-mask-hints` — полностью независимые переключатели: клиент может получать региональные подсказки, ни разу не поделившись собственной обратной связью.

Сервер передаёт опт-ин клиентам параметры частоты отчётности через управляющее сообщение `FeedbackConfig`, настраиваемое опциональным блоком `"feedback"` в `server.json`:

```json
{
  "feedback": {
    "report_failure_threshold": 3,
    "report_interval_secs": 3600
  }
}
```

`report_failure_threshold` — минимальное число подряд идущих неудач на маске, после которого она помечается как неудачная; `report_interval_secs` — минимальный интервал между отправками обратной связи клиентом. Оба параметра опциональны и по умолчанию равны `3` и `3600` соответственно, если блок (или ключ) не задан.

```bash
aivpn-client -k "aivpn://..." --share-mask-feedback --receive-mask-hints --country-code DE
```

Оба переключателя и поле кода страны также доступны в настройках GUI на Linux, Windows, macOS, iOS и Android.

### Бенчмарк соединения

```bash
aivpn-client bench -k "aivpn://..."
# P50: 12ms  P95: 28ms  Up: 47 Mbps  Down: 52 Mbps  Score: 94/100
aivpn-client bench -k "aivpn://..." --json
```

---

### Подпись и верификация масок (провенанс)

Маска задаёт, как формируется трафик и — что критично — *как разбираются пакеты*
(`tag_offset`, раскладка заголовка, `spoof_protocol`). Поэтому вредоносная или
повреждённая маска, дошедшая до сервера или клиента, — реальная поверхность
атаки. Маски aivpn несут ed25519-подпись по **всему** профилю; сервер может
подписывать раздаваемые маски операторским ключом, а сервер и клиент — проверять
эту подпись при загрузке.

Верификация имеет три режима (`mask_verify_mode`, или `--mask-verify-mode`, env
`AIVPN_MASK_VERIFY_MODE`):

| Режим | Поведение |
|-------|-----------|
| `off` | Проверка подписи отключена. |
| `warn` | **По умолчанию.** Проверить и залогировать предупреждение при неудаче, но всё равно загрузить маску — ничего не ломается, если корпус ещё не подписан. |
| `enforce` | Отклонять любую маску, чья подпись не проверяется операторским публичным ключом. Требует, чтобы весь корпус масок был предварительно подписан. |

Порядок действий оператора для включения `enforce`:

```bash
# 1. Сгенерировать операторский ключ подписи (выводит публичный ключ для раздачи).
aivpn-server --gen-mask-signing-key /etc/aivpn/mask-signing.key

# 2. Подписать весь корпус масок на месте (один раз; повторять после добавления масок).
aivpn-server --sign-mask-dir /var/lib/aivpn/masks --mask-signing-key /etc/aivpn/mask-signing.key

# 3. Сервер: указать ключ подписи (авто-подпись новых генерируемых масок) и enforce.
#    server.json:  "mask_signing_key": "/etc/aivpn/mask-signing.key", "mask_verify_mode": "enforce"

# 4. Клиенты: раздать им ПУБЛИЧНЫЙ ключ оператора и включить enforce.
#    client:  --mask-operator-pubkey <BASE64_PUBKEY> --mask-verify-mode enforce
```

Публичный ключ независимо проверяется и для downlink-профиля `reverse_profile`.
Поскольку `enforce` отклоняет неподписанные маски, раскатывайте его поэтапно —
оставайтесь на `warn`, пока каталог масок каждого сервера не подписан, а клиенты
не получили публичный ключ. Ключ подписи — секрет: храните `0600`, доступным на
чтение только оператору.

## Модель безопасности

| Свойство | Механизм |
|----------|---------|
| Шифрование | ChaCha20-Poly1305 AEAD |
| Обмен ключами | X25519 ECDH |
| Аутентификация сессии | PSK на клиента (опционально — привязка устройства) |
| Прямая секретность | X25519 рэтчет в полёте |
| Защита от повтора | Скользящее окно на 256 записей на сессию |
| Анонимность сессии | 8-байтовый BLAKE3-тег; идентификатор сессии не передаётся |
| Мимикрия трафика | FSM `MaskProfile`: инъекция заголовков, IAT-шейпинг |
| Целостность маски | Neural Resonance MSE 0,35; авто-ротация |
| NAT | Сервер: nftables/iptables; клиент: `SO_REUSEPORT` |

Подробная модель угроз и анализ: [THREAT_MODEL.md](THREAT_MODEL.md).

---

## Структура проекта

```
aivpn/
├── crates/aivpn-common/src/
│   ├── crypto.rs          # X25519, ChaCha20-Poly1305, BLAKE3
│   ├── mask.rs            # Профили мимикрии (WebRTC, QUIC, DNS)
│   ├── protocol.rs        # Формат пакетов и управляющий протокол
│   └── fec.rs             # XOR Forward Error Correction
├── crates/aivpn-client/src/
│   ├── client.rs          # Ядро машины состояний
│   ├── tunnel.rs          # Кроссплатформенный TUN
│   ├── kill_switch.rs     # Kill-switch (nftables / pfctl / netsh)
│   └── mimicry.rs         # Движок шейпинга трафика
├── crates/aivpn-server/src/
│   ├── gateway.rs         # UDP-шлюз, диспетчер сессий
│   ├── neural.rs          # Модуль Neural Resonance
│   ├── nat.rs             # NAT (IPv4 + IPv6 NAT66)
│   ├── client_db.rs       # База клиентов
│   └── pool_sync.rs       # Внутрипротокольная синхронизация пула
├── platforms/android/         # Android Kotlin-приложение
├── platforms/ios/             # iOS SwiftUI + NEPacketTunnelProvider
├── crates/aivpn-windows/      # Windows egui GUI
├── platforms/macos/           # macOS SwiftUI в строке меню
├── assets/masks/          # Встроенные профили мимикрии (JSON)
├── deploy/ci/             # Гейты CI, вызываемые из Makefile
├── deploy/docker/             # Dockerfiles и точка входа
├── Dockerfile
├── docker-compose.yml
└── THREAT_MODEL.md
```

---

## Лицензия

MIT — см. [LICENSE](LICENSE).
