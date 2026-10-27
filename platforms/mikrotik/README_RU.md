# aivpn-mikrotik

Запуск клиента AIVPN внутри контейнера MikroTik RouterOS 7. Настраивается одним ключом подключения — не требует специальных знаний VPN.

## Поддерживаемые устройства

| Архитектура | Устройства RouterOS |
|---|---|
| **arm64** (aarch64) | RB5009, CCR2004, hAP ax², RBD53iG, большинство современных RouterBOARD |
| **armv7** | hAP ac², RB3011, RB2011, RB951, RBD52G |
| **amd64** | CHR (Cloud Hosted Router), x86 RouterOS |

Требуется RouterOS **7.6+** с поддержкой контейнеров.

## Предварительная настройка

Активируйте поддержку контейнеров (один раз):

```routeros
/system/device-mode/update container=yes
```

После выполнения команды перезагрузите устройство.

## Быстрая установка

### Шаг 1 — Создать интерфейс veth

```routeros
/interface/veth/add name=veth-aivpn address=172.31.0.2/30 gateway=172.31.0.1
/ip/address/add address=172.31.0.1/30 interface=veth-aivpn
```

### Шаг 2 — Настроить переменные окружения

```routeros
/container/envs/add list=aivpn-env name=AIVPN_KEY value="aivpn://ВАШ_КЛЮЧ_ПОДКЛЮЧЕНИЯ"
```

Опционально — отключить полный туннель (роутить только подсеть VPN):
```routeros
/container/envs/add list=aivpn-env name=AIVPN_FULL_TUNNEL value="false"
```

### Шаг 3 — Подключить /dev/net/tun

```routeros
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
```

### Шаг 4 — Создать и запустить контейнер

Соберите образ по инструкции ниже, сохраните его через `docker save` и загрузите `aivpn-mikrotik.tar` в `disk1/` через WinBox. Импорт из файла не требует опубликованного образа в Docker Hub. [Описание импорта RouterOS](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container#Container-OptionB:ImportimagefromPC).

```routeros
/container/add \
    file=disk1/aivpn-mikrotik.tar \
    interface=veth-aivpn \
    start-on-boot=yes \
    envlist=aivpn-env \
    mounts=aivpn-tun \
    dns=8.8.8.8 \
    logging=yes \
    cap=net-admin \
    comment="AIVPN client"

/container/start [find comment="AIVPN client"]
```

### Шаг 5 — Настроить маршрутизацию

Маршрутизировать весь трафик через VPN-контейнер:

```routeros
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2 routing-table=main distance=5 comment="AIVPN маршрут"
```

Или через политику маршрутизации (только для отдельных хостов):

```routeros
/routing/rule/add src-address=192.168.1.50/32 action=lookup-only-in-table table=aivpn-rt
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2 routing-table=aivpn-rt
```

## Переменные окружения

| Переменная | Обязательно | По умолчанию | Описание |
|---|---|---|---|
| `AIVPN_KEY` | **Да** | — | Ключ подключения из `aivpn-server --show-client` |
| `AIVPN_FULL_TUNNEL` | Нет | `true` | Весь трафик через VPN (`true`/`false`) |

## Проверка статуса

```routeros
/container/print detail where comment="AIVPN client"
/log/print where topics~"container"
```

## Получение ключа подключения

На сервере AIVPN:

```bash
aivpn-server --show-client "my-mikrotik" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip адрес.вашего.сервера
```

## Сборка из исходников

```bash
# Одна архитектура (arm64)
docker build \
    --platform linux/arm64 \
    --build-arg MUSL_IMAGE_TAG=aarch64-musl \
    --build-arg TARGET_TRIPLE=aarch64-unknown-linux-musl \
    -t aivpn-mikrotik:arm64 \
    -f platforms/mikrotik/Dockerfile .

# Сохранить для импорта на роутере
docker save --output aivpn-mikrotik.tar aivpn-mikrotik:arm64

# Мульти-архитектурная публикация
./platforms/mikrotik/build-mikrotik.sh infosave2007/aivpn-mikrotik:latest
```

## Устранение неисправностей

**Контейнер завершается с ошибкой "TUN not found"**  
RouterOS требует явного bind-mount для TUN-устройства:
```routeros
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
```
Пересоздайте контейнер после добавления маунта.

**Нет интернета после подключения на RouterOS 7.22+**  
RouterOS 7.22 содержит регрессию с TUN внутри контейнеров.
Откатитесь на 7.21 или ожидайте патча. Это затрагивает все TUN-контейнеры.

**Трафик не роутится через VPN**  
Проверьте, что маршрут по умолчанию или правила политики маршрутизации указывают на 172.31.0.2.
Проверьте логи: `/log/print where topics~"container"`.
