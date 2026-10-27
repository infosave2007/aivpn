# aivpn-mikrotik

Run AIVPN client inside a MikroTik RouterOS 7 container. Configured with a single connection key — no VPN expertise required.

## Supported Devices

| Architecture | RouterOS Devices |
|---|---|
| **arm64** (aarch64) | RB5009, CCR2004, hAP ax², RBD53iG, most modern RouterBOARD |
| **armv7** | hAP ac², RB3011, RB2011, RB951, RBD52G |
| **amd64** | CHR (Cloud Hosted Router), x86 RouterOS |

Requires RouterOS **7.6+** with container support.

## Prerequisites

Enable the container feature on your MikroTik (one-time):

```routeros
/system/device-mode/update container=yes
```

Reboot the device after running this command.

## Quick Setup

### Step 1 — Create veth interface

```routeros
/interface/veth/add name=veth-aivpn address=172.31.0.2/30 gateway=172.31.0.1
/ip/address/add address=172.31.0.1/30 interface=veth-aivpn
```

### Step 2 — Configure environment variables

```routeros
/container/envs/add list=aivpn-env name=AIVPN_KEY value="aivpn://YOUR_CONNECTION_KEY_HERE"
```

Optional — disable full-tunnel mode (only route VPN subnet, not all traffic):
```routeros
/container/envs/add list=aivpn-env name=AIVPN_FULL_TUNNEL value="false"
```

### Step 3 — Mount /dev/net/tun

```routeros
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
```

### Step 4 — Create and start the container

Build the image using the instructions below, export it with `docker save`, and upload `aivpn-mikrotik.tar` to `disk1/` using WinBox. File import does not require a published Docker Hub image. [RouterOS image import](https://help.mikrotik.com/docs/spaces/ROS/pages/84901929/Container#Container-OptionB:ImportimagefromPC).

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

### Step 5 — Configure routing

Создайте отдельную таблицу и направьте в нее трафик с LAN-моста. В примере LAN использует `bridge` и подсеть `192.168.88.0/24`. Подставьте свои значения.

```routeros
/routing/table/add name=aivpn-rt fib
/ip/route/add dst-address=0.0.0.0/0 gateway=172.31.0.2@main routing-table=aivpn-rt comment="AIVPN LAN route"
/routing/rule/add interface=bridge src-address=192.168.88.0/24 action=lookup-only-in-table table=aivpn-rt
```

Для одного устройства укажите его адрес вместо подсети:

```routeros
/routing/rule/add interface=bridge src-address=192.168.88.50/32 action=lookup-only-in-table table=aivpn-rt
```

Исходный маршрут WAN в `main` нужен самому контейнеру для связи с сервером. Ограничение по входному интерфейсу исключает повторную отправку пакетов из контейнера обратно в контейнер. Не включайте эти соединения в FastTrack: он обходит отдельную таблицу маршрутизации. Установите правило AIVPN перед другими правилами, которые выбирают таблицу для того же LAN.

По умолчанию при остановке VPN пакеты идут через WAN. Чтобы блокировать такой выход, включите настройку до запуска контейнера:

```routeros
/container/envs/add list=aivpn-env name=AIVPN_KILL_SWITCH value="true"
```

Эта настройка блокирует обход TUN внутри работающего контейнера. Если остановлен весь контейнер, трафик выбранных устройств не проходит через него. Пример задает только IPv4: для полного туннеля также настройте IPv6 либо отключите его на выбранном LAN.

## Environment Variables

| Variable | Required | Default | Description |
|---|---|---|---|
| `AIVPN_KEY` | **Yes** | — | Connection key from `aivpn-server --show-client` |
| `AIVPN_FULL_TUNNEL` | No | `true` | Route all traffic through VPN (`true`/`false`) |
| `AIVPN_KILL_SWITCH` | No | `false` | Блокировать выход в обход TUN при остановке VPN |
| `AIVPN_TUN_NAME` | No | `tun0` | Имя TUN внутри контейнера |
| `LAN_IF` | No | `eth0` | Входной интерфейс внутри контейнера |

## Checking Status

```routeros
/container/print detail where comment="AIVPN client"
/log/print where topics~"container"
```

## Getting Your Connection Key

On the AIVPN server:

```bash
aivpn-server --show-client "my-mikrotik" \
    --key-file /etc/aivpn/server.key \
    --clients-db /etc/aivpn/clients.json \
    --server-ip your.server.ip
```

## Building from Source

```bash
# Single arch (arm64)
docker build \
    --platform linux/arm64 \
    --build-arg MUSL_IMAGE_TAG=aarch64-musl \
    --build-arg TARGET_TRIPLE=aarch64-unknown-linux-musl \
    -t aivpn-mikrotik:arm64 \
    -f platforms/mikrotik/Dockerfile .

# Export for router import
docker save --output aivpn-mikrotik.tar aivpn-mikrotik:arm64

# Multi-arch push to Docker Hub
./platforms/mikrotik/build-mikrotik.sh infosave2007/aivpn-mikrotik:latest
```

## Troubleshooting

**Container fails with "TUN not found"**  
RouterOS requires an explicit bind mount for the TUN device:
```routeros
/container/mounts/add name=aivpn-tun src=/dev/net/tun dst=/dev/net/tun type=bind
```
Recreate the container after adding the mount.

**No internet after connecting on RouterOS 7.22+**  
RouterOS 7.22 introduced a regression with TUN inside containers.
Downgrade to 7.21 or wait for a bugfix release. This affects all TUN-based containers.

**Traffic not routed through VPN**  
Check that your default route or policy routing rules point to 172.31.0.2 (the container veth IP).
Verify the VPN is connected: `/log/print where topics~"container"`.
