# aivpn-linux-kernel

Optional Linux kernel module that accelerates the AIVPN data plane.

When the module is loaded, `aivpn-server` and `aivpn-client` automatically detect it via `/dev/aivpn` and bypass the user-space Tokio event loop for packet forwarding. If the module is absent, not loaded, or the kernel version is unsupported, both binaries fall back silently to the standard TUN-based user-space path — no configuration change required.

---

## How It Works

Without the module, each packet crosses the kernel/user boundary four times (UDP recv → decrypt → TUN write on inbound; TUN read → encrypt → UDP send on outbound). The kernel module intercepts the UDP socket's receive path and the TUN device's transmit path entirely inside the kernel, reducing crossings to zero and performing ChaCha20-Poly1305 encryption/decryption via the kernel `crypto_aead` API.

The control plane (session install/remove) uses a character device (`/dev/aivpn`) with ioctl calls. The data plane runs in softirq context with no syscalls per packet.

Expected improvement at high packet rates: 2–4× throughput, 3–5× latency reduction, ~3× CPU reduction. See `DESIGN.md` for detailed performance analysis.

---

## Requirements

### Hardware

- x86-64, aarch64, or armv7 Linux host
- Any NIC supported by the Linux kernel

### Kernel

| Requirement | Minimum |
|---|---|
| Kernel version | Номер версии сам по себе не определяет совместимость Rust API |
| `CONFIG_RUST=y` | Required for Rust control-plane glue |
| Rust miscdevice API | `MiscDeviceOptions::into_raw` и `file_operations.owner`, указывающий на модуль |
| `CONFIG_CRYPTO_CHACHA20POLY1305=y` | Required for in-kernel AEAD |
| `CONFIG_TUN=y` or `=m` | Required (same as user-space path) |
| `CONFIG_CRYPTO_USER_API_AEAD` | Not required (module uses in-kernel API directly) |

Check your kernel config:

```bash
grep -E 'CONFIG_RUST|CONFIG_CRYPTO_CHACHA|CONFIG_TUN' /boot/config-$(uname -r)
```

`CONFIG_RUST` должен быть `y`; криптография и TUN должны быть доступны в ядре или модуле.

Модуль использует нестабильный Rust-for-Linux API, поэтому поддержки всех ядер начиная с 6.1 нет. В upstream Linux до 7.2 включительно miscdevice vtable не задает `owner`. Такое API не удерживает код модуля, пока открыт `/dev/aivpn`, и небезопасно при выгрузке. Нужен kernel с исправленным miscdevice API, в том числе возможен backport. Перед регистрацией устройства AIVPN проверяет настоящую vtable: при NULL `fops` или `owner` загрузка завершается с `ENODEV`, устройство не публикуется. Ручного закрепления модуля нет. Без ускорителя клиент и сервер остаются на userspace TUN.

Контракт API проверен по [Linux v7.2](https://raw.githubusercontent.com/torvalds/linux/v7.2/rust/kernel/miscdevice.rs) и [исправленной реализации upstream](https://github.com/torvalds/linux/blob/master/rust/kernel/miscdevice.rs). Совпадение номера ядра или успешная компиляция C-части не заменяют проверку загрузки и работы Rust-модуля.

### Build Dependencies

```bash
# Debian/Ubuntu
apt install dkms linux-headers-$(uname -r) build-essential rustup

# Fedora/RHEL
dnf install dkms kernel-devel gcc rustup

# Arch Linux
pacman -S dkms linux-headers base-devel rustup
```

Компилятор Rust и rust-src должны соответствовать toolchain, которым собраны Rust metadata выбранного ядра. Произвольный nightly или stable из rustup может дать `E0514` даже при подходящем API. Используйте toolchain пакета kernel headers или настройку сборки своего ядра.

---

## Build and Install with DKMS

DKMS automatically rebuilds the module on kernel upgrades.

### 1. Clone the repository (if not already present)

```bash
git clone https://github.com/infosave2007/aivpn.git
cd aivpn/aivpn-linux-kernel
```

### 2. Install via DKMS

```bash
sudo ./scripts/install-dkms.sh
```

This script:
1. Copies the source tree to `/usr/src/aivpn-<version>/`
2. Runs `dkms add`, `dkms build`, and `dkms install`
3. Loads the module with `modprobe aivpn`

### 3. Verify the module is loaded

```bash
lsmod | grep aivpn
ls -la /dev/aivpn
```

Expected output:

```
aivpn                  45056  0
/dev/aivpn    crw------- 1 root root 10, 123 Jun 11 00:00 /dev/aivpn
```

### 4. Build manually (without DKMS)

```bash
make KVER=$(uname -r)
sudo insmod aivpn.ko
```

---

## Uninstall

```bash
sudo ./scripts/uninstall-dkms.sh
```

Or manually:

```bash
sudo rmmod aivpn
sudo dkms remove aivpn/<version> --all
```

---

## Auto-Detection Behavior

No configuration is needed. Both `aivpn-server` and `aivpn-client` probe `/dev/aivpn` at startup:

| Condition | Behavior |
|---|---|
| Module loaded, API version matches | Kernel acceleration active; log line: `kernel acceleration enabled via /dev/aivpn` |
| Module not loaded / `/dev/aivpn` missing | Silent fallback to user-space TUN path; log line: `kernel acceleration unavailable, using user-space path` |
| Module loaded but API version mismatch | Fallback with warning: `kernel accel unavailable: version mismatch` |
| `/dev/aivpn` exists but process lacks permissions | Fallback with warning; run server/client as root or add the user to a group with access to the device |

The fallback path is identical to the current codebase — no features are lost. Mask mimicry, neural resonance, recording, and key rotation all continue to work normally regardless of whether the kernel module is active.

---

## What Is and Is Not Accelerated

### Accelerated by the kernel module

- UDP packet receive (inbound)
- Resonance tag lookup (O(1) kernel hashtable)
- ChaCha20-Poly1305 decrypt / encrypt
- TUN device injection / extraction (zero-copy when driver headroom permits)
- Anti-replay bitmap check

### Remains in user space

- X25519 key exchange and session handshake
- Neural Resonance Module (MLP forward-pass, mask rotation decisions)
- Traffic mimicry / mask FSM shaping
- Session recording and mask generation
- Management API and client database

---

## Testing the Module

A userspace smoke test is included:

```bash
cd tests
make
sudo ./user_ioctl_test
# Exit 0 = module responding correctly to ioctl add/stat/del
```

---

## Kernel Upgrade Behavior

DKMS rebuilds `aivpn.ko` automatically when a new kernel is installed via the package manager. If the rebuild fails (e.g., due to Rust-for-Linux API changes between kernel versions), DKMS will report the error and the system continues booting normally. `aivpn-server` and `aivpn-client` will detect that `/dev/aivpn` is absent and fall back to user-space mode automatically — no service interruption.

---

## Troubleshooting

**`/dev/aivpn` does not appear after `modprobe aivpn`**

Check `dmesg | grep aivpn` for load errors. Common cause: `CONFIG_CRYPTO_CHACHA20POLY1305` not enabled in the running kernel.

**`aivpn-server` logs "using user-space path" even though the module is loaded**

The server process must run as root (or have read-write permission on `/dev/aivpn`). Check: `ls -la /dev/aivpn`.

**DKMS build fails after kernel upgrade**

The Rust-for-Linux kernel crate API changes between kernel versions. Check `dkms status` and the build log at `/var/lib/dkms/aivpn/<version>/<kernel>/build/make.log`. A crate API breakage will produce a Rust compile error. File an issue with the kernel version and the error output.

**Загрузка завершается с ENODEV и сообщением о miscdevice API**

`file_operations.owner` отсутствует в используемом Rust-for-Linux API. Это отказ до регистрации `/dev/aivpn`, а не ошибка VPN-сеанса. Обновите ядро или примените исправление его miscdevice API. Не обходите проверку owner: до исправления используйте userspace TUN.

**Module loads but throughput improvement is not visible**

Ensure `CONFIG_CRYPTO_CHACHA20_X86_64=y` (or `_ARM64=y`) is enabled so the kernel uses the SIMD-accelerated ChaCha20 implementation. Without it, the kernel falls back to the generic C implementation, which has similar throughput to the user-space crate.

---

## Security Notes

- `/dev/aivpn` is mode `0600` (root-only). Do not widen permissions.
- Session keys are zeroed in kernel memory on session removal (`memzero_explicit`).
- The module does not expose any procfs or sysfs entries that could leak key material.
- Constant-time tag comparison uses `crypto_memneq` (kernel equivalent of `subtle::ConstantTimeEq`).

---

## Compatibility Matrix

| aivpn-server version | Module API version | Kernel contract |
|---|---|---|
| Текущий клиент и сервер | 7 | Совместимый Rust API с module owner в miscdevice vtable; проверка перед регистрацией |

The module API version is checked at runtime. A version mismatch causes automatic fallback, not a crash.

---

## License

MIT — same as the rest of the AIVPN project.
