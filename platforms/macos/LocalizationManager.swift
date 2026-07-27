import Foundation
import Combine

class LocalizationManager: ObservableObject {
    static let shared = LocalizationManager()

    @Published var language: String = "en" {
        didSet {
            UserDefaults.standard.set(language, forKey: "app_language")
        }
    }

    private let strings: [String: [String: String]] = [
        "status_connected": [
            "en": "Connected",
            "ru": "Подключено"
        ],
        "status_disconnected": [
            "en": "Disconnected",
            "ru": "Отключено"
        ],
        "enter_key": [
            "en": "Connection key (aivpn://...)",
            "ru": "Ключ подключения (aivpn://...)"
        ],
        "no_key": [
            "en": "No connection key set",
            "ru": "Ключ подключения не задан"
        ],
        "change": [
            "en": "Change",
            "ru": "Изменить"
        ],
        "full_tunnel": [
            "en": "Full tunnel (route all traffic)",
            "ru": "Полный туннель (весь трафик)"
        ],
        "full_tunnel_help": [
            "en": "Route all system traffic through VPN",
            "ru": "Направить весь системный трафик через VPN"
        ],
        "proxy_mode": [
            "en": "Proxy mode (SOCKS5, no root required)",
            "ru": "Режим прокси (SOCKS5, без прав root)"
        ],
        "proxy_mode_help": [
            "en": "Run as local SOCKS5 proxy — no root required. Set your apps or system proxy to 127.0.0.1:<port>.",
            "ru": "Запуск как локальный SOCKS5-прокси — без прав root. Укажите прокси 127.0.0.1:<порт> в настройках приложений."
        ],
        "proxy_port": [
            "en": "Port:",
            "ru": "Порт:"
        ],
        "proxy_port_invalid": [
            "en": "Proxy port must be a number above 1024",
            "ru": "Порт прокси должен быть числом больше 1024"
        ],
        "connect": [
            "en": "Connect",
            "ru": "Подключить"
        ],
        "disconnect": [
            "en": "Disconnect",
            "ru": "Отключить"
        ],
        "connecting": [
            "en": "Connecting...",
            "ru": "Подключение..."
        ],
        "quit": [
            "en": "Quit",
            "ru": "Выход"
        ],
        "helper_ready": [
            "en": "Service ready",
            "ru": "Сервис готов"
        ],
        "helper_missing": [
            "en": "Service unavailable — install AIVPN from the .pkg installer",
            "ru": "Сервис недоступен — установите AIVPN через файл .pkg"
        ],
        "helper_starting": [
            "en": "Checking service...",
            "ru": "Проверка сервиса..."
        ],
        "key_name": [
            "en": "Key Name",
            "ru": "Название ключа"
        ],
        "select_key": [
            "en": "Select Key",
            "ru": "Выбрать ключ"
        ],
        "select_key_prompt": [
            "en": "Select a connection key",
            "ru": "Выберите ключ подключения"
        ],
        "add_key": [
            "en": "Add Key",
            "ru": "Добавить ключ"
        ],
        "done": [
            "en": "Done",
            "ru": "Готово"
        ],
        "edit": [
            "en": "Edit",
            "ru": "Изменить"
        ],
        "delete": [
            "en": "Delete",
            "ru": "Удалить"
        ],
        "duplicate_key": [
            "en": "This key already exists",
            "ru": "Этот ключ уже существует"
        ],
        "error_invalid_key": [
            "en": "Invalid connection key format",
            "ru": "Неверный формат ключа подключения"
        ],
        "delete_key_confirm": [
            "en": "Delete Key?",
            "ru": "Удалить ключ?"
        ],
        "delete_key_message": [
            "en": "Are you sure you want to delete this key?",
            "ru": "Вы уверены что хотите удалить этот ключ?"
        ],
        "cancel": [
            "en": "Cancel",
            "ru": "Отмена"
        ],
        "connection_keys": [
            "en": "Connection Keys",
            "ru": "Ключи подключения"
        ],
        "no_keys_yet": [
            "en": "No keys yet",
            "ru": "Нет ключей"
        ],
        "add_first_key": [
            "en": "Add First Key",
            "ru": "Добавить первый ключ"
        ],
        "no_key_selected": [
            "en": "No key selected",
            "ru": "Ключ не выбран"
        ],
        "save_key": [
            "en": "Save",
            "ru": "Сохранить"
        ],
        "record_new_mask": [
            "en": "Record New Mask",
            "ru": "Записать новую маску"
        ],
        "stop_recording": [
            "en": "Stop Recording",
            "ru": "Остановить запись"
        ],
        "record_service_name": [
            "en": "Mask Service Name",
            "ru": "Имя сервиса для маски"
        ],
        "recording_ready": [
            "en": "Recording availability is checked by the server when you start",
            "ru": "Доступ к записи проверяется сервером при запуске"
        ],
        "recording_connect_required": [
            "en": "Connect before starting mask recording",
            "ru": "Сначала подключитесь перед записью маски"
        ],
        "recording_starting": [
            "en": "Starting recording...",
            "ru": "Запуск записи..."
        ],
        "recording_active": [
            "en": "Recording in progress. Use the service normally.",
            "ru": "Запись идёт. Используйте сервис как обычно."
        ],
        "recording_stopping": [
            "en": "Stopping recording...",
            "ru": "Останавливаем запись..."
        ],
        "recording_analyzing": [
            "en": "Recording finished. Server is analyzing traffic.",
            "ru": "Запись завершена. Сервер анализирует трафик."
        ],
        "recording_success": [
            "en": "Mask recorded successfully",
            "ru": "Маска успешно записана"
        ],
        "recording_failed": [
            "en": "Mask recording failed",
            "ru": "Запись маски не удалась"
        ],
        "recording_self_test_failed": [
            "en": "Mask did not pass verification",
            "ru": "Маска не прошла проверку"
        ],
        "recording_result_success_title": [
            "en": "Last recording result: saved",
            "ru": "Последний результат записи: маска сохранена"
        ],
        "recording_result_failed_title": [
            "en": "Last recording result: not saved",
            "ru": "Последний результат записи: маска не сохранена"
        ],
        "dismiss": [
            "en": "Dismiss",
            "ru": "Скрыть"
        ],
        "adaptive_mode": [
            "en": "Adaptive Mode",
            "ru": "Адаптивный режим"
        ],
        "adaptive_off": [
            "en": "Off",
            "ru": "Выкл"
        ],
        "adaptive_light": [
            "en": "Light (6s)",
            "ru": "Лёгкий (6с)"
        ],
        "adaptive_aggressive": [
            "en": "Aggressive (4s)",
            "ru": "Агрессивный (4с)"
        ],
        "adaptive_satellite": [
            "en": "Satellite (15s)",
            "ru": "Спутник (15с)"
        ],
        "adaptive_mode_help": [
            "en": "Controls traffic mimicry (HTTPS/QUIC/Zoom) and keepalive frequency. Higher level = better DPI evasion, higher bandwidth overhead",
            "ru": "Управляет маскировкой трафика под HTTPS/QUIC/Zoom и частотой keepalive. Чем выше уровень — тем лучше обход DPI, но выше нагрузка на канал"
        ],
        "recording_desc": [
            "en": "Records your network traffic profile to create a personal mask — a fingerprint used to train the DPI evasion engine",
            "ru": "Записывает сетевой профиль трафика для создания персональной маски — образца, обучающего систему обхода DPI"
        ],
        "diagnostics": [
            "en": "Diagnostics",
            "ru": "Диагностика"
        ],
        "run_benchmark": [
            "en": "Run Benchmark",
            "ru": "Запустить тест"
        ],
        "bench_running": [
            "en": "Running benchmark…",
            "ru": "Тест запущен…"
        ],
        "bench_idle": [
            "en": "Run a benchmark to check connection quality.",
            "ru": "Запустите тест для оценки качества соединения."
        ],
        "mtls_cert_path": [
            "en": "mTLS cert path (optional)",
            "ru": "Путь к mTLS-сертификату (необязательно)"
        ],
        "mtls_cert_path_help": [
            "en": "Path to client certificate file for mutual TLS authentication. Leave empty to disable.",
            "ru": "Путь к файлу клиентского сертификата для взаимной TLS-аутентификации. Оставьте пустым для отключения."
        ],
        "dns_proxy_placeholder": [
            "en": "DNS proxy (e.g. 127.0.0.1:5300)",
            "ru": "DNS-прокси (например 127.0.0.1:5300)"
        ],
        "dns_proxy_help": [
            "en": "Local address for DNS leak prevention proxy. Leave empty to disable. Point your resolver here after connecting.",
            "ru": "Локальный адрес DNS-прокси для предотвращения утечек. Оставьте пустым для отключения. После подключения укажите этот адрес в настройках резолвера."
        ],
        "exclude_routes_label": [
            "en": "Exclude routes (split tunnel)",
            "ru": "Исключить маршруты (split tunnel)"
        ],
        "exclude_routes_placeholder": [
            "en": "192.168.1.0/24, 10.0.0.0/8",
            "ru": "192.168.1.0/24, 10.0.0.0/8"
        ],
        "exclude_routes_help": [
            "en": "Comma-separated CIDRs to bypass the VPN. Use with Full Tunnel to carve out local subnets.",
            "ru": "CIDRы через запятую, которые не будут направлены через VPN. Используйте вместе с полным туннелем для исключения локальных подсетей."
        ],
        "mtls_ignored_in_proxy_mode": [
            "en": "mTLS certificate is not used in SOCKS5 proxy mode",
            "ru": "mTLS-сертификат не применяется в режиме SOCKS5-прокси"
        ],
        "kill_switch": [
            "en": "Kill Switch (block traffic if VPN drops)",
            "ru": "Kill Switch (блок трафика при разрыве VPN)"
        ],
        "kill_switch_help": [
            "en": "Block all non-VPN traffic while connected. Rules persist after unexpected process death.",
            "ru": "Блокировать весь трафик вне VPN. Правила сохраняются после аварийного завершения."
        ],
        "notification_connected": [
            "en": "AIVPN Connected",
            "ru": "AIVPN подключено"
        ],
        "notification_disconnected": [
            "en": "AIVPN Disconnected",
            "ru": "AIVPN отключено"
        ],
        "fec_badge": [
            "en": "FEC",
            "ru": "FEC"
        ],
        "connect_on_launch": [
            // The toggle only registers a LaunchAgent that starts the app at
            // login — it does not auto-connect, so the label must not promise
            // a connection. (RU already said "запускать", which is accurate.)
            "en": "Launch at login",
            "ru": "Запускать при входе"
        ],
        "connect_on_launch_help": [
            "en": "Start AIVPN automatically when you log in",
            "ru": "Автоматически запускать AIVPN при входе в систему"
        ],
        "mask_profile": [
            "en": "Mask Profile",
            "ru": "Профиль маски"
        ],
        "mask_auto": [
            "en": "Auto",
            "ru": "Авто"
        ],
        "mask_auto_marker": [
            "en": " (auto)",
            "ru": " (авто)"
        ],
        "mask_profile_help": [
            "en": "Traffic mimicry profile. Auto lets the server choose the best mask.",
            "ru": "Профиль маскировки трафика. Авто — сервер выбирает маску автоматически."
        ],
        "theme": [
            "en": "Theme",
            "ru": "Тема"
        ],
        "theme_help": [
            "en": "Choose System to follow macOS appearance, or force Light/Dark.",
            "ru": "«Система» — следовать оформлению macOS, либо принудительно Светлая/Тёмная."
        ],
        "theme_system": [
            "en": "System",
            "ru": "Система"
        ],
        "theme_light": [
            "en": "Light",
            "ru": "Светлая"
        ],
        "theme_dark": [
            "en": "Dark",
            "ru": "Тёмная"
        ],
        "bootstrap_advanced_label": [
            "en": "Advanced: bootstrap discovery",
            "ru": "Дополнительно: обнаружение сервера"
        ],
        "bootstrap_advanced_hint": [
            "en": "For operators only. Lets the client find a working server/mask via signed CDN/Telegram/GitHub channels when you don't have a working aivpn:// key yet. Leave empty if you already have a key.",
            "ru": "Только для операторов. Позволяет клиенту найти рабочий сервер/маску через подписанные каналы CDN/Telegram/GitHub, если рабочего ключа aivpn:// ещё нет. Оставьте пустым, если ключ уже есть."
        ],
        "bootstrap_cdn_url": [
            "en": "CDN bootstrap URL",
            "ru": "CDN URL для bootstrap"
        ],
        "bootstrap_cdn_url_help": [
            "en": "HTTPS URL serving a signed bootstrap descriptor (multi-channel distribution).",
            "ru": "HTTPS-адрес, отдающий подписанный bootstrap-дескриптор (мультиканальное распространение)."
        ],
        "bootstrap_telegram_token": [
            "en": "Telegram bootstrap bot token",
            "ru": "Токен Telegram-бота для bootstrap"
        ],
        "bootstrap_telegram_token_help": [
            "en": "Telegram bot token that publishes signed bootstrap descriptors.",
            "ru": "Токен Telegram-бота, публикующего подписанные bootstrap-дескрипторы."
        ],
        "bootstrap_telegram_chat": [
            "en": "Telegram bootstrap chat/channel ID (optional)",
            "ru": "ID чата/канала Telegram для bootstrap (необязательно)"
        ],
        "bootstrap_telegram_chat_help": [
            "en": "Optional chat or channel ID the bootstrap bot publishes descriptors to.",
            "ru": "Необязательный ID чата или канала, в который бот публикует bootstrap-дескрипторы."
        ],
        "bootstrap_github": [
            "en": "GitHub bootstrap repo (e.g. owner/repo)",
            "ru": "GitHub-репозиторий для bootstrap (например owner/repo)"
        ],
        "bootstrap_github_help": [
            "en": "GitHub repository publishing signed bootstrap descriptors as releases/files.",
            "ru": "GitHub-репозиторий, публикующий подписанные bootstrap-дескрипторы (релизы/файлы)."
        ],
        "server_signing_key": [
            "en": "Server signing public key (base64)",
            "ru": "Публичный ключ подписи сервера (base64)"
        ],
        "server_signing_key_help": [
            "en": "Ed25519 public key used to verify bootstrap descriptor signatures. Required for bootstrap discovery to be trusted.",
            "ru": "Публичный ключ Ed25519 для проверки подписи bootstrap-дескриптора. Требуется, чтобы обнаружение сервера считалось доверенным."
        ],
        "polymorphic_mask": [
            "en": "Polymorphic (per-session unique shape)",
            "ru": "Полиморфизм (уникальная форма на сессию)"
        ],
        "polymorphic_mask_help": [
            "en": "Generates a unique traffic shape variant of the selected mask for every session, making DPI fingerprinting harder. Requires a specific mask (not Auto).",
            "ru": "Генерирует уникальный вариант формы трафика выбранной маски для каждой сессии, усложняя её распознавание DPI. Требует конкретную маску (не Авто)."
        ],
        "mask_feedback_section": [
            "en": "Crowdsourced mask feedback",
            "ru": "Коллективная обратная связь по маскам"
        ],
        "share_mask_feedback": [
            "en": "Share blocked-mask feedback",
            "ru": "Делиться данными о заблокированных масках"
        ],
        "share_mask_feedback_help": [
            "en": "Anonymously report when a mask gets blocked by DPI, helping other users avoid it.",
            "ru": "Анонимно сообщать о блокировке маски DPI, помогая другим пользователям её избегать."
        ],
        "receive_mask_hints": [
            "en": "Receive mask hints for my region",
            "ru": "Получать подсказки по маскам для моего региона"
        ],
        "receive_mask_hints_help": [
            "en": "Use crowdsourced feedback from other users to prefer masks that currently work well in your region.",
            "ru": "Использовать коллективные данные других пользователей для выбора масок, которые сейчас хорошо работают в вашем регионе."
        ],
        "country_code_placeholder": [
            "en": "Country code (e.g. RU)",
            "ru": "Код страны (например RU)"
        ],
        "country_code_help": [
            "en": "ISO 3166-1 alpha-2 country code (2 letters), used only for regional mask hints. Leave empty to disable.",
            "ru": "Код страны ISO 3166-1 alpha-2 (2 буквы), используется только для региональных подсказок по маскам. Оставьте пустым для отключения."
        ],

        // MARK: - Admin (P3.3-macOS client management)
        "admin_panel_button": [
            "en": "Manage Clients (Admin)",
            "ru": "Управление клиентами (админ)"
        ],
        "admin_panel_title": [
            "en": "Client Management",
            "ru": "Управление клиентами"
        ],
        "admin_clients": [
            "en": "Clients",
            "ru": "Клиенты"
        ],
        "admin_no_clients": [
            "en": "No clients yet.",
            "ru": "Клиентов пока нет."
        ],
        "admin_add_client": [
            "en": "Add Client",
            "ru": "Добавить клиента"
        ],
        "admin_client_name": [
            "en": "Client name",
            "ru": "Имя клиента"
        ],
        "admin_one_time": [
            "en": "One-time (revoke after first connect)",
            "ru": "Одноразовый (отозвать после первого подключения)"
        ],
        "admin_expires_at": [
            "en": "Expires",
            "ru": "Истекает"
        ],
        "admin_expires_enable": [
            "en": "Set expiration date",
            "ru": "Задать срок действия"
        ],
        "admin_create": [
            "en": "Create",
            "ru": "Создать"
        ],
        "admin_creating": [
            "en": "Creating…",
            "ru": "Создание…"
        ],
        "admin_role_user": [
            "en": "User",
            "ru": "Пользователь"
        ],
        "admin_role_viewer": [
            "en": "Viewer",
            "ru": "Наблюдатель"
        ],
        "admin_role_admin": [
            "en": "Admin",
            "ru": "Администратор"
        ],
        "admin_status_enabled": [
            "en": "Enabled",
            "ru": "Включён"
        ],
        "admin_status_disabled": [
            "en": "Disabled",
            "ru": "Отключён"
        ],
        "admin_edit": [
            "en": "Edit",
            "ru": "Изменить"
        ],
        "admin_save": [
            "en": "Save",
            "ru": "Сохранить"
        ],
        "admin_cancel": [
            "en": "Cancel",
            "ru": "Отмена"
        ],
        "admin_revoke": [
            "en": "Revoke",
            "ru": "Отозвать"
        ],
        "admin_revoke_confirm_title": [
            "en": "Revoke this client?",
            "ru": "Отозвать этого клиента?"
        ],
        "admin_revoke_confirm_message": [
            "en": "This immediately disconnects the client and invalidates its connection key. This cannot be undone.",
            "ru": "Клиент будет немедленно отключён, а его ключ подключения станет недействительным. Это действие необратимо."
        ],
        "admin_reset_device": [
            "en": "Reset Device Binding",
            "ru": "Сбросить привязку устройства"
        ],
        "admin_reset_device_confirm_title": [
            "en": "Reset device binding?",
            "ru": "Сбросить привязку устройства?"
        ],
        "admin_reset_device_confirm_message": [
            "en": "The client will be able to re-enroll from a new device using the same connection key.",
            "ru": "Клиент сможет повторно подключиться с нового устройства, используя тот же ключ подключения."
        ],
        "admin_show_key": [
            "en": "Show Connection Key",
            "ru": "Показать ключ подключения"
        ],
        "admin_connection_key": [
            "en": "Connection Key",
            "ru": "Ключ подключения"
        ],
        "admin_qr_loading": [
            "en": "Generating QR code…",
            "ru": "Генерация QR-кода…"
        ],
        "admin_qr_failed": [
            "en": "Could not generate QR code",
            "ru": "Не удалось создать QR-код"
        ],
        "admin_save_to_file": [
            "en": "Save to File…",
            "ru": "Сохранить в файл…"
        ],
        "admin_copy_key": [
            "en": "Copy Key",
            "ru": "Скопировать ключ"
        ],
        "admin_copied": [
            "en": "Copied",
            "ru": "Скопировано"
        ],
        "admin_loading": [
            "en": "Loading…",
            "ru": "Загрузка…"
        ],
        "admin_refresh": [
            "en": "Refresh",
            "ru": "Обновить"
        ],
        "admin_close": [
            "en": "Close",
            "ru": "Закрыть"
        ],
        "admin_error_generic": [
            "en": "Request failed. Is AIVPN connected?",
            "ru": "Запрос не выполнен. AIVPN подключён?"
        ],
        "admin_unavailable_title": [
            "en": "Admin panel unavailable",
            "ru": "Панель администратора недоступна"
        ],
        "admin_unavailable_message": [
            "en": "The admin channel could not be reached. Make sure you're connected, and note that in full-tunnel mode the admin socket token is only readable while running in SOCKS5 proxy mode.",
            "ru": "Не удалось подключиться к каналу администрирования. Убедитесь, что AIVPN подключён; учтите, что в режиме полного туннеля токен админ-сокета доступен для чтения только в режиме SOCKS5-прокси."
        ],
        "admin_not_admin_role": [
            "en": "Your account does not have admin access on this server.",
            "ru": "У вашей учётной записи нет прав администратора на этом сервере."
        ],
        "admin_device_bound": [
            "en": "Device bound",
            "ru": "Устройство привязано"
        ],
        "admin_vpn_ip": [
            "en": "VPN IP",
            "ru": "VPN IP"
        ],
        "admin_created_at": [
            "en": "Created",
            "ru": "Создан"
        ],

        // MARK: - Admin: pool topology (Wave B3-macOS)
        "admin_tab_clients": [
            "en": "Clients",
            "ru": "Клиенты"
        ],
        "admin_tab_pool": [
            "en": "Pool",
            "ru": "Пул"
        ],
        "admin_pool_title": [
            "en": "Pool Nodes",
            "ru": "Узлы пула"
        ],
        "admin_pool_no_nodes": [
            "en": "No pool nodes.",
            "ru": "Узлов пула нет."
        ],
        "admin_pool_health": [
            "en": "Pool Health",
            "ru": "Состояние пула"
        ],
        "admin_pool_transport": [
            "en": "Transport",
            "ru": "Транспорт"
        ],
        "admin_pool_total_nodes": [
            "en": "Total nodes",
            "ru": "Всего узлов"
        ],
        "admin_pool_connected_peers": [
            "en": "Connected peers",
            "ru": "Подключённые узлы"
        ],
        "admin_pool_converged_peers": [
            "en": "Converged peers",
            "ru": "Синхронизированные узлы"
        ],
        "admin_pool_diverged_warning": [
            "en": "Some peers are currently out of sync.",
            "ru": "Некоторые узлы сейчас рассинхронизированы."
        ],
        "admin_pool_partition_conflict_warning": [
            "en": "Partition conflict detected: two or more nodes are claiming the same VPN-IP partition.",
            "ru": "Обнаружен конфликт разделов: два или более узла используют один и тот же раздел VPN-IP."
        ],
        "admin_pool_subnet_mismatch_warning": [
            "en": "Subnet mismatch detected: a peer reports a different VPN subnet.",
            "ru": "Обнаружено несовпадение подсети: один из узлов сообщает другую VPN-подсеть."
        ],
        "admin_pool_node_verified": [
            "en": "Verified",
            "ru": "Подтверждён"
        ],
        "admin_pool_node_unverified": [
            "en": "Unverified",
            "ru": "Не подтверждён"
        ],
        "admin_pool_node_revoked": [
            "en": "Revoked",
            "ru": "Отозван"
        ],
        "admin_pool_node_connected": [
            "en": "Connected",
            "ru": "Подключён"
        ],
        "admin_pool_node_disconnected": [
            "en": "Disconnected",
            "ru": "Отключён"
        ],
        "admin_pool_last_seen": [
            "en": "Last seen",
            "ru": "Последний раз в сети"
        ],
        "admin_pool_never_seen": [
            "en": "Never",
            "ru": "Никогда"
        ],
        "admin_pool_no_address": [
            "en": "No dial address",
            "ru": "Нет адреса подключения"
        ],

        // MARK: - Admin: per-client exit node (Wave B3-macOS)
        "admin_exit_node": [
            "en": "Exit node (optional)",
            "ru": "Узел выхода (опционально)"
        ],
        "admin_exit_node_placeholder": [
            "en": "host:port — leave empty for global default",
            "ru": "host:port — оставьте пустым для значения по умолчанию"
        ],
        "admin_exit_node_current": [
            "en": "Exit node",
            "ru": "Узел выхода"
        ],
        "admin_exit_node_global": [
            "en": "Global default",
            "ru": "Глобальный по умолчанию"
        ],
        // G-B1: exit-node picker additions — dropdown sourced from
        // `GET /api/v1/pool/nodes` (AdminStore.poolNodes), with an explicit
        // "custom" escape hatch that keeps the original free-text host:port
        // entry available.
        "admin_exit_node_custom": [
            "en": "Custom (enter host:port)…",
            "ru": "Другой (ввести host:port)…"
        ],
        "admin_exit_node_live_hint": [
            "en": "Per-client exit node applies live — no reconnect needed.",
            "ru": "Узел выхода для клиента применяется вживую — переподключение не требуется."
        ],
        "admin_exit_node_restart_hint": [
            "en": "Global default exit node applies on the server's next restart.",
            "ru": "Глобальный узел выхода по умолчанию применяется после перезапуска сервера."
        ],

        // MARK: - Admin: error detail (P2 — status-specific wording where the
        // in-tunnel admin socket gives no error body to show; see
        // `adminErrorMessage` in AdminView.swift for why).
        "admin_error_bad_request": [
            "en": "Request rejected — invalid input.",
            "ru": "Запрос отклонён — некорректные данные."
        ],
        "admin_error_forbidden": [
            "en": "Forbidden — your role does not allow this action.",
            "ru": "Доступ запрещён — ваша роль не позволяет это действие."
        ],
        "admin_error_not_found": [
            "en": "Not found — this client may have already been removed.",
            "ru": "Не найдено — возможно, этот клиент уже удалён."
        ],
        "admin_error_conflict": [
            "en": "Conflict — the server's state changed; refresh and retry.",
            "ru": "Конфликт — состояние на сервере изменилось; обновите и повторите."
        ],
        "admin_error_server": [
            "en": "Server error — try again shortly.",
            "ru": "Ошибка сервера — попробуйте немного позже."
        ],

        // MARK: - Reject reason (G-A4) — localized text for the client's
        // machine-readable "AIVPN-STATUS rejected <token>" stdout line (see
        // handshake_reject_token() in crates/aivpn-client/src/client.rs).
        // Keys match the tokens verbatim (reject_reason_<token>).
        "reject_reason_one_time_used": [
            "en": "This one-time key was already used.",
            "ru": "Этот одноразовый ключ уже был использован."
        ],
        "reject_reason_expired": [
            "en": "This client's key has expired.",
            "ru": "Срок действия ключа этого клиента истёк."
        ],
        "reject_reason_disabled": [
            "en": "This client has been disabled by the server administrator.",
            "ru": "Этот клиент отключён администратором сервера."
        ],
        "reject_reason_unspecified": [
            "en": "The server refused this connection.",
            "ru": "Сервер отклонил это подключение."
        ],

        // MARK: - Admin: Viewer read-only mode (G-A1)
        "admin_panel_button_viewer": [
            "en": "View clients",
            "ru": "Просмотр клиентов"
        ],
        "admin_viewer_mode_banner": [
            "en": "Viewer mode — read-only, no changes allowed",
            "ru": "Режим просмотра — только чтение, изменения запрещены"
        ],

        // MARK: - Admin: audit log (G-A2)
        "admin_tab_audit": [
            "en": "Audit Log",
            "ru": "Журнал аудита"
        ],
        "audit_not_configured_title": [
            "en": "Audit log unavailable",
            "ru": "Журнал аудита недоступен"
        ],
        "audit_not_configured_message": [
            "en": "This server has no audit log configured, or the request failed.",
            "ru": "На этом сервере не настроен журнал аудита, либо запрос завершился с ошибкой."
        ],
        "audit_no_entries": [
            "en": "No audit entries yet.",
            "ru": "Записей аудита пока нет."
        ],
        "audit_chain_verified": [
            "en": "Chain verified",
            "ru": "Цепочка подтверждена"
        ],
        "audit_chain_broken": [
            "en": "Chain BROKEN",
            "ru": "Цепочка НАРУШЕНА"
        ],
        "audit_chain_broken_here": [
            "en": "Hash-chain verification broke at this entry",
            "ru": "Проверка цепочки хешей нарушена на этой записи"
        ],
        "audit_result_ok": [
            "en": "OK",
            "ru": "OK"
        ],
        "audit_result_failed": [
            "en": "Failed",
            "ru": "Ошибка"
        ],

        // MARK: - Entry buttons (Wave C3-macOS)
        "install_wizard_button": [
            "en": "Install server via SSH",
            "ru": "Установить сервер по SSH"
        ],

        // MARK: - SSH server install wizard (Wave C3-macOS)
        "install_wizard_title": [
            "en": "Install Server via SSH",
            "ru": "Установка сервера по SSH"
        ],
        "install_step_target_title": [
            "en": "Where to install",
            "ru": "Куда устанавливаем"
        ],
        "install_host": [
            "en": "Host (IP or domain)",
            "ru": "Хост (IP или домен)"
        ],
        "install_port": [
            "en": "SSH port",
            "ru": "SSH-порт"
        ],
        "install_user": [
            "en": "SSH user",
            "ru": "Пользователь SSH"
        ],
        "install_auth_title": [
            "en": "Authentication",
            "ru": "Аутентификация"
        ],
        "install_auth_password": [
            "en": "Password",
            "ru": "Пароль"
        ],
        "install_auth_key_file": [
            "en": "SSH key file",
            "ru": "Файл SSH-ключа"
        ],
        "install_password_placeholder": [
            "en": "SSH password",
            "ru": "Пароль SSH"
        ],
        "install_key_file_path": [
            "en": "Private key file (PEM)",
            "ru": "Файл приватного ключа (PEM)"
        ],
        "install_browse": [
            "en": "Choose…",
            "ru": "Выбрать…"
        ],
        "install_key_passphrase": [
            "en": "Key passphrase (optional)",
            "ru": "Пароль ключа (опционально)"
        ],
        "install_server_ip": [
            "en": "Server public IP (optional, auto-detected if empty)",
            "ru": "Публичный IP сервера (опционально, авто-определение)"
        ],
        "install_server_port": [
            "en": "Server VPN port (optional)",
            "ru": "VPN-порт сервера (опционально)"
        ],
        "install_mode": [
            "en": "Install mode",
            "ru": "Режим установки"
        ],
        "install_mode_systemd": [
            "en": "systemd",
            "ru": "systemd"
        ],
        "install_mode_docker": [
            "en": "Docker",
            "ru": "Docker"
        ],
        "install_bind_device": [
            "en": "Bind admin client to this device",
            "ru": "Привязать admin-клиент к этому устройству"
        ],
        "install_bind_device_help": [
            "en": "On: uses this Mac's device key (or creates one on the server). Off: creates an unbound admin client.",
            "ru": "Вкл.: используется ключ устройства этого Mac (или создаётся на сервере). Выкл.: создаётся непривязанный admin-клиент."
        ],
        "install_advanced": [
            "en": "Advanced",
            "ru": "Дополнительно"
        ],
        "install_binary_source": [
            "en": "aivpn-server binary source",
            "ru": "Источник бинарника aivpn-server"
        ],
        "install_binary_source_releases": [
            "en": "GitHub Releases (default)",
            "ru": "GitHub Releases (по умолчанию)"
        ],
        "install_binary_source_file": [
            "en": "Local file",
            "ru": "Локальный файл"
        ],
        "install_binary_source_url": [
            "en": "URL",
            "ru": "URL"
        ],
        "install_binary_file_path": [
            "en": "Local aivpn-server binary path",
            "ru": "Путь к локальному бинарнику aivpn-server"
        ],
        "install_binary_url": [
            "en": "Download URL",
            "ru": "URL для загрузки"
        ],
        "install_probing": [
            "en": "Checking host key…",
            "ru": "Проверка отпечатка хоста…"
        ],
        "install_next_probe": [
            "en": "Next: check host fingerprint",
            "ru": "Далее: проверить отпечаток"
        ],
        "install_tofu_title": [
            "en": "Confirm host identity",
            "ru": "Подтвердите личность хоста"
        ],
        "install_tofu_message": [
            "en": "This is the SSH host key fingerprint the server presented. Verify it out-of-band if possible, then trust it to continue.",
            "ru": "Это отпечаток SSH-ключа хоста, который предъявил сервер. По возможности сверьте его отдельным каналом, затем подтвердите доверие для продолжения."
        ],
        "install_show_script": [
            "en": "Show install script",
            "ru": "Показать скрипт установки"
        ],
        "install_cancel": [
            "en": "Cancel",
            "ru": "Отмена"
        ],
        "install_trust_and_install": [
            "en": "Trust & Install",
            "ru": "Доверяю, установить"
        ],
        "install_script_title": [
            "en": "install-server.sh",
            "ru": "install-server.sh"
        ],
        "install_script_sha256": [
            "en": "SHA256",
            "ru": "SHA256"
        ],
        "install_close": [
            "en": "Close",
            "ru": "Закрыть"
        ],
        "install_installing_title": [
            "en": "Installing…",
            "ru": "Установка…"
        ],
        "install_success_title": [
            "en": "Installation complete",
            "ru": "Установка завершена"
        ],
        "install_failure_title": [
            "en": "Installation failed",
            "ru": "Установка не удалась"
        ],
        "install_exit_code": [
            "en": "exit code",
            "ru": "код завершения"
        ],
        "install_profile_name": [
            "en": "Profile name",
            "ru": "Имя профиля"
        ],
        "install_import_profile": [
            "en": "Import profile",
            "ru": "Импортировать профиль"
        ],
        "install_imported": [
            "en": "Profile imported — connected as admin.",
            "ru": "Профиль импортирован — подключение как администратор."
        ],
        // G-C1: the key is now imported automatically as soon as the
        // client_done marker arrives (see InstallServerStore.startInstall's
        // marker handler) — these support the rename affordance the
        // "Import profile" button used to gate, kept so the user can still
        // see/rename the profile without a mandatory manual click.
        "install_rename": [
            "en": "Rename",
            "ru": "Переименовать"
        ],
        "install_import_failed": [
            "en": "Automatic import failed — add this key manually from the main window.",
            "ru": "Не удалось импортировать ключ автоматически — добавьте его вручную в главном окне."
        ],
        "install_no_connection_key": [
            "en": "No connection key was returned over this channel (device binding was likely off) — check the admin panel or server logs to fetch one manually.",
            "ru": "По этому каналу ключ подключения не получен (вероятно, привязка устройства была выключена) — получите его вручную через панель администрирования или логи сервера."
        ],
        "install_start_over": [
            "en": "New install",
            "ru": "Новая установка"
        ],

        // Known ##AIVPN marker steps (install-server.sh + ssh-install run) —
        // mirrors the step list documented on ssh_install_cmd.rs.
        "install_step_ssh_connect": [
            "en": "Connecting over SSH",
            "ru": "Подключение по SSH"
        ],
        "install_step_upload": [
            "en": "Uploading",
            "ru": "Загрузка файлов"
        ],
        "install_step_start": [
            "en": "Starting installer",
            "ru": "Запуск установщика"
        ],
        "install_step_detect_env": [
            "en": "Detecting environment",
            "ru": "Определение окружения"
        ],
        "install_step_port_check": [
            "en": "Checking VPN port",
            "ru": "Проверка VPN-порта"
        ],
        "install_step_install_deps": [
            "en": "Installing dependencies",
            "ru": "Установка зависимостей"
        ],
        "install_step_tun_device": [
            "en": "Configuring TUN device",
            "ru": "Настройка TUN-устройства"
        ],
        "install_step_create_dirs": [
            "en": "Creating directories",
            "ru": "Создание директорий"
        ],
        "install_step_fetch_binary": [
            "en": "Fetching aivpn-server binary",
            "ru": "Загрузка бинарника aivpn-server"
        ],
        "install_step_verify_binary": [
            "en": "Verifying binary",
            "ru": "Проверка бинарника"
        ],
        "install_step_install_binary": [
            "en": "Installing binary",
            "ru": "Установка бинарника"
        ],
        "install_step_seed_config": [
            "en": "Writing server config",
            "ru": "Запись конфигурации сервера"
        ],
        "install_step_gen_key": [
            "en": "Generating server keys",
            "ru": "Генерация ключей сервера"
        ],
        "install_step_seed_masks": [
            "en": "Seeding masks",
            "ru": "Загрузка масок"
        ],
        "install_step_install_systemd_unit": [
            "en": "Installing systemd unit",
            "ru": "Установка systemd-юнита"
        ],
        "install_step_ip_forward": [
            "en": "Enabling IP forwarding",
            "ru": "Включение IP-форвардинга"
        ],
        "install_step_firewall": [
            "en": "Configuring firewall",
            "ru": "Настройка файервола"
        ],
        "install_step_start_service": [
            "en": "Starting service",
            "ru": "Запуск сервиса"
        ],
        "install_step_create_admin_client": [
            "en": "Creating admin client",
            "ru": "Создание admin-клиента"
        ],
        "install_step_health_check": [
            "en": "Health check",
            "ru": "Проверка работоспособности"
        ],
        "install_step_done": [
            "en": "Done",
            "ru": "Готово"
        ],
        "install_step_client_done": [
            "en": "Installer finished",
            "ru": "Установщик завершил работу"
        ],
        "install_step_device_pubkey": [
            "en": "Device binding",
            "ru": "Привязка устройства"
        ],
        "install_step_preflight": [
            "en": "Preflight checks",
            "ru": "Предварительные проверки"
        ],
        "install_step_docker_mode": [
            "en": "Docker setup",
            "ru": "Настройка Docker"
        ],

        // Known ##AIVPN marker codes.
        "install_code_port_free": [
            "en": "port free",
            "ru": "порт свободен"
        ],
        "install_code_upgrade": [
            "en": "upgrading existing install",
            "ru": "обновление существующей установки"
        ],
        "install_code_port_busy": [
            "en": "port busy",
            "ru": "порт занят"
        ],
        "install_code_created": [
            "en": "created",
            "ru": "создано"
        ],
        "install_code_exists": [
            "en": "already exists",
            "ru": "уже существует"
        ],
        "install_code_template_missing": [
            "en": "template missing",
            "ru": "шаблон отсутствует"
        ],
        "install_code_no_local_device_key": [
            "en": "no local device key",
            "ru": "нет локального ключа устройства"
        ],
        "install_code_fingerprint_mismatch": [
            "en": "fingerprint mismatch",
            "ru": "отпечаток не совпадает"
        ],
        "install_code_auth_failed": [
            "en": "authentication failed",
            "ru": "ошибка аутентификации"
        ],
        "install_code_connect_failed": [
            "en": "connection failed",
            "ru": "ошибка подключения"
        ],
        "install_code_binary_missing": [
            "en": "aivpn-client not found",
            "ru": "aivpn-client не найден"
        ],
        "install_code_spawn_failed": [
            "en": "failed to start process",
            "ru": "не удалось запустить процесс"
        ],

        // MARK: - Server settings (G-A3: apply-with-rollback)
        "server_settings_title": [
            "en": "Server Settings",
            "ru": "Настройки сервера"
        ],
        "server_settings_button": [
            "en": "Server settings…",
            "ru": "Настройки сервера…"
        ],
        "server_settings_admin_only": [
            "en": "Admin access required to view server settings.",
            "ru": "Для просмотра настроек сервера требуются права администратора."
        ],
        "server_settings_mask_section_title": [
            "en": "Active mask",
            "ru": "Активная маска"
        ],
        "server_settings_select_client": [
            "en": "Client",
            "ru": "Клиент"
        ],
        "server_settings_no_clients": [
            "en": "No clients available",
            "ru": "Нет доступных клиентов"
        ],
        "server_settings_mask_catalog_unavailable": [
            "en": "Mask catalog unavailable — enter a mask ID manually.",
            "ru": "Каталог масок недоступен — введите ID маски вручную."
        ],
        "server_settings_mask_id_placeholder": [
            "en": "Mask ID",
            "ru": "ID маски"
        ],
        "server_settings_mask_auto": [
            "en": "auto",
            "ru": "авто"
        ],
        "server_settings_apply": [
            "en": "Apply",
            "ru": "Применить"
        ],
        "server_settings_applying": [
            "en": "Applying…",
            "ru": "Применение…"
        ],
        "server_settings_confirm": [
            "en": "Confirm",
            "ru": "Подтвердить"
        ],
        "server_settings_confirming": [
            "en": "Confirming…",
            "ru": "Подтверждение…"
        ],
        "server_settings_confirm_countdown": [
            "en": "Confirm within %d s or it reverts",
            "ru": "Подтвердите в течение %d с, иначе откат"
        ],
        "server_settings_reverted": [
            "en": "Reverted — the change was not confirmed in time.",
            "ru": "Откат — изменение не было подтверждено вовремя."
        ],
        "server_settings_exit_section_title": [
            "en": "Global default exit (pool)",
            "ru": "Глобальный узел выхода по умолчанию (пул)"
        ],
        "server_settings_exit_restart_note": [
            "en": "Applies after server RESTART.",
            "ru": "Применяется после ПЕРЕЗАПУСКА сервера."
        ],
        "server_settings_exit_none": [
            "en": "(none)",
            "ru": "(нет)"
        ],
    ]

    init() {
        language = UserDefaults.standard.string(forKey: "app_language") ?? Locale.current.language.languageCode?.identifier ?? "en"
        if language != "en" && language != "ru" {
            language = "en"
        }
    }

    func t(_ key: String) -> String {
        guard let dict = strings[key] else { return key }
        return dict[language] ?? dict["en"] ?? key
    }

    /// G-A4: maps a `handshake_reject_token()` value (crates/aivpn-client/
    /// src/client.rs) — carried verbatim through the helper's
    /// "AIVPN-STATUS rejected <token>" status message (see
    /// `rejectToken(in:)` in aivpn-helper/main.swift and the `pollStatus()`
    /// parser in VPNManager.swift) — to a localized user-facing string.
    /// An unrecognized token (e.g. a future server adds a reason this build
    /// doesn't know about) falls back to the generic "unspecified" wording
    /// rather than leaking the raw ASCII token to the UI.
    func rejectReasonText(token: String) -> String {
        switch token {
        case "one_time_used": return t("reject_reason_one_time_used")
        case "expired": return t("reject_reason_expired")
        case "disabled": return t("reject_reason_disabled")
        default: return t("reject_reason_unspecified")
        }
    }

    func toggleLanguage() {
        language = language == "en" ? "ru" : "en"
    }
}
