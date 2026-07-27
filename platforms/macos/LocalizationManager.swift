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

    func toggleLanguage() {
        language = language == "en" ? "ru" : "en"
    }
}
