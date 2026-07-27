import Foundation
import Combine

class LocalizationManager: ObservableObject {
    static let shared = LocalizationManager()

    private static let appVersion: String = {
        return Bundle.main.infoDictionary?["CFBundleShortVersionString"] as? String ?? "?"
    }()

    @Published var language: String = "en" {
        didSet { UserDefaults.standard.set(language, forKey: "app_language") }
    }

    private let strings: [String: [String: String]] = [
        "status_connected":    ["en": "Connected",      "ru": "Подключено"],
        "status_disconnected": ["en": "Disconnected",   "ru": "Отключено"],
        "status_connecting":   ["en": "Connecting…",    "ru": "Подключение…"],
        "status_reconnecting":  ["en": "Reconnecting…",   "ru": "Переподключение…"],
        "status_disconnecting": ["en": "Disconnecting…",  "ru": "Отключение…"],
        "connect":             ["en": "Connect",        "ru": "Подключить"],
        "disconnect":          ["en": "Disconnect",     "ru": "Отключить"],
        "enter_key":           ["en": "Connection key (aivpn://…)", "ru": "Ключ подключения (aivpn://…)"],
        "full_tunnel":         ["en": "Full tunnel (route all traffic)", "ru": "Полный туннель (весь трафик)"],
        "add_key":             ["en": "Add Key",        "ru": "Добавить ключ"],
        "key_name":            ["en": "Key Name",       "ru": "Название ключа"],
        "save_key":            ["en": "Save",           "ru": "Сохранить"],
        "cancel":              ["en": "Cancel",         "ru": "Отмена"],
        "delete":              ["en": "Delete",         "ru": "Удалить"],
        "edit":                ["en": "Edit",           "ru": "Изменить"],
        "connection_keys":     ["en": "Saved Keys",     "ru": "Сохранённые ключи"],
        "no_keys_yet":         ["en": "No keys yet",   "ru": "Нет ключей"],
        "add_first_key":       ["en": "Add First Key",  "ru": "Добавить первый ключ"],
        "no_key_selected":     ["en": "No key selected","ru": "Ключ не выбран"],
        "duplicate_key":       ["en": "This key already exists", "ru": "Этот ключ уже существует"],
        "delete_key_confirm":  ["en": "Delete Key?",    "ru": "Удалить ключ?"],
        "delete_key_message":  ["en": "Are you sure you want to delete this key?",
                                "ru": "Вы уверены что хотите удалить этот ключ?"],
        "split_tunnel":        ["en": "Excluded Domains (Split DNS)", "ru": "Исключённые домены (Split DNS)"],
        "split_tunnel_routes": ["en": "Excluded Routes (CIDR)",      "ru": "Исключённые маршруты (CIDR)"],
        "split_tunnel_none":   ["en": "None",                         "ru": "Нет"],
        "record_new_mask":     ["en": "Record New Mask", "ru": "Записать новую маску"],
        "stop_recording":      ["en": "Stop Recording", "ru": "Остановить запись"],
        "record_service_name": ["en": "Mask Service Name", "ru": "Имя сервиса для маски"],
        "recording_starting":  ["en": "Starting recording…", "ru": "Запуск записи…"],
        "recording_active":    ["en": "Recording in progress. Use the service normally.",
                                "ru": "Запись идёт. Используйте сервис как обычно."],
        "recording_stopping":  ["en": "Stopping recording…", "ru": "Останавливаем запись…"],
        "recording_analyzing": ["en": "Analyzing traffic…",  "ru": "Анализ трафика…"],
        "recording_success":   ["en": "Mask recorded successfully", "ru": "Маска успешно записана"],
        "recording_failed":    ["en": "Mask recording failed",      "ru": "Запись маски не удалась"],
        "cert_rejected_title": ["en": "Certificate rejected", "ru": "Сертификат отклонён"],
        "cert_rejected_body":  ["en": "The server rejected your client certificate. Re-add this connection key to re-provision it.",
                                "ru": "Сервер отклонил клиентский сертификат. Добавьте ключ подключения заново, чтобы перевыпустить его."],
        "handshake_rejected_title": ["en": "Connection refused", "ru": "В подключении отказано"],
        "handshake_reject_reason_1": ["en": "This one-time connection key has already been used. Ask the server operator for a new key.",
                                      "ru": "Этот одноразовый ключ подключения уже использован. Запросите новый ключ у оператора сервера."],
        "handshake_reject_reason_2": ["en": "This client has expired. Ask the server operator for a new connection key.",
                                      "ru": "Срок действия этого клиента истёк. Запросите новый ключ подключения у оператора сервера."],
        "handshake_reject_reason_3": ["en": "This client has been disabled by the server operator.",
                                      "ru": "Этот клиент отключён оператором сервера."],
        "handshake_reject_reason_0": ["en": "The server refused this connection.",
                                      "ru": "Сервер отклонил это подключение."],
        "recording_self_test_failed": ["en": "Mask did not pass verification",
                                       "ru": "Маска не прошла проверку"],
        "recording_result_success_title": ["en": "Last recording: saved",
                                           "ru": "Результат: маска сохранена"],
        "recording_result_failed_title":  ["en": "Last recording: not saved",
                                           "ru": "Результат: маска не сохранена"],
        "dismiss":             ["en": "Dismiss",  "ru": "Скрыть"],
        "upload":              ["en": "Upload",   "ru": "Исходящий"],
        "download":            ["en": "Download", "ru": "Входящий"],
        "duration":            ["en": "Duration", "ru": "Длительность"],
        "version_footer":      ["en": "v\(LocalizationManager.appVersion) · Neural Resonance VPN",
                                "ru": "v\(LocalizationManager.appVersion) · Neural Resonance VPN"],
        "error_invalid_key":   ["en": "Invalid connection key format",
                                "ru": "Неверный формат ключа подключения"],
        "no_profiles":         ["en": "No saved keys. Tap + to add one.",
                                "ru": "Нет ключей. Нажмите + для добавления."],
        "recording_ready":     ["en": "Recording availability is checked by the server when you start",
                                "ru": "Доступ к записи проверяется сервером при запуске"],
        "adaptive_mode":       ["en": "Adaptive Mode",          "ru": "Адаптивный режим"],
        "adaptive_mode_help":  ["en": "Auto-adjusts keepalive and FEC on unstable connections",
                                "ru": "Автоматически адаптирует keepalive и FEC при нестабильном соединении"],
        "adaptive_off":        ["en": "Off",                    "ru": "Выкл"],
        "adaptive_light":      ["en": "Light (6s)",             "ru": "Лёгкий (6с)"],
        "adaptive_aggressive": ["en": "Aggressive (4s)",        "ru": "Агрессивный (4с)"],
        "adaptive_satellite":  ["en": "Satellite (15s)",        "ru": "Спутник (15с)"],
        "diagnostics":         ["en": "Diagnostics",            "ru": "Диагностика"],
        "run_benchmark":       ["en": "Run Benchmark",          "ru": "Запустить тест"],
        "bench_running":       ["en": "Running benchmark…",     "ru": "Тест запущен…"],
        "bench_idle":          ["en": "Tap to measure latency and connection quality.",
                                "ru": "Нажмите для измерения задержки и качества соединения."],
        "mtls_cert_hint":      ["en": "mTLS cert (base64, leave empty to disable)",
                                "ru": "mTLS сертификат (base64, оставьте пустым для отключения)"],
        "server_signing_key":  ["en": "Server signing key",
                                "ru": "Ключ подписи сервера"],
        "server_signing_key_hint": [
            "en": "Ed25519 public key (base64) to verify server signatures. Leave empty to skip.",
            "ru": "Публичный ключ Ed25519 (base64) для проверки подписей сервера. Оставьте пустым, чтобы пропустить."
        ],
        "kill_switch":         ["en": "Kill Switch (block traffic if VPN drops)",
                                "ru": "Kill Switch (блокировать при разрыве)"],
        "done":                ["en": "Done",           "ru": "Готово"],
        "split_tunnel_title":  ["en": "Split Tunnel",   "ru": "Split Tunnel"],
        "open_settings":       ["en": "Open Settings",  "ru": "Открыть Настройки"],
        "error_permission_denied": [
            "en": "VPN permission denied. Tap Retry or open Settings → VPN to allow.",
            "ru": "Доступ к VPN запрещён. Нажмите «Повторить» или откройте Настройки → VPN.",
        ],
        "error_vpn_write_failed": [
            "en": "Cannot save VPN config. Check Network Extension capability in your provisioning profile.",
            "ru": "Не удалось сохранить VPN конфигурацию. Проверьте Network Extension в provisioning profile.",
        ],
        "error_keychain_write_failed": [
            "en": "Could not securely store the connection secret in Keychain. Connection cancelled.",
            "ru": "Не удалось безопасно сохранить секрет подключения в Keychain. Подключение отменено.",
        ],
        "menu_edit":           ["en": "Edit",            "ru": "Изменить"],
        "menu_delete":         ["en": "Delete",          "ru": "Удалить"],
        "bench_quality_label": ["en": "Quality",         "ru": "Качество"],
        "bench_p50_label":     ["en": "P50 latency",     "ru": "Задержка P50"],
        "bench_ms":            ["en": "ms",              "ru": "мс"],
        "invalid_cidr":        ["en": "Invalid format — use 192.168.1.0/24",
                                "ru": "Неверный формат — используйте 192.168.1.0/24"],
        "split_tunnel_note":   [
            "en": "Domain and route lists are stored in the App Group and are not cryptographically verified.",
            "ru": "Списки доменов и маршрутов хранятся в App Group без криптографической верификации.",
        ],
        "quality":             ["en": "Quality",        "ru": "Качество"],
        "key_save_failed":     ["en": "Failed to save key — check VPN and Keychain permissions in Settings.",
                                "ru": "Не удалось сохранить ключ — проверьте разрешения VPN и Keychain в Настройках."],
        "recording_server_rejected": [
            "en": "Server rejected the recording request",
            "ru": "Сервер отклонил запрос на запись",
        ],
        "retry":               ["en": "Retry",          "ru": "Повторить"],
        "settings":            ["en": "Settings",       "ru": "Настройки"],
        "fec_active":          ["en": "FEC Active",     "ru": "FEC активен"],
        "mask_profile":        ["en": "Mask Profile",   "ru": "Профиль маски"],
        "mask_auto":           ["en": "Auto",           "ru": "Авто"],
        "mask_auto_marker":    ["en": " (auto)",        "ru": " (авто)"],
        "polymorphic_mode":    ["en": "Polymorphic (per-session unique)",
                                 "ru": "Полиморфная маска (уникальна для сессии)"],
        "share_mask_feedback": ["en": "Share blocked-mask feedback",
                                 "ru": "Делиться данными о заблокированных масках"],
        "receive_mask_hints":  ["en": "Receive mask hints",
                                 "ru": "Получать рекомендации масок"],
        "country_code":        ["en": "Country Code",   "ru": "Код страны"],
        "country_code_placeholder": ["en": "US",         "ru": "US"],

        // MARK: Bootstrap descriptor discovery ("Advanced" / discover server)
        "advanced_section":    ["en": "Advanced",       "ru": "Дополнительно"],
        "advanced_hint":       [
            "en": "Discover a server without a saved connection key, using signed rotating descriptors distributed via CDN, GitHub, or Telegram. You still need the server address, its public key, and the operator's signing key from another source.",
            "ru": "Найдите сервер без сохранённого ключа подключения — с помощью подписанных дескрипторов, которые распространяются через CDN, GitHub или Telegram. Адрес сервера, его открытый ключ и ключ подписи оператора всё равно нужно получить из другого источника.",
        ],
        "bootstrap_open_discovery": ["en": "Discover Server…", "ru": "Найти сервер…"],
        "bootstrap_discovery_title": ["en": "Discover Server", "ru": "Поиск сервера"],
        "bootstrap_server_section": ["en": "Server", "ru": "Сервер"],
        "bootstrap_channels_section": ["en": "Descriptor Channels", "ru": "Каналы дескрипторов"],
        "bootstrap_server_address": ["en": "Server address (host:port)", "ru": "Адрес сервера (host:port)"],
        "bootstrap_server_pubkey": ["en": "Server public key (hex)", "ru": "Публичный ключ сервера (hex)"],
        "bootstrap_server_psk": ["en": "Pre-shared key (hex, optional)", "ru": "Общий ключ PSK (hex, необязательно)"],
        "bootstrap_key_name": ["en": "Key name", "ru": "Название ключа"],
        "bootstrap_signing_pubkey": ["en": "Descriptor signing public key (hex)", "ru": "Ключ подписи дескрипторов (hex)"],
        "bootstrap_cdn_url": ["en": "CDN URL", "ru": "CDN URL"],
        "bootstrap_github_repo": ["en": "GitHub repo (owner/repo)", "ru": "GitHub репозиторий (owner/repo)"],
        "bootstrap_telegram_bot_token": ["en": "Telegram bot token", "ru": "Токен Telegram-бота"],
        "bootstrap_telegram_chat": ["en": "Telegram chat/channel ID", "ru": "ID чата/канала Telegram"],
        "bootstrap_discover_button": ["en": "Discover Server", "ru": "Найти сервер"],
        "bootstrap_discovering": ["en": "Discovering…", "ru": "Поиск…"],
        "bootstrap_channel_results": ["en": "Channel Results", "ru": "Результаты по каналам"],
        "bootstrap_result_success": [
            "en": "Discovered {n} descriptor(s) from {m} channel(s). Saved as \"{name}\".",
            "ru": "Найдено дескрипторов: {n} (каналов успешно: {m}). Сохранено как «{name}».",
        ],
        "bootstrap_result_failure": [
            "en": "No valid descriptors found. Check channel settings and the signing key.",
            "ru": "Дескрипторы не найдены. Проверьте настройки каналов и ключ подписи.",
        ],
        "bootstrap_missing_fields": [
            "en": "Server address is required.",
            "ru": "Укажите адрес сервера.",
        ],
        "bootstrap_invalid_server_key": [
            "en": "Server public key must be 64 hex characters (32 bytes).",
            "ru": "Публичный ключ сервера должен быть 64 hex-символа (32 байта).",
        ],
        "bootstrap_invalid_signing_key": [
            "en": "Signing public key must be 64 hex characters (32 bytes).",
            "ru": "Ключ подписи должен быть 64 hex-символа (32 байта).",
        ],
        "bootstrap_encode_failed": [
            "en": "Failed to build the connection key from the discovered data.",
            "ru": "Не удалось собрать ключ подключения из найденных данных.",
        ],
        "bootstrap_default_key_name": ["en": "Discovered", "ru": "Найден"],

        // MARK: In-app admin (P3.2) — client management screen
        "admin_title":            ["en": "Client Management", "ru": "Управление клиентами"],
        "admin_loading":          ["en": "Loading…", "ru": "Загрузка…"],
        "admin_no_clients":       ["en": "No clients yet", "ru": "Нет клиентов"],
        "admin_add_client":       ["en": "Add Client", "ru": "Добавить клиента"],
        "admin_save":             ["en": "Save", "ru": "Сохранить"],
        "admin_client_name":      ["en": "Client name", "ru": "Имя клиента"],
        "admin_one_time":         ["en": "One-time enrollment", "ru": "Одноразовое подключение"],
        "admin_has_expiry":       ["en": "Expires", "ru": "Истекает"],
        "admin_expires_at":       ["en": "Expires at", "ru": "Дата истечения"],
        "admin_edit_section":     ["en": "Edit", "ru": "Изменить"],
        "admin_info":             ["en": "Info", "ru": "Информация"],
        "admin_enabled":          ["en": "Enabled", "ru": "Включён"],
        "admin_vpn_ip":           ["en": "VPN IP", "ru": "VPN IP"],
        "admin_role":             ["en": "Role", "ru": "Роль"],
        "admin_role_admin":       ["en": "Admin", "ru": "Администратор"],
        "admin_role_viewer":      ["en": "Viewer", "ru": "Наблюдатель"],
        "admin_role_user":        ["en": "User", "ru": "Пользователь"],
        "admin_device_bound":     ["en": "Device bound", "ru": "Устройство привязано"],
        "admin_yes":              ["en": "Yes", "ru": "Да"],
        "admin_no":               ["en": "No", "ru": "Нет"],
        "admin_created_at":       ["en": "Created", "ru": "Создан"],
        "admin_traffic_in":       ["en": "Received", "ru": "Получено"],
        "admin_traffic_out":      ["en": "Sent", "ru": "Отправлено"],
        "admin_connection_key":   ["en": "Connection Key", "ru": "Ключ подключения"],
        "admin_show_connection_key": ["en": "Show Connection Key", "ru": "Показать ключ подключения"],
        "admin_copy":             ["en": "Copy", "ru": "Копировать"],
        "admin_share":            ["en": "Share", "ru": "Поделиться"],
        "admin_reset_device":     ["en": "Reset Device Binding", "ru": "Сбросить привязку устройства"],
        "admin_reset_device_hint": [
            "en": "Clears the bound device key and re-enables one-time enrollment for this client.",
            "ru": "Сбрасывает привязку устройства и снова разрешает одноразовое подключение для этого клиента.",
        ],
        "admin_reset_device_done": ["en": "Device binding reset", "ru": "Привязка устройства сброшена"],
        "admin_revoke":           ["en": "Revoke", "ru": "Отозвать"],
        "admin_revoke_confirm_title": [
            "en": "Revoke this client?",
            "ru": "Отозвать этого клиента?",
        ],
        "admin_revoke_confirm_message": [
            "en": "Permanently revoke and disconnect this client. This cannot be undone.",
            "ru": "Клиент будет безвозвратно отозван и отключён. Это действие нельзя отменить.",
        ],

        // MARK: Per-client exit node (Wave B2a/B3-iOS)
        "admin_exit_node":        ["en": "Exit node (optional)", "ru": "Узел выхода (необязательно)"],
        "admin_exit_node_hint": [
            "en": "host:port — leave empty to use the server's global exit node.",
            "ru": "host:port — оставьте пустым, чтобы использовать глобальный узел выхода сервера.",
        ],
        "admin_exit_node_global": ["en": "Global (default)", "ru": "Глобальный (по умолчанию)"],

        // MARK: Pool topology view (Wave B1/B3-iOS)
        "pool_title":              ["en": "Pool Topology", "ru": "Топология пула"],
        "pool_health_section":     ["en": "Pool Health", "ru": "Состояние пула"],
        "pool_nodes_section":      ["en": "Nodes", "ru": "Узлы"],
        "pool_links_section":      ["en": "Links", "ru": "Связи"],
        "pool_no_nodes":           ["en": "No pool nodes", "ru": "Нет узлов пула"],
        "pool_transport":          ["en": "Transport", "ru": "Транспорт"],
        "pool_transport_masked":   ["en": "Masked", "ru": "Маскированный"],
        "pool_transport_legacy":   ["en": "Legacy", "ru": "Устаревший"],
        "pool_transport_none":     ["en": "Not configured", "ru": "Не настроен"],
        "pool_total_nodes":        ["en": "Total nodes", "ru": "Всего узлов"],
        "pool_connected_peers":    ["en": "Connected peers", "ru": "Подключено пиров"],
        "pool_converged_peers":    ["en": "Converged peers", "ru": "Синхронизировано пиров"],
        "pool_diverged":           ["en": "Diverged", "ru": "Есть расхождение"],
        "pool_revoked":            ["en": "Revoked", "ru": "Отозван"],
        "pool_last_seen":          ["en": "Last seen", "ru": "Последний раз в сети"],
        "pool_last_converged":     ["en": "Last converged", "ru": "Последняя синхронизация"],
        "pool_conflict_warning": [
            "en": "Pool partition or subnet conflict detected — check node configuration.",
            "ru": "Обнаружен конфликт партиции или подсети пула — проверьте настройки узлов.",
        ],
        "pool_partition_conflict": ["en": "Partition conflict", "ru": "Конфликт партиции"],
        "pool_subnet_mismatch":    ["en": "Subnet mismatch", "ru": "Несовпадение подсети"],
    ]

    init() {
        let systemLang: String?
        if #available(iOS 16, *) {
            systemLang = Locale.current.language.languageCode?.identifier
        } else {
            systemLang = Locale.current.languageCode
        }
        language = UserDefaults.standard.string(forKey: "app_language") ?? systemLang ?? "en"
        if language != "en" && language != "ru" { language = "en" }
    }

    func t(_ key: String) -> String {
        guard let dict = strings[key] else { return key }
        return dict[language] ?? dict["en"] ?? key
    }

    func toggleLanguage() {
        language = language == "en" ? "ru" : "en"
    }
}
