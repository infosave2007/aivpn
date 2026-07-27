//! Localization: EN passthrough / RU translation lookup table. Moved
//! verbatim out of `app/mod.rs` (pure move, no behavior change).

pub(super) fn t<'a>(lang: &str, key: &'a str) -> &'a str {
    if lang != "ru" {
        return key;
    }
    match key {
        "Disconnected" => "Отключено",
        "Connecting..." => "Подключение...",
        "Connect" => "Подключить",
        "Disconnect" => "Отключить",
        "No profiles - add one below" => "Нет профилей - добавьте ниже",
        "Select a profile below" => "Выберите профиль",
        "Profiles" => "Профили",
        "+ Add" => "+ Добавить",
        "Edit" => "Ред.",
        "Diagnostics" => "Диагностика",
        // 3c: bootstrap-fallback indicator (client fell back to the
        // built-in default mask after repeated dead handshakes).
        "Using built-in mask (fallback)" => "Встроенная маска (аварийный режим)",
        "Running diagnostics..." => "Диагностика...",
        "Adaptive mode" => "Адаптивный режим",
        "Mask profile" => "Маска трафика",
        "Polymorphic (per-session unique shape)" => "Полиморфизм (уникальная форма на сессию)",
        "Each session gets a unique variant of the selected mask. Not used with \"Auto\"." => {
            "Каждая сессия получает уникальный вариант выбранной маски. Недоступно для \"Авто\"."
        }
        "Share blocked-mask feedback" => "Делиться данными о заблокированных масках",
        "Receive mask hints for my region" => "Получать подсказки масок для моего региона",
        "Country code" => "Код страны",
        "Kill switch" => "Kill switch",
        "Start on login" => "Автозапуск",
        "DNS proxy" => "DNS прокси",
        "Exclude routes" => "Исключить маршруты",
        "Include routes only" => "Только эти маршруты",
        "SOCKS5 proxy" => "SOCKS5 прокси",
        "Device key path" => "Путь к ключу",
        "Log" => "Лог",
        "Clear" => "Очистить",
        "No output yet" => "Нет вывода",
        "Record New Mask" => "Запись маски",
        "Start Recording" => "Записать",
        "Stop" => "Стоп",
        "Dismiss" => "Закрыть",
        "Recording:" => "Запись:",
        "Stopping recording..." => "Остановка...",
        "Add Profile" => "Добавить профиль",
        "Edit Profile" => "Изменить профиль",
        "Name" => "Имя",
        "Connection key" => "Ключ подключения",
        "mTLS cert path (optional)" => "mTLS путь (необязательно)",
        "Save" => "Сохранить",
        "Cancel" => "Отмена",
        "Bootstrap (advanced)" => "Bootstrap (для опытных)",
        "Bootstrap CDN URL" => "CDN-адрес bootstrap",
        "Bootstrap Telegram token" => "Токен Telegram-бота bootstrap",
        "Bootstrap Telegram chat" => "Chat/канал Telegram bootstrap",
        "Bootstrap GitHub repo" => "GitHub-репозиторий bootstrap",
        "Server signing key" => "Ключ подписи сервера",
        // Admin client-management panel
        "Admin — Client Management" => "Админ — управление клиентами",
        "Refresh" => "Обновить",
        "One-time" => "Одноразовый",
        "Adding..." => "Добавление...",
        "Loading..." => "Загрузка...",
        "No clients" => "Нет клиентов",
        "enabled" => "включён",
        "disabled" => "отключён",
        "one-time" => "одноразовый",
        "Confirm revoke?" => "Подтвердить отзыв?",
        "Yes" => "Да",
        "No" => "Нет",
        "Key" => "Ключ",
        "Disable" => "Отключить",
        "Enable" => "Включить",
        "Reset device" => "Сбросить устройство",
        "Revoke" => "Отозвать",
        "Copy" => "Копировать",
        "Show QR" => "Показать QR",
        "Close" => "Закрыть",
        "Generating QR..." => "Генерация QR...",
        "Save QR" => "Сохранить QR",
        "Exit node (optional)" => "Узел выхода (необязательно)",
        "Exit" => "Выход",
        // Pool topology panel (Wave B3)
        "Pool Topology" => "Топология пула",
        "Transport" => "Транспорт",
        "Connected" => "Подключено",
        "Converged" => "Синхронизировано",
        "Partition conflict detected" => "Обнаружен конфликт разделов",
        "Subnet mismatch detected" => "Обнаружено несоответствие подсети",
        "Some peers diverged" => "Некоторые узлы рассинхронизированы",
        "No pool nodes" => "Нет узлов пула",
        "verified" => "проверен",
        "unverified" => "не проверен",
        "connected" => "подключён",
        "offline" => "офлайн",
        "revoked" => "отозван",
        "Last seen" => "Последняя активность",
        "never" => "никогда",
        // G-A1: Viewer read-only badge
        "View only" => "Только просмотр",
        // G-A2: audit-log panel
        "Audit Log" => "Журнал аудита",
        "chain verified" => "цепочка подтверждена",
        "chain BROKEN" => "ЦЕПОЧКА НАРУШЕНА",
        "No audit entries" => "Нет записей аудита",
        // C3: SSH server install wizard
        "Install Server via SSH" => "Установка сервера по SSH",
        "Use SSH key instead of password" => "Использовать SSH-ключ вместо пароля",
        "Private key path" => "Путь к приватному ключу",
        "Key passphrase (optional)" => "Пароль ключа (необязательно)",
        "SSH password" => "Пароль SSH",
        "Binary source" => "Источник бинарника",
        "Binary URL" => "URL бинарника",
        "Binary file path" => "Путь к бинарнику",
        "Browse..." => "Обзор...",
        "Server IP (optional)" => "IP сервера (необязательно)",
        "Server port (optional)" => "Порт сервера (необязательно)",
        "Bind this device (admin access)" => "Привязать это устройство (доступ администратора)",
        "Show script" => "Показать скрипт",
        "Host key fingerprint" => "Отпечаток ключа хоста",
        "Confirm this is the correct server's key" => {
            "Подтвердите, что это правильный ключ сервера"
        }
        "I trust this key" => "Я доверяю этому ключу",
        "Install" => "Установить",
        "Don't trust" => "Не доверять",
        "Connect & verify host key" => "Подключиться и проверить ключ хоста",
        "Start over" => "Начать заново",
        "Import profile" => "Импортировать профиль",
        "Install finished successfully" => "Установка успешно завершена",
        "Install failed" => "Установка не удалась",
        "Installing..." => "Установка...",
        // G-C1: auto-import confirmation
        "Imported profile" => "Профиль импортирован",
        "ready to connect (admin access)" => "готов к подключению (права администратора)",
        // G-B1: exit-node pick_list (pool.nodes source + custom host:port)
        "(default)" => "(по умолчанию)",
        "Custom..." => "Свой адрес...",
        "Exit node" => "Узел выхода",
        "applies live, no reconnect" => "применяется сразу, без переподключения",
        "global default applies on restart" => "глобальный дефолт — при перезапуске",
        // G-A3: Server Settings (Admin-only apply-with-rollback)
        "Server Settings" => "Настройки сервера",
        "Confirm" => "Подтвердить",
        "Apply" => "Применить",
        "Change applied - confirm within ~120s or it will be rolled back" => {
            "Изменение применено — подтвердите в течение ~120с, иначе оно будет отменено"
        }
        "Change was not confirmed in time and was rolled back" => {
            "Изменение не было подтверждено вовремя и было отменено"
        }
        "Time left" => "Осталось времени",
        "Active mask override" => "Активная маска клиента",
        "Select client..." => "Выберите клиента...",
        "Select mask..." => "Выберите маску...",
        "No clients loaded yet" => "Клиенты ещё не загружены",
        "No mask catalog received yet (connect once first)" => {
            "Каталог масок ещё не получен (сначала подключитесь один раз)"
        }
        "Global exit node (pool default)" => "Глобальный узел выхода (дефолт пула)",
        "Takes effect only after the server process restarts" => {
            "Вступает в силу только после перезапуска сервера"
        }
        _ => key,
    }
}
