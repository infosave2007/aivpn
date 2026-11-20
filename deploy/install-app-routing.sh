#!/usr/bin/env bash
# Устанавливает только привилегированные компоненты split по приложениям.
set -euo pipefail
umask 077

readonly META=/var/lib/aivpn-app-routing-install
readonly STATE=/var/lib/aivpn-app-routing
readonly RUNTIME=/run/aivpn-app-routing/state
readonly SERVICE=aivpn-app-routing.service
readonly SOCKET=aivpn-app-routing.socket
readonly IMAGE=/usr/libexec/aivpn/aivpn
readonly -a DESTINATIONS=(
    /usr/libexec/aivpn/aivpn
    /usr/lib/systemd/system/aivpn-app-routing.service
    /usr/lib/systemd/system/aivpn-app-routing.socket
)
readonly -a LEGACY_DESTINATIONS=(
    /usr/bin/aivpn-routing-service
    /usr/libexec/aivpn-packet-worker
    /usr/bin/aivpn-app-control
    /usr/lib/systemd/system/aivpn-app-routing.service
    /usr/lib/systemd/system/aivpn-app-routing.socket
    /usr/libexec/aivpn-app-routing-setup
)
readonly -a SOURCES=(aivpn aivpn-app-routing.service aivpn-app-routing.socket)
readonly ACTION=${1:-}
readonly BUNDLE=${2:-$(dirname -- "$(readlink -f -- "${BASH_SOURCE[0]}")")}
AIVPN_SETUP_STAGE=

fail() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }

safe_directory() {
    local path=$1 part current= mode
    local -a parts
    [[ $path == /* ]] || fail "Нужен абсолютный путь: $path"
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        [[ -n $part ]] || continue
        [[ $part != . && $part != .. ]] || fail "Неканонический путь: $path"
        current+=/$part
        [[ ! -L $current && -d $current && $(stat -c %u -- "$current") == 0 ]] || fail "Небезопасный каталог: $current"
        mode=$(stat -c %a -- "$current")
        (( (8#$mode & 0022) == 0 )) || fail "Каталог доступен для чужой записи: $current"
    done
}

safe_file() {
    local path=$1 mode
    [[ -f $path && ! -L $path && $(stat -c %u -- "$path") == 0 && $(stat -c %h -- "$path") == 1 ]] || fail "Небезопасный файл: $path"
    mode=$(stat -c %a -- "$path")
    (( (8#$mode & 0022) == 0 )) || fail "Файл доступен для чужой записи: $path"
}

digest() { sha256sum -- "$1" | cut -d ' ' -f 1; }

cleanup_stage() {
    if [[ -n $AIVPN_SETUP_STAGE && $AIVPN_SETUP_STAGE == "$META"/stage.* ]]; then
        rm -rf -- "$AIVPN_SETUP_STAGE"
    fi
}

# Разрешены только два точных состава: прежний комплект или единый образ.
check_manifest() {
    local file=$1 line hash target index=0 current=1 legacy=1
    safe_file "$file"
    while IFS= read -r line; do
        hash=${line%% *}; target=${line#*  }
        [[ $hash =~ ^[0-9a-f]{64}$ ]] || fail "Повреждена контрольная сумма"
        [[ $index -lt ${#DESTINATIONS[@]} && $target == "${DESTINATIONS[$index]}" ]] || current=0
        [[ $index -lt ${#LEGACY_DESTINATIONS[@]} && $target == "${LEGACY_DESTINATIONS[$index]}" ]] || legacy=0
        ((index+=1))
    done < "$file"
    (( (current && index == ${#DESTINATIONS[@]}) || (legacy && index == ${#LEGACY_DESTINATIONS[@]}) )) || fail "Изменен список установленных файлов"
}

manifest_hash() {
    local file=$1 target=$2 hash path
    [[ -f $file ]] || return 0
    while read -r hash path; do [[ $path != "$target" ]] || { printf '%s' "$hash"; return; }; done < "$file"
}

verify_installed() {
    local expected pending actual target
    [[ ! -e $META/manifest ]] || check_manifest "$META/manifest"
    [[ ! -e $META/pending ]] || check_manifest "$META/pending"
    for target in "${DESTINATIONS[@]}" "${LEGACY_DESTINATIONS[@]}"; do
        [[ -e $target || -L $target ]] || continue
        safe_file "$target"
        actual=$(digest "$target")
        expected=$(manifest_hash "$META/manifest" "$target")
        pending=$(manifest_hash "$META/pending" "$target")
        # Базовая установка GUI/CLI ведет собственный точный receipt общего образа.
        if [[ $target == "$IMAGE" && -z $expected && -z $pending && -f /var/lib/aivpn-client-install/manifest ]]; then
            safe_directory /var/lib/aivpn-client-install
            safe_file /var/lib/aivpn-client-install/manifest
            expected=$(manifest_hash /var/lib/aivpn-client-install/manifest "$IMAGE")
        fi
        [[ $actual == "$expected" || $actual == "$pending" ]] || fail "Файл не принадлежит установке или был изменен: $target"
    done
}

check_private_tree() {
    local root=$1 path leaf count=0 device
    [[ -e $root || -L $root ]] || return 0
    safe_directory "$root"
    [[ $(stat -c %a -- "$root") == 700 ]] || fail "Небезопасные права состояния: $root"
    device=$(stat -c %d -- "$root")
    while IFS= read -r -d '' path; do
        ((count+=1)); ((count <= 65536)) || fail "Превышен размер журнала установки"
        [[ $(stat -c %d -- "$path") == "$device" ]] || fail "Сторонний mount в каталоге состояния: $path"
        leaf=${path##*/}
        if [[ -d $path && ! -L $path ]]; then
            [[ $leaf =~ ^[[:alnum:]_]+$ ]] || fail "Неизвестный каталог состояния: $path"
            [[ $(stat -c '%u:%a' -- "$path") == 0:700 ]] || fail "Небезопасный каталог состояния: $path"
        else
            case "$leaf" in .lock|state.json|pending.json|dns-journal.json|.new-state.json|.new-pending.json|.new-dns-journal.json) ;; *) fail "Неизвестный файл состояния сохранен: $path" ;; esac
            safe_file "$path"
            [[ $(stat -c %a -- "$path") == 600 ]] || fail "Небезопасные права состояния: $path"
        fi
    done < <(find -P "$root" -xdev -mindepth 1 -print0)
}

install_components() {
    local index source target stage
    [[ ! -e $META/removing ]] || fail "Сначала завершите прерванное удаление"
    for source in "${SOURCES[@]}"; do
        [[ -f $BUNDLE/$source && ! -L $BUNDLE/$source ]] || fail "В комплекте нет файла $source"
    done
    verify_installed
    stage=$(mktemp -d "$META/stage.XXXXXXXX")
    AIVPN_SETUP_STAGE=$stage
    for index in "${!SOURCES[@]}"; do
        install -m 600 -- "$BUNDLE/${SOURCES[$index]}" "$stage/$index"
        printf '%s  %s\n' "$(digest "$stage/$index")" "${DESTINATIONS[$index]}"
    done > "$stage/manifest"
    if [[ -e $META/pending ]]; then
        cmp -s -- "$META/pending" "$stage/manifest" || fail "Прерванную установку надо продолжить тем же комплектом"
    else
        mv -T -- "$stage/manifest" "$META/pending"
    fi
    sync -f "$META/pending"
    local -a backups=() absent=()
    for target in "${DESTINATIONS[@]}"; do
        if [[ -e $target ]]; then
            backups+=("$target")
            cp -p -- "$target" "$stage/backup-${#backups[@]}"
        else absent+=("$target"); fi
    done
    rollback_install() {
        local i target
        trap - ERR
        systemctl stop "$SERVICE" "$SOCKET" || true
        for i in "${!backups[@]}"; do
            target=${backups[$i]}
            cp -p -- "$stage/backup-$((i+1))" "${target}.rollback"
            mv -fT -- "${target}.rollback" "$target"
        done
        for target in "${absent[@]}"; do rm -f -- "$target"; done
        rm -f -- "$META/pending"
        systemctl daemon-reload
        [[ ! -f $META/manifest ]] || systemctl start "$SOCKET" "$SERVICE" || true
        fail "Установка отменена, прежние файлы восстановлены; проверьте готовность службы"
    }
    trap rollback_install ERR
    if systemctl is-active --quiet "$SERVICE" || systemctl is-active --quiet "$SOCKET"; then
        systemctl stop "$SERVICE" "$SOCKET"
    fi
    for index in "${!DESTINATIONS[@]}"; do
        target=${DESTINATIONS[$index]}
        source=$(mktemp "${target}.install.XXXXXXXX")
        install -m "$([[ $index == 0 ]] && printf 755 || printf 644)" -- "$stage/$index" "$source"
        mv -fT -- "$source" "$target"
        if command -v restorecon >/dev/null; then restorecon -F "$target"; fi
    done
    systemctl daemon-reload
    systemctl enable --now "$SOCKET" "$SERVICE"
    systemctl is-active --quiet "$SOCKET"
    systemctl is-active --quiet "$SERVICE"
    trap - ERR
    # Старые программы удаляются только после успешного запуска нового образа
    # и только если их хеши подтверждены прежним receipt.
    for target in "${LEGACY_DESTINATIONS[@]}"; do
        [[ $target != /usr/lib/systemd/system/* ]] || continue
        [[ -e $target ]] || continue
        [[ $(digest "$target") == "$(manifest_hash "$META/manifest" "$target")" ]] || fail "Старый файл изменился: $target"
        rm -- "$target"
    done
    mv -fT -- "$META/pending" "$META/manifest"
    sync -f "$META/manifest"
    printf 'Компоненты split установлены. Политики и профили сохранены.\n'
    printf 'После первой установки перезагрузите компьютер, чтобы правила наследования учитывали историю нового сеанса.\n'
}

mark_removal() {
    local phase=$1 namespace=$2 control=$3 temporary
    temporary=$(mktemp "$META/progress.XXXXXXXX")
    printf '%s %s %s\n' "$phase" "$namespace" "$control" > "$temporary"
    mv -fT -- "$temporary" "$META/removing"
    sync -f "$META/removing"
}

uninstall_components() {
    local target phase= namespace= control= extra=
    local controller=$IMAGE cleaner=$IMAGE
    local -a control_args=(app-routing) cleanup_args=(__routing-service)
    if [[ ! -e $META/manifest && ! -e $META/pending ]]; then
        for target in "${DESTINATIONS[@]}"; do
            if [[ $target == "$IMAGE" && -f /var/lib/aivpn-client-install/manifest ]]; then
                safe_file "$target"
                [[ $(digest "$target") == "$(manifest_hash /var/lib/aivpn-client-install/manifest "$target")" ]] || fail "Измененный общий образ сохранен"
            else [[ ! -e $target && ! -L $target ]] || fail "Незарегистрированный файл сохранен: $target"; fi
        done
        [[ ! -e $STATE && ! -e $RUNTIME ]] || fail "Незарегистрированное состояние сохранено"
        [[ ! -e $META/removing ]] || { safe_file "$META/removing"; rm -- "$META/removing"; }
        printf 'Компоненты split уже удалены.\n'
        return
    fi
    [[ -f $META/manifest && ! -e $META/pending ]] || fail "Нет завершенной установки; сначала восстановите комплект"
    verify_installed
    if [[ -n $(manifest_hash "$META/manifest" /usr/bin/aivpn-app-control) ]]; then
        controller=/usr/bin/aivpn-app-control; cleaner=/usr/bin/aivpn-routing-service
        control_args=(); cleanup_args=()
    fi
    if [[ -e $META/removing ]]; then
        safe_file "$META/removing"
        read -r phase namespace control extra < "$META/removing"
        [[ $phase == decommissioned || $phase == cleaned ]] || fail "Неизвестный этап удаления"
        [[ $namespace =~ ^[0-9a-f]{64}$ && $control =~ ^[0-9a-f]{64}$ && -z $extra ]] || fail "Поврежден журнал удаления"
        for target in "$STATE/state.json" "$STATE/control/state.json"; do
            [[ ! -e $target ]] || { safe_file "$target"; [[ $(digest "$target") == "$([[ $target == "$STATE/state.json" ]] && printf %s "$namespace" || printf %s "$control")" ]] || fail "Состояние изменилось после подготовки удаления"; }
        done
    else
        for target in "$controller" "$cleaner" /usr/lib/systemd/system/aivpn-app-routing.service /usr/lib/systemd/system/aivpn-app-routing.socket; do [[ -f $target ]] || fail "Для безопасного удаления восстановите файл: $target"; done
        systemctl start "$SOCKET" "$SERVICE"
        "$controller" "${control_args[@]}" decommission --all-users
        namespace=$(digest "$STATE/state.json")
        control=$(digest "$STATE/control/state.json")
        mark_removal decommissioned "$namespace" "$control"
        phase=decommissioned
    fi
    if [[ $phase == decommissioned ]]; then
        systemctl disable --now "$SOCKET" "$SERVICE"
        "$cleaner" "${cleanup_args[@]}" --cleanup
        mark_removal cleaned "$namespace" "$control"
    fi
    # Проверяем оба дерева до удаления первого файла. Чужие данные остаются на месте.
    check_private_tree "$STATE"
    check_private_tree "$RUNTIME"
    [[ ! -d $STATE ]] || find -P "$STATE" -xdev -depth -delete
    [[ ! -d $RUNTIME ]] || find -P "$RUNTIME" -xdev -depth -delete
    for target in "${DESTINATIONS[@]}" "${LEGACY_DESTINATIONS[@]}"; do
        [[ $target != "$IMAGE" ]] || continue
        [[ ! -e $target ]] || rm -- "$target"
    done
    for target in /usr/bin /usr/libexec /usr/lib/systemd/system /var/lib; do sync -f "$target"; done
    rm -- "$META/manifest"
    rm -- "$META/removing"
    systemctl daemon-reload
    printf 'Компоненты split удалены. Системный DNS восстановлен.\n'
}

[[ $EUID == 0 ]] || fail "Запустите установщик через sudo"
[[ $ACTION == install || $ACTION == uninstall ]] || fail "Использование: $0 install [каталог комплекта] | uninstall"
for tool in systemctl install stat sha256sum cut sed cmp flock find sync ip nft iptables-nft ip6tables-nft; do command -v "$tool" >/dev/null || fail "Нужна команда $tool"; done
for directory in /usr/bin /usr/lib /usr/lib/systemd/system /var/lib /run; do safe_directory "$directory"; done
if [[ ! -e /usr/libexec ]]; then install -d -m 755 /usr/libexec; fi
safe_directory /usr/libexec
if [[ ! -e /usr/libexec/aivpn ]]; then install -d -m 755 /usr/libexec/aivpn; fi
safe_directory /usr/libexec/aivpn
if [[ ! -e $META ]]; then install -d -m 700 "$META"; fi
safe_directory "$META"
[[ $(stat -c %a -- "$META") == 700 ]] || fail "Изменены права каталога установщика"
[[ ! -L $META/lock ]] || fail "Подмена блокировки установщика"
exec 9>"$META/lock"
flock -n 9 || fail "Уже работает другой установщик"
safe_file "$META/lock"
trap cleanup_stage EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
case "$ACTION" in install) install_components ;; uninstall) uninstall_components ;; esac
