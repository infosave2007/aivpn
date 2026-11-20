#!/usr/bin/env bash
# Базовая установка одного образа без назначения capabilities интерфейсу.
set -euo pipefail
umask 077
readonly IMAGE=/usr/libexec/aivpn/aivpn
readonly POLICY=/usr/share/polkit-1/actions/com.aivpn.client.policy
readonly META=/var/lib/aivpn-client-install
readonly ACTION=${1:-}
readonly BUNDLE=${2:-}
fail() { printf 'Ошибка: %s\n' "$*" >&2; exit 1; }
safe_directory() {
    local current= part path=$1 mode
    local -a parts
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        [[ -n $part ]] || continue
        [[ $part != . && $part != .. ]] || fail 'Неканонический системный каталог'
        current+=/$part
        if [[ ! -e $current ]]; then install -d -m 755 -o root -g root -- "$current"; fi
        [[ ! -L $current && -d $current && $(stat -c %u -- "$current") == 0 ]] || fail "Небезопасный каталог: $current"
        mode=$(stat -c %a -- "$current"); (( (8#$mode & 0022) == 0 )) || fail "Чужая запись в каталоге: $current"
    done
}
check_file() {
    local path=$1 mode
    [[ ! -L $path && -f $path && $(stat -c %u:%h -- "$path") == 0:1 ]] || fail "Небезопасный файл: $path"
    mode=$(stat -c %a -- "$path"); (( (8#$mode & 0022) == 0 )) || fail "Чужая запись в файле: $path"
}
hash() { sha256sum -- "$1" | cut -d ' ' -f 1; }
receipt_hash() {
    local hash target
    [[ -f $1 ]] || return 0
    while read -r hash target; do [[ $target != "$2" ]] || { printf '%s' "$hash"; return; }; done < "$1"
}
[[ $EUID == 0 && ( $ACTION == install || $ACTION == uninstall ) ]] || fail 'Нужны root и действие install или uninstall'
for path in /usr/libexec/aivpn /usr/share/polkit-1/actions /var/lib; do safe_directory "$path"; done
if [[ ! -e $META ]]; then install -d -m 700 "$META"; fi
safe_directory "$META"
[[ $(stat -c %a -- "$META") == 700 ]] || fail 'Чужие права receipt'
[[ ! -L $META/lock ]] || fail 'Подмена блокировки'
exec 9>"$META/lock"; flock -n 9 || fail 'Уже работает другой установщик'
check_file "$META/lock"
for receipt in "$META/manifest" "$META/pending"; do
    [[ ! -e $receipt ]] || {
        check_file "$receipt"
        mapfile -t lines < "$receipt"
        [[ ${#lines[@]} == 2 && ${lines[0]} =~ ^[0-9a-f]{64}\ \ /usr/libexec/aivpn/aivpn$ && ${lines[1]} =~ ^[0-9a-f]{64}\ \ /usr/share/polkit-1/actions/com.aivpn.client.policy$ ]] || fail 'Поврежден receipt'
    }
done
if [[ -e /var/lib/aivpn-app-routing-install/manifest ]]; then
    [[ $ACTION == install && ${AIVPN_COMPILED_ROUTING:-false} == true ]] || fail 'Сначала штатно удалите app-routing; действующая защита не понижается'
    check_file /var/lib/aivpn-app-routing-install/manifest
    [[ $(hash "$BUNDLE/aivpn") == "$(receipt_hash /var/lib/aivpn-app-routing-install/manifest "$IMAGE")" ]] || fail 'Общий образ обновляется транзакцией app-routing'
fi
for target in "$IMAGE" "$POLICY"; do
    [[ -e $target || -L $target ]] || continue
    check_file "$target"
    actual=$(hash "$target")
    expected=$(receipt_hash "$META/manifest" "$target")
    pending=$(receipt_hash "$META/pending" "$target")
    if [[ $target == "$IMAGE" && -f /var/lib/aivpn-app-routing-install/manifest ]]; then
        safe_directory /var/lib/aivpn-app-routing-install
        check_file /var/lib/aivpn-app-routing-install/manifest
        shared=$(receipt_hash /var/lib/aivpn-app-routing-install/manifest "$target")
        [[ $actual != "$shared" ]] || expected=$shared
    fi
    if [[ $target == "$POLICY" && -z $expected && -z $pending && $ACTION == install ]]; then
        [[ $actual != 59ae43ef9322f4f746b90c47da278d86739097950e026a28262fbf20e7612b12 && $actual != "$(hash "$BUNDLE/com.aivpn.client.policy")" ]] || expected=$actual
    fi
    [[ $actual == "$expected" || $actual == "$pending" ]] || fail "Незарегистрированный или измененный файл сохранен: $target"
done
if [[ $ACTION == uninstall ]]; then
    # Другие клиенты того же установленного образа должны быть закрыты заранее.
    for executable in /proc/[0-9]*/exe; do
        pid=${executable#/proc/}; pid=${pid%/exe}
        [[ $pid == "$PPID" || $pid == "${AIVPN_SETUP_CALLER:-0}" ]] && continue
        [[ ! $executable -ef $IMAGE ]] || fail 'Сначала закройте работающие клиенты AIVPN'
    done
    [[ ! -e $POLICY ]] || rm -- "$POLICY"
    [[ ! -e $IMAGE ]] || rm -- "$IMAGE"
    rm -f -- "$META/manifest" "$META/pending"
    exit 0
fi
for file in aivpn com.aivpn.client.policy; do [[ -f $BUNDLE/$file && ! -L $BUNDLE/$file ]] || fail 'Неполный внутренний комплект'; done
stage=$(mktemp -d "$META/stage.XXXXXXXX")
trap 'rm -rf -- "$stage"' EXIT
install -m 755 -o root -g root "$BUNDLE/aivpn" "$stage/image"
install -m 644 -o root -g root "$BUNDLE/com.aivpn.client.policy" "$stage/policy"
printf '%s  %s\n%s  %s\n' "$(hash "$stage/image")" "$IMAGE" "$(hash "$stage/policy")" "$POLICY" > "$stage/manifest"
if [[ -e $META/pending ]]; then cmp -s "$META/pending" "$stage/manifest" || fail 'Продолжите тем же образом'; else mv -T "$stage/manifest" "$META/pending"; fi
sync -f "$META/pending"
mv -fT -- "$stage/image" "$IMAGE"
mv -fT -- "$stage/policy" "$POLICY"
if command -v restorecon >/dev/null; then restorecon -F "$IMAGE" "$POLICY"; fi
mv -fT -- "$META/pending" "$META/manifest"
sync -f "$META/manifest"
printf 'Единый образ установлен без file capabilities.\n'
