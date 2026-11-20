# Доверенная сессия Windows-драйвера

Драйвер предоставляет LocalSystem-службе отдельное устройство `\\.\AivpnAppRouting`. Он хранит проверенную политику в пределах одной сессии. Прием политики не включает фильтры WFP, маршруты или DNS. Команды активации и передачи handle packet worker в этом интерфейсе нет.

Доступ к устройству разрешен только SYSTEM. Каждое открытие и управляющий запрос дополнительно требуют session 0, первичный SYSTEM token без ограничений и группы INTERACTIVE, отсутствие impersonation. Одна сессия принадлежит одному FILE_OBJECT и исходному EPROCESS. Копия handle в другом процессе не дает управление. Копии внутри исходного процесса сохраняют сессию до закрытия последнего handle. IRP_MJ_CLEANUP очищает политику, следующий open получает новый номер сессии.

## ABI версии 1

Поддерживается Windows x64 с little-endian представлением целых. Размеры и смещения закреплены `protocol.h`. Все IOCTL используют METHOD_BUFFERED и требуют FILE_READ_DATA вместе с FILE_WRITE_DATA. Неизвестные команды, версии, flags, reserved, лишние и недостающие байты отклоняются. QUERY, STAGE и BIND возвращают 48 байт; DIAGNOSE возвращает 264 байта.

| Команда | Вход | Результат |
| --- | --- | --- |
| QUERY, function 0x900 | Заголовок 24 байта | Номер сессии, поколение принятой политики, признак staging |
| STAGE, function 0x901 | Заголовок и ap_policy, всего 14400 байт | Политика проверена и сохранена в неактивной сессии |
| BIND, function 0x902 | Handle, slot и SID либо native path, всего 8320 байт | Привязка подтверждена данными ОС |
| DIAGNOSE, function 0x903 | Process handle и destination, всего 56 байт | Identity и диагностическое решение, 264 байта |

Заголовок содержит version, size, session, flags и reserved. QUERY допускает session=0 для первоначального получения номера; последующие запросы Rust API используют полученный номер. STAGE требует точного номера текущей сессии. Валидатор политики общий с `native/linux/kernel-policy`; Windows-драйвер вызывает его с platform=2. Номера владельцев, приложений и профилей еще не являются привязками к объектам ОС: BIND проверяет их привязку к ОС, DIAGNOSE использует ее при диагностической оценке.

Поколение политики не может уменьшаться. Повтор того же поколения с тем же содержимым успешен; другое содержимое при том же поколении отклоняется. Отказ не меняет прежнюю политику. Счетчик сессий не переполняется: после максимального значения новые открытия отклоняются до перезагрузки драйвера.

Все запросы синхронные. Отложенных IRP, packet queues, произвольных pointers, event handles, shell-команд и исполняемых payload в ABI нет. Отмена, уже установленная перед обработкой, возвращает STATUS_CANCELLED; завершенный запрос не остается в очереди отмены. Объем постоянного состояния фиксирован одной политикой на 256 правил.

`src/windows/driver.rs` открывает не наследуемый handle, принимает только KernelPolicy и проверяет ответ. StagedState описывает хранение документа. Этот тип не подтверждает состояние защиты. Поле enforcement должно быть нулевым; ненулевое значение отклоняется как несовместимый ответ.

## Сборка

Обычная cargo-сборка не собирает SYS и не требует WDK. Для отдельной сборки нужны Python 3, clang-cl, lld-link, Microsoft Windows SDK и WDK x64. Пути передаются явно:

```sh
python3 build-driver.py \
  --sdk-include /path/to/sdk/Include/version \
  --wdk-include /path/to/wdk/Include/version \
  --wdk-lib /path/to/wdk/Lib/version/km/x64 \
  --output /path/to/build-output
```

Скрипт проверяет C как kernel code с /W4 /WX и создает неподписанный `aivpn-app-routing.sys`. Подпись, установка и конфигурация устройства выполняются отдельно. Проверка в тестовом режиме Windows не подтверждает производственную подпись, SecureBoot или HVCI.

## Проверки

`tests/windows_driver.rs` запускается последовательно в настоящей Windows от LocalSystem-службы. Для проверок UAC нужны временные пользователи AivpnDriverUser и AivpnDriverAdmin, второй входит в Administrators. Общий временный пароль передается только тестовому процессу в AIVPN_CONTROL_PASSWORD; дочерние проверки его не наследуют. Тестовые аккаунты, служба и загруженный SYS удаляются после проверки стенда. Модульные проверки декодера ответа находятся в `src/windows/driver/tests.rs`.

Привилегированные integration tests помечены `#[ignore]`. На подготовленном стенде основная suite запускается с `--ignored --test-threads=1 --skip process_role_child --skip system_process_child`. Дочерние сценарии запускает сам родитель с `--ignored --exact` и обязательным окружением. В обычном `cargo test` они явно отмечены как ignored, а чистые проверки декодера выполняются.

WFP classifier, packet channel, безопасный запуск worker, fail-closed при сбоях и общий DNS требуют отдельных проверяемых частей реализации. Этот модуль не устанавливает runtime supported или ACTIVE.

## Identity и диагностический consumer

BIND связывает номер из KernelBindings с объектом ОС. Для executable служба открывает native path через GLOBALROOT с share-read/delete и без share-write. Драйвер проверяет file handle с FILE_READ_DATA | FILE_READ_ATTRIBUTES, IoFileObjectType и UserMode. Kernel handle и ссылка на FILE_OBJECT удерживают stream. Ключ приложения - одинаковые device object и ненулевой SectionObjectPointer удерживаемых FILE_OBJECT. По контракту Windows SECTION_OBJECT_POINTERS соответствует одному stream; его opaque members не читаются. FileID не является ключом приложения: разные ADS одного файла могут иметь одинаковый FileID. Hardlink прежнего stream сохраняет роль, отдельный ADS ее не получает. Вторая роль для того же stream отклоняется.

Запись в удерживаемый объект запрещена, rename/delete updater остаются доступны. Для замены открытого файла updater может использовать FileRenameInfoEx с POSIX semantics. NTFS ограничивает rename каталога с открытыми потомками; updater может сначала перенести старый файл из каталога. Для BIND требуется поддержка FileIdInformation, его значение сохраняется как диагностическая метаданная.

Привязка хранит выбранный native path. Независимый kernel-open этого пути должен подтвердить тот же stream, что переданный handle. Process callback копирует exact ImageFileName при FileOpenNameAvailable, не открывает пути и не выполняет FS queries. DIAGNOSE сравнивает сохраненное имя и проверяет текущие объекты всех привязанных путей независимо текущей policy. Отличающийся stream получает отрицательный маркер для каждого подтвержденного совпадения. Полный проход сохраняет все markers, затем отдельный проход пересекает их с выбранными текущей policy slots. Удаление и возврат отдельного правила в той же сессии не очищают наблюдения, включая факт для первоначально не выбранного binding. Старый объект и hardlink сохраняют роль, другой известный executable остается SYSTEM при соответствующем default.

Для DOS drive form вида \??\C: DIAGNOSE запрашивает полный target DOS symbolic link в сохраненном effective token контексте creator. Native имя сравнивается полностью, включая том; одинаковый относительный путь другого тома не совпадает. Неизвестные формы имени, dot-компоненты и неподтвержденные mappings дают unresolved. Имя открытия хранится отдельно от позднего OS namespace lookup: DIAGNOSE не делает произвольные смены DOS mapping атомарными. Например, mapping drive может измениться после creation и до первого запроса. Этот временной интервал требует отдельного provenance gate перед packet admission. Наличие сохраненного junction alias не означает полной приемки всех filesystem namespaces и reparse races.

Для владельца и package BIND принимает приватный token handle службы с TOKEN_QUERY. SID из запроса должен в точности совпадать с TokenUser или TokenAppContainerSid ОС. Число не назначает identity. Rust API получает номера из KernelBindings и сам извлекает SID из token. GUI этого ABI не видит. Неизвестные kind, нулевые slots, неверный тип/доступ handle, несовпавшие SID, длины, padding и reserved отклоняются. Привязки неизменны до cleanup, повтор той же привязки успешен. В сессии не больше 257 привязок. Старый STAGE сохраняет прежнюю семантику: диагностике дополнительно нужны все привязки владельца и селекторов policy.

PsSetCreateProcessNotifyRoutineEx удерживает EPROCESS, первичный token, effective token creator и FILE_OBJECT образа до возврата из create callback. Kernel handle в callback не создается. Actual creator определяется текущим EPROCESS и CreatingThreadId; подменяемый ParentProcessId не дает наследование. Плоская цепочка содержит максимум32 origins. Выход предка не меняет identity живого потомка. Переход к другому полному SID обрывает наследование, включая случай отсутствующей числовой привязки. Неизвестный creator остается unresolved.

Callback публикует immutable record в таблицу512 slots атомарно. Он не ожидает session/cache mutex, filesystem или worker. Краткий reader epoch защищает lookup и получение references. Exit атомарно удаляет exact EPROCESS record; один kernel reaper освобождает retired records и последние origin references вне callback. После удаления callback unload останавливает reaper и освобождает таблицу. Предел576 records включает512 published и64 retirement/capture slack; общий cap16960 origins включает предков и отложенное освобождение. При нехватке места процесс продолжает работу ОС, но не получает image identity из отсутствующего capture. Cleanup сессии освобождает bindings; процессный cache принадлежит времени жизни драйвера.

DIAGNOSE (function 0x903, вход 56 байт, ответ 264 байта) принимает process handle с PROCESS_QUERY_LIMITED_INFORMATION и IPv4/IPv6 destination. Он проверяет handle через PsProcessType/UserMode и использует удерживаемый EPROCESS. Ответ содержит реальные user/package SID, время создания и решение общего ap_evaluate. OS stream availability, policy image resolution и доступность FileID представлены отдельно. После cleanup image новый metadata handle может быть недоступен; FileID берется из подтвержденного same-stream BIND либо успешного OS query. При отсутствии метаданных FileID нулевой, Rust DTO file_id_available=false; это не заменяет retained stream identity. Процессы, созданные до загрузки драйвера, не восстанавливаются по строке пути: image unresolved, применимые identity rules возвращают BLOCK. VPN преобразуется в диагностический VpnNotReady/BLOCK; SYSTEM не меняет маршруты ОС. Запрос после завершения процесса отклоняется. Каждый запрос оценивается заново, это не принятый socket или сохраненный flow.

QUERY, STAGE и BIND продолжают возвращать capabilities=1, enforcement=0. DIAGNOSE не устанавливает WFP callout, не задерживает первый socket, не передает пакеты и не подтверждает ACTIVE. Следующая зависимая единица должна связать этот механизм с WFP, обеспечить pre-existing process admission, первый пакет, удержание решения принятого потока, переоценку непринятой попытки и guards при остановке BFE/драйвера/службы. Подпись, HVCI и SecureBoot остаются release gates.

Native suite `windows_identity` запускается от LocalSystem после загрузки драйвера, с `--ignored --skip identity_child --skip identity_chain_child --skip identity_crash_child --skip identity_orphan_creator --test-threads=1`. Для проверки ранее запущенного процесса runner передает AIVPN_IDENTITY_EXISTING_PID процесса, который существовал до загрузки. Контроль второго тома требует AIVPN_IDENTITY_SECOND_ROOT на отдельном собственном NTFS-томе. Проверки других SID используют те же временные аккаунты, что windows_driver. Все child functions требуют явное окружение родителя и не являются самостоятельными сценариями.
