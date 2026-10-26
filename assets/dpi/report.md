# Отчет об обучении GBDT-гейта

Гейт по окну из 24 кадров оценивает, похож ли уже отобранный внешний UDP-поток на туннель. Это приближение офлайн-вердикта nDPI. Гейт не заменяет nDPI и не показывает устойчивость к произвольному фильтру провайдера.

## Матрица захватов

Базовый каталог содержит все 10 семейств в train, val и test, по отдельной сессии. Дополнительные обычные QUIC/MASQUE и AIVPN-сессии имеют одну положительную QUIC-метку: это задача семейства протокола против Unknown, а не VPN против MASQUE. Повторы 0 и 1 допустимы в train, 2 и 3 оставлены для отдельного контроля после заморозки. Базовый генератор сохраняет длины внутренней нагрузки 8, 64, 256, 768, 1000, 4096; дополнительные сессии расширяют скорости, RTT и размеры. Контроль сессионный, семейства не исключались. Общие рецепты не доказывают перенос на произвольный трафик.

Базовые val/test уже оценивались до исправления баланса обучающей популяции. Их числа ниже являются открытой диагностикой. Финальный контроль на новых сессиях оценивается отдельно после фиксации хэша модели; эти сессии не входят в fit.

Схема признаков 2 заменяет первый байт short header 0x40..0x7f на 0x40 только при вычислении среднего и обеих энтропий. Разрешенные spin и защищенные биты не определяют эти признаки. Wire и остальные семейства не меняются. Порог 0.5 не менялся.

Базовые сессии используют проверенные кадры транспортного observer. Дополнительные сессии отбирают восходящие short-header кадры по длине, затем каждый шестнадцатый кадр. Это wire-only выборка исправных сессий, а не точное совпадение с live observer после AEAD. nDPI видит полный восходящий обмен; такое же ограничение контекста применяется к обеим реализациям.

Провод этих захватов держит начальный и минимальный MTU 1200, верх PMTUD 1380 и внутренний бюджет 1140. Кадры прошлого провода в матрицу не входят. Если manifest не передал номер зерна, в публичные файлы он не подставляется. Различие захватов проверено попарно различными хэшами PCAP и списков кадров.

Положительная метка требует QUIC или STUN с уверенностью DPI на целом PCAP, без угадывания по порту. Перед отрицательными порчами проверяется неизмененная выборка в том же standalone-контексте и с тем же числом кадров. Если она уже Unknown/VPN или не имеет DPI-уверенности, отрицательные метки не принимаются: отсутствие handshake нельзя приписывать порче. Иначе порча принимается только при вердикте Unknown или известный VPN. Остальные известные протоколы отклоняются. Производные остаются в части исходной сессии, синтетические векторы в fit не добавляются.

Порог 0.5, 120 деревьев, глубина 3, скорость 0.15 и seed 0 не менялись. Основные числа считаются по неперекрывающимся окнам с шагом 24. Окна с шагом 8 в обучение не входят и приведены отдельно.

Обучающие веса задают равную априорную важность классов, семейств внутри класса и исходных capture_id внутри семейства: w = N / (2 * K_class * C_mask_class * N_capture_mask_class). Все окна сохраняются. Порчи с одним capture_id остаются одной исходной сессией. Длинный захват не получает большую массу за число окон. Это заданная популяция поддержки, а не оценка естественной частоты трафика. Отсутствующие отрицательные группы не выдумываются.

| Часть | Маска | Профиль | Протокол маски | Учитель nDPI | Кадров | Окон |
| --- | --- | --- | --- | --- | --- | --- |
| train | Zoom | `webrtc_zoom_v3` | WebRTC_DTLS_SRTP | STUN / DPI | 118 | 4 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 117 | 4 |
| train | Telemost | `webrtc_yandex_telemost_v1` | WebRTC_DTLS_SRTP | STUN / DPI | 118 | 4 |
| train | VK Teams | `webrtc_vk_teams_v1` | WebRTC_STUN | STUN / DPI | 118 | 4 |
| train | Jazz | `webrtc_sberjazz_v1` | WebRTC_TURN_DTLS_SRTP | STUN / DPI | 118 | 4 |
| train | Salute | `sber_salute_v1` | WebRTC_STUN | STUN / DPI | 118 | 4 |
| train | WhatsApp | `whatsapp_voip_v1` | WebRTC_SDES_SRTP | STUN / DPI | 118 | 4 |
| train | Avito | `avito_api_v1` | QUIC | QUIC / DPI | 117 | 4 |
| train | Telegram | `telegram_calls_v1` | WebRTC_TURN_DTLS_SRTP | STUN / DPI | 118 | 4 |
| train | VK Video | `vk_video_v1` | QUIC | QUIC / DPI | 117 | 4 |
| val | Zoom | `webrtc_zoom_v3` | WebRTC_DTLS_SRTP | STUN / DPI | 120 | 5 |
| val | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 119 | 4 |
| val | Telemost | `webrtc_yandex_telemost_v1` | WebRTC_DTLS_SRTP | STUN / DPI | 120 | 5 |
| val | VK Teams | `webrtc_vk_teams_v1` | WebRTC_STUN | STUN / DPI | 120 | 5 |
| val | Jazz | `webrtc_sberjazz_v1` | WebRTC_TURN_DTLS_SRTP | STUN / DPI | 119 | 4 |
| val | Salute | `sber_salute_v1` | WebRTC_STUN | STUN / DPI | 120 | 5 |
| val | WhatsApp | `whatsapp_voip_v1` | WebRTC_SDES_SRTP | STUN / DPI | 120 | 5 |
| val | Avito | `avito_api_v1` | QUIC | QUIC / DPI | 119 | 4 |
| val | Telegram | `telegram_calls_v1` | WebRTC_TURN_DTLS_SRTP | STUN / DPI | 120 | 5 |
| val | VK Video | `vk_video_v1` | QUIC | QUIC / DPI | 119 | 4 |
| test | Zoom | `webrtc_zoom_v3` | WebRTC_DTLS_SRTP | STUN / DPI | 118 | 4 |
| test | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 117 | 4 |
| test | Telemost | `webrtc_yandex_telemost_v1` | WebRTC_DTLS_SRTP | STUN / DPI | 118 | 4 |
| test | VK Teams | `webrtc_vk_teams_v1` | WebRTC_STUN | STUN / DPI | 118 | 4 |
| test | Jazz | `webrtc_sberjazz_v1` | WebRTC_TURN_DTLS_SRTP | STUN / DPI | 118 | 4 |
| test | Salute | `sber_salute_v1` | WebRTC_STUN | STUN / DPI | 118 | 4 |
| test | WhatsApp | `whatsapp_voip_v1` | WebRTC_SDES_SRTP | STUN / DPI | 118 | 4 |
| test | Avito | `avito_api_v1` | QUIC | QUIC / DPI | 117 | 4 |
| test | Telegram | `telegram_calls_v1` | WebRTC_TURN_DTLS_SRTP | STUN / DPI | 118 | 4 |
| test | VK Video | `vk_video_v1` | QUIC | QUIC / DPI | 117 | 4 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 652 | 27 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 402 | 16 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 652 | 27 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 401 | 16 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1954 | 81 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1446 | 60 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1954 | 81 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1353 | 56 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 434 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 435 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 434 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 435 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 652 | 27 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 398 | 16 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 652 | 27 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 391 | 16 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1954 | 81 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1287 | 53 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1954 | 81 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1331 | 55 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 434 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 435 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 435 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 435 | 18 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |
| train | QUIC HTTPS | `quic_https_v2` | QUIC | QUIC / DPI | 1303 | 54 |

## Числа

Обучающих окон: 1632, из них туннель: 296. Проверка: 86. Контроль: 80. Окно называется туннелем, если вероятность строго больше 0.5. Константа большинства, посчитанная только по train, на контроле всегда отвечает классом цель.

| Выбор | Точность | Balanced accuracy | Точность туннеля | Полнота туннеля | F1 | Ложный туннель | Пропуск туннеля | Окон |
| --- | --- | --- | --- | --- | --- | --- | --- | --- |
| Проверка, модель | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 86 |
| Контроль, модель | 1.000 | 1.000 | 1.000 | 1.000 | 1.000 | 0.000 | 0.000 | 80 |
| Проверка, константа | 0.535 | 0.500 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | 86 |
| Контроль, константа | 0.500 | 0.500 | 0.000 | 0.000 | 0.000 | 0.000 | 1.000 | 80 |

Заранее заданный зазор к константе равен 0.050. На контроле он выполнен: balanced accuracy 1.000 против 0.500. Balanced accuracy равна полусумме полноты обоих классов; обе константы имеют 0.5 независимо от большинства. Precision, recall и FPR приведены отдельно. После этой сверки деревья и порог не менялись.

Ложный туннель на контроле: 0.000 (интервал Уилсона 0.000-0.088). Интервал считает окна независимыми. Окна не перекрываются, но каждая маска представлена одной сессией, поэтому разброс по маскам важнее ширины интервала.

Контроль по маскам. Доля у целевых окон - это ложный туннель.

| Маска | Целевых окон | Ложный туннель | Средняя p | Отрицательных окон | Поймано | Средняя p |
| --- | --- | --- | --- | --- | --- | --- |
| Zoom | 4 | 0.000 | 1.283545e-04 | 0 | нет | нет |
| QUIC HTTPS | 4 | 0.000 | 3.221475e-05 | 8 | 1.000 | 1.000 |
| Telemost | 4 | 0.000 | 3.881364e-04 | 0 | нет | нет |
| VK Teams | 4 | 0.000 | 3.004134e-05 | 8 | 1.000 | 1.000 |
| Jazz | 4 | 0.000 | 2.428767e-05 | 0 | нет | нет |
| Salute | 4 | 0.000 | 1.947764e-05 | 8 | 1.000 | 1.000 |
| WhatsApp | 4 | 0.000 | 2.750726e-04 | 0 | нет | нет |
| Avito | 4 | 0.000 | 3.605085e-05 | 8 | 1.000 | 1.000 |
| Telegram | 4 | 0.000 | 1.206514e-04 | 0 | нет | нет |
| VK Video | 4 | 0.000 | 2.260981e-05 | 8 | 1.000 | 1.000 |

Проверка val, в подгонку не входила.

| Маска | Целевых окон | Ложный туннель | Средняя p | Отрицательных окон | Поймано | Средняя p |
| --- | --- | --- | --- | --- | --- | --- |
| Zoom | 5 | 0.000 | 1.398930e-04 | 0 | нет | нет |
| QUIC HTTPS | 4 | 0.000 | 0.001 | 8 | 1.000 | 1.000 |
| Telemost | 5 | 0.000 | 3.979364e-04 | 0 | нет | нет |
| VK Teams | 5 | 0.000 | 3.179443e-05 | 8 | 1.000 | 0.997 |
| Jazz | 4 | 0.000 | 1.872083e-05 | 0 | нет | нет |
| Salute | 5 | 0.000 | 2.233752e-05 | 8 | 1.000 | 1.000 |
| WhatsApp | 5 | 0.000 | 0.018 | 0 | нет | нет |
| Avito | 4 | 0.000 | 3.493796e-05 | 8 | 1.000 | 1.000 |
| Telegram | 5 | 0.000 | 1.731888e-05 | 0 | нет | нет |
| VK Video | 4 | 0.000 | 1.950783e-05 | 8 | 1.000 | 1.000 |

Дополнительно, шаг 8, только контроль, в обучение не входил: окон 200, точность 1.000, ложный туннель 0.000, F1 1.000. Это зависимые повторы основных окон, основной вывод по ним не делается.

## Деревья

Порог узла записывается как наибольший f32, который не выше double-порога sklearn. Расхождение листа на основных окнах: 0. Наибольший зазор вероятности sklearn и встроенного обхода f32 на проверке и контроле: 7.575229e-08. Публикуемые метрики посчитаны встроенным обходом.

Две полные подгонки на одних и тех же обучающих окнах дали одинаковые узлы, смещения деревьев и начальное значение. Сравнивались результаты двух обучений, а не два рендера одного результата.

Наиболее используемые признаки:

- quic_longform_frac: 0.426
- byte0_mean: 0.276
- ent_first16: 0.257
- szfrac_1000_1400: 0.011
- sz_p90: 0.011
- byte0_msb_frac: 0.009
- sz_min: 0.005
- szfrac_100_300: 0.002

## Что отброшено

- test/telegram_calls_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/telegram_calls_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/telegram_calls_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/telegram_calls_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_sberjazz_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_sberjazz_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_sberjazz_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_sberjazz_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_yandex_telemost_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_yandex_telemost_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_yandex_telemost_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_yandex_telemost_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_zoom_v3 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_zoom_v3 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_zoom_v3 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/webrtc_zoom_v3 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/whatsapp_voip_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/whatsapp_voip_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/whatsapp_voip_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- test/whatsapp_voip_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/telegram_calls_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/telegram_calls_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/telegram_calls_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/telegram_calls_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_sberjazz_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_sberjazz_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_sberjazz_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_sberjazz_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_yandex_telemost_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_yandex_telemost_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_yandex_telemost_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_yandex_telemost_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_zoom_v3 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_zoom_v3 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_zoom_v3 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/webrtc_zoom_v3 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/whatsapp_voip_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/whatsapp_voip_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/whatsapp_voip_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- train/whatsapp_voip_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/telegram_calls_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/telegram_calls_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/telegram_calls_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/telegram_calls_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_sberjazz_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_sberjazz_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_sberjazz_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_sberjazz_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_yandex_telemost_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_yandex_telemost_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_yandex_telemost_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_yandex_telemost_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_zoom_v3 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_zoom_v3 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_zoom_v3 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/webrtc_zoom_v3 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/whatsapp_voip_v1 / broken_replay: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/whatsapp_voip_v1 / noise_same_len: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/whatsapp_voip_v1 / random_noise: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)
- val/whatsapp_voip_v1 / xor_header: Нет симметричного контроля: неизмененный standalone-контекст уже Unknown/VPN или без DPI-уверенности (учитель Unknown, уверенность Unknown)

## Воспроизведение

Python 3.14.8, scikit-learn 1.9.1, numpy 2.5.4, scipy 1.18.1, joblib 1.6.0, threadpoolctl 3.7.0. nDPI: Welcome to nDPI 5.0.0-1-375f99e. Потоки BLAS: 1. Пул учителя: 2. Seed 0.

Повтор при тех же захватах и тех же версиях должен дать ту же таблицу. Другая сборка sklearn режет деревья иначе, поэтому версии закреплены в requirements.txt.


## Финальный контроль после фиксации модели

Базовые val/test выше уже были открыты. Новые 10 сессий всех семейств и 32 отложенные сессии QUIC/MASQUE оценены после фиксации хэша модели. Ни окна, ни отрицательные производные этих сессий не участвовали в fit или подборе. Модель после оценки не менялась.

| Набор | Окон | Balanced accuracy | FPR | Полнота Unknown | Macro FPR | Macro полнота Unknown |
| --- | --- | --- | --- | --- | --- | --- |
| Все | 1623 | 1.000 | 0.000 | 1.000 | 0.000 | 1.000 |
| fresh404 | 80 | 1.000 | 0.000 | 1.000 | 0.000 | 1.000 |
| matched_aivpn | 840 | 1.000 | 0.000 | 1.000 | 0.000 | 1.000 |
| matched_masque | 703 | 1.000 | 0.000 | 1.000 | 0.000 | 1.000 |

Семейства свежего контроля отдельно. Большое число QUIC-окон не увеличивает вес других строк этой таблицы.

| Семейство | Целевых окон | FP | Отрицательных окон | Пропусков |
| --- | --- | --- | --- | --- |
| avito_api_v1 | 4 | 0 | 8 | 0 |
| quic_https_v2 | 4 | 0 | 8 | 0 |
| sber_salute_v1 | 4 | 0 | 8 | 0 |
| telegram_calls_v1 | 4 | 0 | 0 | 0 |
| vk_video_v1 | 4 | 0 | 8 | 0 |
| webrtc_sberjazz_v1 | 4 | 0 | 0 | 0 |
| webrtc_vk_teams_v1 | 4 | 0 | 8 | 0 |
| webrtc_yandex_telemost_v1 | 4 | 0 | 0 | 0 |
| webrtc_zoom_v3 | 4 | 0 | 0 | 0 |
| whatsapp_voip_v1 | 4 | 0 | 0 | 0 |

Исходные сессии финального контроля. Несколько порч одной сессии не считаются новыми независимыми захватами.

| Сессия | Целевых окон | FP | Отрицательных окон | Пропусков |
| --- | --- | --- | --- | --- |
| test/fresh404-avito_api_v1 | 4 | 0 | 8 | 0 |
| test/fresh404-quic_https_v2 | 4 | 0 | 8 | 0 |
| test/fresh404-sber_salute_v1 | 4 | 0 | 8 | 0 |
| test/fresh404-telegram_calls_v1 | 4 | 0 | 0 | 0 |
| test/fresh404-vk_video_v1 | 4 | 0 | 8 | 0 |
| test/fresh404-webrtc_sberjazz_v1 | 4 | 0 | 0 | 0 |
| test/fresh404-webrtc_vk_teams_v1 | 4 | 0 | 8 | 0 |
| test/fresh404-webrtc_yandex_telemost_v1 | 4 | 0 | 0 | 0 |
| test/fresh404-webrtc_zoom_v3 | 4 | 0 | 0 | 0 |
| test/fresh404-whatsapp_voip_v1 | 4 | 0 | 0 | 0 |
| test/matched-r2-c0-aivpn | 27 | 0 | 8 | 0 |
| test/matched-r2-c0-masque | 16 | 0 | 8 | 0 |
| test/matched-r2-c1-aivpn | 27 | 0 | 8 | 0 |
| test/matched-r2-c1-masque | 16 | 0 | 8 | 0 |
| test/matched-r2-c2-aivpn | 81 | 0 | 8 | 0 |
| test/matched-r2-c2-masque | 58 | 0 | 8 | 0 |
| test/matched-r2-c3-aivpn | 81 | 0 | 8 | 0 |
| test/matched-r2-c3-masque | 55 | 0 | 8 | 0 |
| test/matched-r2-c4-aivpn | 18 | 0 | 8 | 0 |
| test/matched-r2-c4-masque | 18 | 0 | 8 | 0 |
| test/matched-r2-c5-aivpn | 18 | 0 | 0 | 0 |
| test/matched-r2-c5-masque | 18 | 0 | 8 | 0 |
| test/matched-r2-c6-aivpn | 54 | 0 | 8 | 0 |
| test/matched-r2-c6-masque | 54 | 0 | 8 | 0 |
| test/matched-r2-c7-aivpn | 54 | 0 | 8 | 0 |
| test/matched-r2-c7-masque | 54 | 0 | 8 | 0 |
| test/matched-r3-c0-aivpn | 27 | 0 | 8 | 0 |
| test/matched-r3-c0-masque | 17 | 0 | 8 | 0 |
| test/matched-r3-c1-aivpn | 27 | 0 | 8 | 0 |
| test/matched-r3-c1-masque | 16 | 0 | 8 | 0 |
| test/matched-r3-c2-aivpn | 81 | 0 | 8 | 0 |
| test/matched-r3-c2-masque | 56 | 0 | 8 | 0 |
| test/matched-r3-c3-aivpn | 81 | 0 | 8 | 0 |
| test/matched-r3-c3-masque | 53 | 0 | 8 | 0 |
| test/matched-r3-c4-aivpn | 18 | 0 | 8 | 0 |
| test/matched-r3-c4-masque | 18 | 0 | 8 | 0 |
| test/matched-r3-c5-aivpn | 18 | 0 | 8 | 0 |
| test/matched-r3-c5-masque | 18 | 0 | 8 | 0 |
| test/matched-r3-c6-aivpn | 54 | 0 | 8 | 0 |
| test/matched-r3-c6-masque | 54 | 0 | 8 | 0 |
| test/matched-r3-c7-aivpn | 54 | 0 | 8 | 0 |
| test/matched-r3-c7-masque | 54 | 0 | 8 | 0 |

Эта проверка оценивает приближение family/Unknown-вердикта nDPI. Она не доказывает неразличимость VPN и обычного MASQUE для другого классификатора.


## Независимый WireGuard

Три новых полных захвата настоящего WireGuard не входят в обучение или настройку. Учитель подтвердил WireGuard с уверенностью DPI. Выборка фиксирована до оценки: type4 data, каждый шестнадцатый кадр, первые 120 образцов каждого захвата. По схеме признаков 2 обнаружено 15 из 15 окон. Проверены разные MTU; хэши источников и оценки сохранены отдельно от обучающей выборки.
