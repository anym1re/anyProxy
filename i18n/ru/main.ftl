# Отказы при построении доменных типов.
error-name = имя: от 1 до { $max } символов a-z, 0-9, подчёркивание или дефис
error-domain = домен: имя хоста в нижнем регистре, например example.com
error-color = цвет: шестнадцатеричная тройка в нижнем регистре, например #1a2b3c
error-text-too-long = текст: не более { $max } символов
error-quota = квота должна быть больше нуля
error-timestamp = отметка времени по RFC 3339, например 2026-12-31T23:59:59Z
error-stealth-without-domain = маскированной ноде нужен домен
error-open-with-domain = нода без маскировки не может иметь домен
error-masking-not-offered = маскировка предлагается только для mtproto
error-ad-tag = спонсорский тег — тридцать два шестнадцатеричных знака
error-max-devices = ограничение по устройствам: от 1 до 1000
error-access-revoked = отозванный доступ не возобновляется
error-surface-mismatch = ожидался доступ типа { $expected }, получен { $actual }
error-secret-form = секрет: ровно 32 шестнадцатеричных символа
error-credential-form = имя учётной записи: от 1 до 64 символов
error-sealed-value = зашифрованное значение не удалось открыть
error-key-file-unreadable = файл ключа не читается
error-key-file-permissions = файл ключа не должен быть доступен группе и остальным
error-key-file-length = файл ключа должен содержать ровно 32 байта
error-link-host = для ссылки нужен адрес узла
error-stored-value = сохранённое значение не соответствует ни одному варианту
error-password-hash = у администратора должен быть пароль

# Почему доступ не обслуживается.
reason-client-suspended = клиент приостановлен
reason-client-archived = клиент в архиве
reason-access-disabled = доступ отключён
reason-access-revoked = доступ отозван
reason-expired = срок истёк
reason-client-quota-exhausted = клиент исчерпал общий объём
reason-access-quota-exhausted = это подключение исчерпало свой объём

access-count =
    { $count ->
        [one] { $count } подключение
        [few] { $count } подключения
       *[other] { $count } подключений
    }

# Вывод командной строки.
cli-client-created = клиент { $label } создан
cli-client-not-found = клиента { $label } нет
cli-node-not-found = ноды { $label } нет
cli-tag-not-found = тега { $label } нет
cli-access-not-found = доступа с таким идентификатором нет
cli-node-created = нода { $label } зарегистрирована
cli-node-renamed = нода { $node } переименована; выданные ссылки называют прежнее имя
cli-node-sponsored = нода { $node }: спонсорство задано; движок перезапустится с ним
cli-tag-created = тег { $name } создан
cli-access-created = доступ создан на ноде { $node }
cli-access-updated = доступ изменён
cli-accesses-revoked = отозвано: { $count }
cli-nothing-found = показывать нечего
cli-field-label = метка
cli-field-state = состояние
cli-field-quota = объём
cli-field-expires = истекает
cli-field-created = создан
cli-field-kind = тип
cli-field-domain = домен
cli-field-method = метод
cli-field-node = нода
cli-field-tag = тег
cli-value-none = нет
cli-link-confirm = вывод ссылки раскрывает секрет; для продолжения укажите --yes
cli-method-not-served = нода типа { $kind } не обслуживает { $method }

# Отказ панели, сказанный на языке оператора, а не панели: по проводу идёт
# код, предложение собирается здесь.
api-unauthenticated = вход не выполнен; выполните: anyproxy login
api-invalid-credentials = неверный логин, пароль или код
api-forbidden = ваша роль этого не разрешает
api-not-found = не найдено
api-too-many-requests = слишком много попыток; подождите и повторите
api-acknowledgement-required = печать ссылки раскрывает секрет; добавьте --yes
api-method-not-served = нода не обслуживает этот метод
api-node-without-domain = скрытной ноде нужен домен
api-access-not-on-this-node = этот доступ принадлежит другой ноде
api-host-required = для ссылки нужен адрес
api-already-enrolled = эта нода уже зарегистрирована
api-unknown = панель отклонила запрос ({ $code })

cli-signed-in = вход выполнен: { $login }
cli-signed-out = выход выполнен
cli-login-prompt = логин:
cli-password-prompt = пароль:
cli-totp-prompt = код:
cli-password-not-an-argument = пароль читается с терминала, а не из аргумента
cli-panel-required = задайте ANYPROXY_PANEL или передайте --panel
cli-enrollment-code = код регистрации (показывается один раз): { $code }
cli-enrollment-fingerprint = отпечаток панели: { $fingerprint }
cli-enrollment-command = выполните на ноде: { $command }
