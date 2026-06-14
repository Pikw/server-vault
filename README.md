# Server Vault

Маленькая локальная система для базы серверов, отчётов и защищённого хранения секретов.

## Что внутри

- `server_vault.py` - CLI без внешних Python-зависимостей.
- `data/servers.db` - SQLite-база с метаданными серверов, отчётами и событиями.
- `data/secrets/*.json.enc` - зашифрованные секреты по серверам.
- `data/reports/<server_id>/...` - исходные отчёты и артефакты.
- `data/exports/*.json` - sanitized-экспорты для других агентов.
- `data/archives/*.tar.gz.enc` - зашифрованные архивы всего vault.

Пароль шифрования не хранится. При записи/чтении секретов и создании архива CLI спросит passphrase.

## Быстрый старт

```bash
cd server-vault
python3 server_vault.py init
python3 server_vault.py add-server --id example-vps --host 203.0.113.10 --user admin --port 22 --tags ubuntu,vps --note "Example Ubuntu VM"
python3 server_vault.py import-report example-vps ./example-report.md
python3 server_vault.py list
python3 server_vault.py show example-vps
```

## Секреты

Записать секрет:

```bash
python3 server_vault.py put-secret example-vps --key ssh_password
```

Прочитать секрет:

```bash
python3 server_vault.py get-secret example-vps --key ssh_password
```

Секреты лежат отдельно от SQLite и шифруются командой:

```text
openssl enc -aes-256-cbc -pbkdf2 -iter 600000 -salt
```

## Экспорт знаний агенту

Экспорт без секретов:

```bash
python3 server_vault.py export-agent example-vps
```

Будет создан JSON в `data/exports/`. Его можно передавать другому агенту: там есть адрес, пользователь, порт, теги, заметки, ссылки на отчёты, но нет паролей.

## Архивирование

Создать зашифрованный архив всего vault:

```bash
python3 server_vault.py archive
```

Архив попадёт в `data/archives/`. Его можно переносить или хранить отдельно.

## Рекомендуемый workflow

1. Добавить сервер в реестр.
2. Сложить пароль/ключ в encrypted secrets.
3. Агент подключается к серверу, собирает отчёт.
4. Отчёт импортируется в vault.
5. Для другого агента делается sanitized `export-agent`.
6. Периодически делается encrypted `archive`.

## Модель безопасности

Что защищено:

- значения паролей, токенов и ключей;
- архивы vault;
- агентские экспорты не содержат секретов.

Что не скрывается:

- IP/hostname;
- логин пользователя;
- порт SSH;
- теги и заметки;
- факт наличия секрета с конкретным ключом, например `ssh_password`.

Для более серьёзной продакшен-схемы можно заменить passphrase-шифрование на `age`/GPG/Hashicorp Vault/1Password CLI, но эта версия специально сделана маленькой и переносимой.
