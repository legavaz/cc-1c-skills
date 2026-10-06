---
name: db-session
description: Сеансы и блокировки автономного сервера 1С через ibcmd — список сеансов, сведения о сеансе, принудительное завершение, прерывание серверного вызова, блокировки. Используй когда нужно посмотреть или снять сеансы ibsrv, снять блокировку, разобраться кто держит базу
argument-hint: "[list|info|terminate|interrupt|locks] (-ProcessId <pid> | -Remote <url>)"
allowed-tools:
  - Bash
  - Read
  - Glob
  - AskUserQuestion
---

# /db-session — Сеансы и блокировки (ibcmd)

Смотрит и обслуживает сеансы информационной базы и её блокировки через режимы `session` и `lock` утилиты `ibcmd`.

## Важное ограничение (проверено на 8.3.27.2214)

Режимы `session` и `lock` работают **только с РАБОТАЮЩИМ автономным сервером** (`ibsrv.exe`) и подключаются к нему:

| Параметр | Когда |
|---|---|
| `-ProcessId <pid>` | сервер запущен на **этой** машине (`ibsrv.exe`); навык проверяет, что процесс существует и это именно `ibsrv` |
| `-Remote <url>` | сервер на **другой** машине — сетевой адрес шлюза администрирования |

Параметры подключения к базе (`--db-path`, `--data`, `--user`, `--password`) эти режимы **не принимают**
(`Ошибка разбора параметра`) — в offline-режиме у неработающего сервера ни сеансов, ни блокировок не
существует, поэтому и спросить их нельзя. По этой же причине база передаётся не базой, а сервером.

> Для кластерных баз проекта (`localhost\GitConv`, `localhost\task`) навык **неприменим**: их сеансы
> ведёт кластер, а не `ibsrv`. Там работай через живой сеанс 1С (MCP-1С) или Конфигуратор.

## Usage

```
/db-session list     -ProcessId 1234
/db-session info     -ProcessId 1234 -Session <uuid>
/db-session locks    -ProcessId 1234
/db-session terminate -ProcessId 1234 -Session <uuid> -ErrorMessage "текст"
/db-session list     -Remote http://server:8314
```

## Параметры подключения

1. Идентификатор процесса найди сам: `Get-Process ibsrv` (или `Get-Process ibsrv,ibsrv*`), если сервер запущен на этой машине
2. `-Remote` нужен только для сервера на другой машине — адрес берётся из конфигурации автономного сервера (`http-address`/`http-port`, по умолчанию `localhost:8314`)
3. Не указано ни то, ни другое — спроси пользователя, где запущен автономный сервер; угадывать нечего
4. Путь к `ibcmd` — из `-V8Path`; если не передан, навык ищет `ibcmd.exe` рядом с `1cv8`
   (в `C:\Program Files\1cv8\<версия>\bin`, затем `C:\Program Files\1cv8\ibcmd.exe`);
   на *nix — `/opt/1cv8/<версия>/bin/ibcmd`. Если файла нет — сообщи и предложи установку

## Команда

```powershell
powershell.exe -NoProfile -File "${CLAUDE_SKILL_DIR}/scripts/db-session.ps1" <параметры>
```

### Параметры скрипта

| Параметр | Обязательный | Описание |
|----------|:------------:|----------|
| `-Command <команда>` | нет | `list` (по умолчанию) / `info` / `terminate` / `interrupt` / `locks` |
| `-ProcessId <pid>` | * | Идентификатор процесса `ibsrv.exe` на этой машине |
| `-Remote <url>` | * | Сетевой адрес шлюза администрирования автономного сервера |
| `-Session <uuid>` | для `info`/`terminate`/`interrupt` | Идентификатор сеанса; для `locks` фильтрует по сеансу |
| `-ErrorMessage <текст>` | нет | Причина завершения/прерывания; только `terminate` и `interrupt` |
| `-Licenses` | нет | Сведения о лицензиях сеанса; только `list` и `info` |
| `-V8Path <путь>` | нет | Путь к `ibcmd.exe`, каталог `bin` платформы или каталог `1cv8` — ищет `ibcmd` рядом |
| `-AdditionalIbcmdArguments <список>` | нет | Доп. аргументы `ibcmd` через запятую, в форме `--ключ=значение` |

> `*` — нужно либо `-ProcessId`, либо `-Remote`; оба сразу навык не примет (сервер либо локальный, либо удалённый)

### Команды

| Команда | Команда ibcmd | Смысл |
|---|---|---|
| `list` | `session list [--licenses]` | список активных сеансов; пустой вывод = сеансов нет |
| `info` | `session info --session=<uuid> [--licenses]` | свойства одного сеанса |
| `terminate` | `session terminate --session=<uuid> [--error-message]` | принудительное завершение сеанса |
| `interrupt` | `session interrupt-current-server-call --session=<uuid> [--error-message]` | прерывание текущего серверного вызова |
| `locks` | `lock list [--session=<uuid>]` | блокировки базы |

## Примеры

```powershell
# Кто работает с базой
powershell.exe -NoProfile -File "${CLAUDE_SKILL_DIR}/scripts/db-session.ps1" -Command list -ProcessId 528

# Кто какую лицензию держит
powershell.exe -NoProfile -File "${CLAUDE_SKILL_DIR}/scripts/db-session.ps1" -Command list -ProcessId 528 -Licenses

# Кто держит блокировку
powershell.exe -NoProfile -File "${CLAUDE_SKILL_DIR}/scripts/db-session.ps1" -Command locks -ProcessId 528

# Снять зависший сеанс с объяснением пользователю
powershell.exe -NoProfile -File "${CLAUDE_SKILL_DIR}/scripts/db-session.ps1" -Command terminate -ProcessId 528 -Session "8f2e...-..." -ErrorMessage "Работа завершена: обслуживание завершено"

# Удалённый автономный сервер
powershell.exe -NoProfile -File "${CLAUDE_SKILL_DIR}/scripts/db-session.ps1" -Command list -Remote "http://srv01:8314"
```

## Проверенные особенности платформы (8.3.27.2214)

| Особенность | Следствие |
|---|---|
| `session list` пустым выводом не падает — просто печатает ничего | навык печатает «активных сеансов нет» и возвращает `0` |
| `lock list` отдаёт записи в формате `ключ : значение` (а не таблицу, как `session list`) | два разных разбора вывода в навыке |
| У несуществующего сеанса `session info` завершается кодом `0` с пустым выводом | навык отличает это от успеха и поднимает ошибку |

## Смежное

| Задача | Навык |
|--------|-------|
| Сесансы кластерной базы (живой сеанс 1С) | MCP-1С `get_event_log`, Конфигуратор |
| Расширения в базе | `/db-cfe-admin` |
| Журнал регистрации автономного сервера | `/db-eventlog` |
| Правило 9 (клиентские сеансы — открытые и по одному) | [`AGENTS.md`](../../../AGENTS.md) |
| Возможности ibcmd целиком | [`docs/ibcmd/`](../../../docs/ibcmd/README.md) |
