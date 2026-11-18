# SQL remediation backlog: привести SQL к существующим Rust-контрактам

**Дата аудита:** 2026-11-18\
**Репозитории:** `qembed/qembed-object-runtime` (Rust, неизменяемый
источник действующих контрактов) и `qembed/qembed-sql` (SQL,
единственная область изменений).\
**Режим работы:** только SQL. Изменения Rust-кода, Rust-миграций,
Rust-тестов и Rust Roadmap не требуются и не должны выполняться.

## 1. Обязательное правило аудита

Существующий Rust-код, его миграции, репозитории, доменные типы и
integration tests являются базовым контрактом. SQL-репозиторий
необходимо адаптировать к ним.

Это означает:

-   Не переименовывать и не менять Rust-таблицы, колонки, типы, статусы,
    поведение репозиториев и тесты.
-   Не предлагать изменения Rust как способ устранения
    SQL-несоответствий.
-   Исправлять SQL clean schema, SQL migrations, SQL constraints,
    indexes, triggers, functions, RLS policies, grants, seeds и SQL
    tests.
-   Если SQL r3 содержит функции, для которых Rust-реализации пока нет,
    их можно оставить как будущие расширения, но они не должны менять
    или блокировать уже существующие Rust-контракты.
-   Все решения ниже сформулированы как конкретные изменения SQL-части.

**Целевой результат:** чистая установка SQL-схемы и последующая работа
существующего Rust-приложения должны использовать одну физическую модель
данных и одинаковую семантику.

------------------------------------------------------------------------

## 2. Приоритеты

  -----------------------------------------------------------------------
  Приоритет                           Значение
  ----------------------------------- -----------------------------------
  P0                                  SQL в текущем виде несовместим с
                                      уже реализованным Rust или может
                                      нарушить его
                                      безопасность/корректность.
                                      Исправить до использования общей
                                      схемы.

  P1                                  Важные ограничения целостности и
                                      поведения, которые должны быть
                                      обеспечены БД. Исправить до
                                      расширения соответствующей
                                      функциональности.

  P2                                  Будущие SQL-объекты и расширения,
                                      пока не используемые текущим
                                      Rust-кодом. Не должны мешать P0/P1.
  -----------------------------------------------------------------------

## 3. AUDIT-001 --- привести физическую схему SQL к Rust migrations

**Приоритет:** P0

### Что уже ожидает Rust

Текущие Rust migrations создают и используют следующие таблицы:

-   `objects`
-   `object_versions`
-   `snapshots`
-   `events`
-   `outbox_messages`

Rust-код и SQLx-запросы ориентируются на физические имена таблиц и
колонок из этих миграций.

В SQL clean schema r3 используются альтернативные имена:

-   `qembed_objects` вместо `objects`
-   `runtime_snapshots` вместо `snapshots`
-   `object_events` вместо `events`
-   `outbox` вместо `outbox_messages`

Также в ряде таблиц различаются имена первичных ключей и ссылочных
колонок: например, Rust-контракт использует `object_id`,
`object_version_id`, `snapshot_id`, тогда как SQL r3 местами использует
обобщённый `id`.

### Что необходимо изменить в SQL-репозитории

1.  Изменить clean schema так, чтобы основные таблицы назывались ровно:
    -   `objects`
    -   `object_versions`
    -   `snapshots`
    -   `events`
    -   `outbox_messages`
2.  Привести имена колонок, PK, FK и индексов к тем, которые создают
    существующие Rust migrations.
3.  Сохранить типы колонок, nullability, default values и уникальные
    ограничения, ожидаемые текущими Rust SQLx-запросами.
4.  Переписать все SQL views, triggers, functions, policies, grants и
    seed-скрипты, которые ссылаются на прежние имена.
5.  Обновить SQL smoke/acceptance tests: тесты должны работать с именами
    и контрактами таблиц, которые реально использует Rust.
6.  Если SQL-репозиторий содержит собственную миграционную историю,
    определить её так, чтобы чистая установка приводила к совместимой
    схеме. Не требовать от пользователя применения двух несовместимых
    наборов DDL.

### Критерий готовности

На пустой PostgreSQL базе SQL clean install создаёт таблицы и колонки, с
которыми существующие Rust migrations/repositories совместимы без
единого изменения Rust.

------------------------------------------------------------------------

## 4. AUDIT-002 --- согласовать owner authentication с Rust-моделью

**Приоритет:** P0

### Что уже ожидает Rust

Rust migration `20261118000000_owner_authentication.sql` и
`qembed-store/src/auth.rs` используют:

-   `owner_principals`
-   `owner_credentials`

Rust-модель разделяет Principal и Credential. Principal представляет
владельца/субъекта, Credential --- средство аутентификации. Текущий auth
adapter выполняет pre-auth lookup до создания tenant-bound `Scope`.

SQL r3 использует другую модель и другие имена:

-   `principals`
-   `callers`
-   поля/понятия вроде `kind`, `key_hash`, `token_hash`, `caller_kind`.

Эти структуры нельзя считать взаимозаменяемыми без точного соответствия
полей и ограничений.

### Что необходимо изменить в SQL-репозитории

1.  В clean schema использовать `owner_principals` и `owner_credentials`
    как физические таблицы для текущего Rust auth path.
2.  Привести колонки, типы, PK/FK, уникальные ограничения и
    обязательность полей к Rust migration.
3.  Развести идентичность субъекта и секрет аутентификации:
    -   principal хранит идентичность владельца;
    -   credential хранит hash токена/секрета и состояние credential.
4.  Обеспечить уникальность credential lookup hash в соответствии с Rust
    lookup.
5.  Хранить только hash высокоэнтропийного API token; не хранить
    исходный токен.
6.  Согласовать поля отзыва/активности credential так, чтобы Rust мог
    однозначно исключить отозванные credentials.
7.  Обеспечить FK от credential к principal и корректное поведение при
    удалении/деактивации principal.
8.  Не требовать tenant `Scope` для первоначального поиска credential:
    auth lookup должен быть возможен до установления tenant context.
9.  Если `principals`/`callers` нужны для будущей модели, оставить их
    как отдельное расширение или представить совместимым слоем, но не
    использовать вместо таблиц текущего Rust auth path.

### Критерий готовности

Существующий Rust authentication adapter может выполнять lookup и
проверку credentials на SQL-схеме без изменения Rust-кода. Отозванный
credential не проходит аутентификацию; исходный токен в БД отсутствует.

------------------------------------------------------------------------

## 5. AUDIT-003 --- привести Object и ObjectVersion к состояниям Rust

**Приоритет:** P0

### Что уже ожидает Rust

Rust domain и Store используют состояния объекта в lowercase:

-   `draft`
-   `validating`
-   `active`
-   `suspended`
-   `archived`

Текущий Rust integration test конкурентной публикации создаёт две
Draft-версии одного объекта, после чего две операции публикации
конкурируют; ожидается ровно один победитель.

SQL r3: - использует Capitalized значения (`Draft`, `Validating`,
`Active`, `Suspended`, `Archived`) в CHECK constraint; - содержит
partial unique index, который разрешает только одну Draft-версию на
объект.

Это создаёт два прямых конфликта с существующим Rust.

### Что необходимо изменить в SQL-репозитории

1.  Изменить CHECK constraints для object state на точные lowercase
    значения, которые записывает Rust.
2.  Проверить и привести к Rust-контракту значения состояний
    `object_versions` (включая draft/published/superseded, если они
    используются соответствующей Rust migration).
3.  Удалить partial unique index, запрещающий более одной Draft-версии
    на один объект.
4.  Сохранить ограничения, необходимые для корректной публикации:
    -   опубликованная версия однозначно идентифицируется;
    -   published pointer объекта указывает на версию этого же объекта;
    -   конкурентная публикация не может дать двух победителей;
    -   переключение published pointer выполняется атомарно.
5.  Убедиться, что SQL triggers/constraints не запрещают
    последовательность операций, которую выполняет существующий
    `ObjectRepository`.
6.  Проверить соответствие типов и имён колонок `object_id`,
    `object_version_id`, `published_version_id` и связанных FK
    фактическим Rust migrations.
7.  Обновить SQL acceptance tests: две Draft-версии на одном объекте
    должны быть допустимы; конкурентная публикация должна завершаться
    ровно одним успешным результатом.

### Критерий готовности

Все состояния, которые пишет Rust, принимаются SQL. Сценарий двух
Draft-версий и конкурентной первой публикации проходит на PostgreSQL;
уникальность опубликованного результата и целостность published pointer
сохраняются.

------------------------------------------------------------------------

## 6. AUDIT-004 --- привести Snapshot persistence к Rust-контракту

**Приоритет:** P0

### Что уже ожидает Rust

Rust использует таблицу `snapshots` с основными полями:

-   `snapshot_id`
-   `canonical_json`
-   `content_hash`
-   `json_projection`

Контракт RT-039 и Rust implementation: - `canonical_json BYTEA` ---
единственный source of truth; - SHA-256 считается по точным сохранённым
байтам; - JCS/RFC 8785 canonical validation выполняется на стороне
Rust; - JSONB projection --- производное представление; - snapshot
immutable.

SQL r3 использует `runtime_snapshots` и отдельные projection-колонки
(`config`, `capabilities`, `tool_bindings`, `budget_snapshot`,
`context_config`, `policy_version`).

### Что необходимо изменить в SQL-репозитории

1.  Использовать таблицу `snapshots` и имена колонок, ожидаемые Rust
    migration.
2.  Сохранить `canonical_json` как `BYTEA`, не заменять его на
    JSON/JSONB.
3.  Сохранить `content_hash` с типом и форматом, совместимым с Rust
    SHA-256 implementation.
4.  Сохранить `json_projection` как производную JSONB projection.
5.  Не пересобирать canonical bytes из JSONB и не использовать JSONB как
    источник для hash.
6.  Если SQL guard проверяет согласованность projection/hash, он должен
    проверять именно соответствие сохранённым exact bytes и не подменять
    Rust JCS validation.
7.  Обеспечить запрет UPDATE/DELETE snapshot после создания, совместимый
    с Rust insert-only поведением.
8.  Дополнительные SQL projection-поля из r3 не должны становиться
    обязательными для текущего Rust insert path. Если они полезны для
    будущих запросов, получать их из `json_projection` или вводить как
    nullable/derived extensions.
9.  Обновить индексы и FK, используя `snapshot_id` и фактические ссылки
    из Rust.

### Критерий готовности

Существующий Rust код может вставить и прочитать snapshot с exact
canonical bytes, hash и projection. Любая попытка изменить или удалить
snapshot отклоняется БД. SQL не требует дополнительных полей, которых
текущий Rust не записывает.

------------------------------------------------------------------------

## 7. AUDIT-005 --- согласовать Events и Outbox с Rust

**Приоритет:** P0

### Что уже ожидает Rust

Rust использует:

`events`: - `tenant_id` - `event_id` - `aggregate_type` -
`aggregate_id` - `event_type` - `payload`

`outbox_messages`: - `tenant_id` - `delivery_id` - `event_id` -
`topic` - `payload`

Rust-контракт требует: - запись event и outbox в одной транзакции; -
append-only events; - типизированный allowlist event payload DTO
(RUST-025); - отсутствие произвольных payload типов; - tenant
consistency.

SQL r3 использует `object_events` и `outbox` с иной структурой, включая
`stream_type`, `stream_id`, `stream_version`, `status`, `attempts`,
`available_at`, `locked_until`, `delivered_at`.

### Что необходимо изменить в SQL-репозитории

1.  Использовать `events` и `outbox_messages` для текущего Rust
    persistence path.
2.  Привести имена и типы колонок к Rust migrations:
    -   `event_id`, `aggregate_type`, `aggregate_id`, `event_type`,
        `payload`;
    -   `delivery_id`, `event_id`, `topic`, `payload`.
3.  Сохранить FK outbox → event и tenant consistency согласно
    фактическим Rust миграциям.
4.  Обеспечить атомарную вставку event и outbox в одной транзакции; SQL
    constraints не должны требовать отдельного commit.
5.  Запретить UPDATE/DELETE для `events` на уровне БД (append-only).
6.  Не вводить обязательные `stream_version` или иные поля, которые
    текущий Rust не передаёт.
7.  Не требовать от текущего Rust заполнения дополнительных delivery
    state/lease полей, если их ещё нет в его outbox insert path. Такие
    поля можно добавлять как nullable/defaulted extension для будущего
    worker path.
8.  Проверить, что SQL не расширяет допустимые event payload так, чтобы
    обходить Rust allowlist. SQL может валидировать общую структуру, но
    источником типизированного allowlist остаётся Rust.
9.  Сохранить индексы для выборки outbox по tenant/event и доступным
    текущим полям; будущие lease indexes не должны менять текущую
    семантику.
10. Обновить SQL tests для same-transaction rollback: при rollback не
    остаётся ни event, ни outbox row.

### Критерий готовности

Rust transaction может записать event + outbox с текущим набором полей.
Rollback удаляет обе вставки; committed event неизменяем; SQL не требует
новых обязательных полей.

------------------------------------------------------------------------

## 8. AUDIT-006 --- включить RLS на реальных tenant-таблицах

**Приоритет:** P0, безопасность

### Что уже ожидает Rust

`TenantTransaction` устанавливает transaction-local PostgreSQL context
через:

`set_config('app.tenant_id', ..., true)`

SQL r3 использует аналогичный tenant context и предусматривает RLS.
Однако Rust migrations на момент аудита не включают RLS на всех реальных
application tables. Rust RLS tests проверяют поведение на временной
probe table `tenant_query_probe`, а не на каждой реальной таблице.

Важно: `TenantTransaction` только устанавливает tenant context.
Фактическую изоляцию строк обеспечивают PostgreSQL RLS policies и
privileges.

### Что необходимо изменить в SQL-репозитории

1.  Включить `ENABLE ROW LEVEL SECURITY` на всех реальных tenant-scoped
    таблицах текущего Rust path, как минимум:
    -   `objects`
    -   `object_versions`
    -   `snapshots`
    -   `events`
    -   `outbox_messages`
    -   `owner_principals`/`owner_credentials` --- только если их
        фактическая модель и access path предусматривают tenant scoping;
        pre-auth lookup нельзя сломать требованием заранее известного
        tenant.
2.  Включить `FORCE ROW LEVEL SECURITY` там, где это требуется threat
    model и роли приложения.
3.  Создать policies, которые читают
    `current_setting('app.tenant_id', true)` и безопасно обрабатывают
    отсутствующий/пустой context (доступ не разрешать).
4.  Для каждой таблицы определить корректные USING и WITH CHECK условия
    для SELECT/INSERT/UPDATE/DELETE.
5.  Проверить, что tenant_id нельзя подменить через INSERT/UPDATE в
    обход установленного контекста.
6.  Разделить миграционную/owner роль и runtime application role.
    Runtime role не должна быть superuser, table owner или иметь
    BYPASSRLS.
7.  Убедиться, что grants не дают обхода RLS через SECURITY DEFINER
    functions с чрезмерными правами.
8.  Привести policies к реальным таблицам и реальным колонкам Rust
    schema, а не только к SQL r3 альтернативным таблицам.
9.  Добавить SQL integration/acceptance tests на реальных таблицах:
    -   без tenant context запрос не видит/не меняет tenant rows;
    -   tenant A не читает/не меняет строки tenant B;
    -   INSERT с чужим tenant_id отклоняется;
    -   UPDATE, меняющий tenant_id, отклоняется;
    -   проверены SELECT, INSERT, UPDATE и DELETE;
    -   тесты выполняются под runtime role, не являющейся
        owner/BYPASSRLS.
10. Проверить поведение после commit и rollback при повторном
    использовании одного pooled connection: transaction-local context не
    должен протекать.

### Критерий готовности

RLS включён на фактических tenant-таблицах. Проверки выполняются под
реальной runtime role и доказывают отсутствие cross-tenant доступа на
`objects`, `object_versions`, `snapshots`, `events` и `outbox_messages`.

------------------------------------------------------------------------

## 9. AUDIT-007 --- перенести необходимые ObjectVersion invariants в DB guards

**Приоритет:** P1

### Что уже ожидает Rust

Rust Domain и Store проверяют допустимые переходы состояний и выполняют
публикацию транзакционно, с блокировкой строки и проверкой ожидаемого
published pointer. SQL r3 содержит более полный набор DB guards:

-   запрет редактирования/удаления опубликованной версии;
-   разрешённый переход `published → superseded`;
-   уникальность опубликованной версии;
-   deferred constraint trigger для published pointer.

В Rust migrations часть ограничений уже есть, но не весь набор SQL r3.

### Что необходимо изменить в SQL-репозитории

1.  Сопоставить каждый SQL guard с уже существующими Rust переходами
    состояний.
2.  Добавить DB-level запрет изменения содержимого опубликованной
    версии.
3.  Разрешить только согласованные переходы published → superseded, если
    именно это соответствует фактическому Rust lifecycle.
4.  Не вводить запрет нескольких Draft-версий (см. AUDIT-003).
5.  Добавить/сохранить уникальность активной опубликованной версии в
    форме, совместимой с Rust publication transaction.
6.  Проверять, что published pointer объекта указывает на
    `object_versions` с тем же `object_id`.
7.  Если проверка требует deferred constraint trigger, реализовать её
    как DEFERRABLE/INITIALLY DEFERRED, чтобы корректная
    последовательность SQL statements внутри одной транзакции могла
    завершиться.
8.  Запретить физическое удаление version rows, если это требуется
    текущим lifecycle/ссылочной целостностью.
9.  Проверить прямые SQL UPDATE/DELETE попытки, минуя Rust Domain.

### Критерий готовности

БД самостоятельно защищает неизменяемость опубликованных версий и
целостность published pointer, но не блокирует разрешённые Rust операции
и не запрещает несколько Draft-версий.

------------------------------------------------------------------------

## 10. AUDIT-008 --- обеспечить tenant consistency через composite foreign keys

**Приоритет:** P1

### Что уже ожидает Rust

В Rust migrations уже присутствуют некоторые composite FK. SQL r3
использует tenant-composite references шире. RUST-027 добавляет проверки
RLS и composite FK на существующей схеме, но этот backlog не требует
менять Rust.

### Что необходимо изменить в SQL-репозитории

1.  Провести инвентаризацию всех tenant-owned таблиц и связей между
    ними.
2.  Для каждой связи tenant-owned row → tenant-owned parent обеспечить
    FK, включающий `tenant_id`, а не только глобальный UUID.
3.  Добавить необходимые UNIQUE constraints на родительские пары
    `(tenant_id, id)`, чтобы composite FK был валиден.
4.  Проверить как минимум связи:
    -   `object_versions` → `objects`;
    -   `snapshots` → соответствующий tenant/object aggregate, если
        такая связь предусмотрена текущей моделью;
    -   `events` → aggregate/object, где применимо;
    -   `outbox_messages` → `events`;
    -   остальные уже существующие tenant-owned relations в clean
        schema.
5.  Согласовать имена колонок с Rust migrations; не вводить новые
    обязательные колонки, которые Rust не передаёт.
6.  Определить ON DELETE/ON UPDATE поведение с учётом append-only и
    retention требований.
7.  Добавить негативные SQL tests: попытка связать row tenant A с parent
    tenant B должна завершаться FK violation.
8.  Проверить INSERT и UPDATE пути, включая изменение tenant_id.

### Критерий готовности

Невозможно создать межтенантную ссылку даже при ошибке в application
code или прямом SQL запросе.

------------------------------------------------------------------------

## 11. AUDIT-009 --- подготовить SQL persistence для invocation/tool execution leases и fencing

**Приоритет:** P1, перед реализацией соответствующих worker adapters

### Что уже определено в Rust-контрактах

RT-040 определяет независимые leases и fencing для Invocation и
ToolExecution. Rust domain уже содержит Invocation optimistic versioning
и fencing token. `Unknown` не является автоматически retryable
состоянием: сначала требуется reconciliation.

Полные persistence adapters для worker/tool execution на момент аудита
ещё не завершены.

### Что необходимо изменить/подготовить в SQL-репозитории

1.  Не менять существующие Rust Invocation контракты ради SQL r3.
2.  Для будущей invocation persistence предусмотреть поля/ограничения,
    совместимые с Rust optimistic versioning и fencing token.
3.  Для ToolExecution предусмотреть отдельные lease owner, lease expiry
    и fencing token; не переиспользовать invocation lease.
4.  Обеспечить монотонность fencing token при каждом новом захвате
    lease.
5.  Устаревший worker с меньшим fencing token не должен иметь
    возможности завершить/перезаписать работу нового владельца lease.
6.  Определить допустимые state transitions и terminal states на уровне
    DB guards.
7.  Состояние `Unknown` не должно автоматически переходить в retry;
    предусмотреть reconciliation path.
8.  Добавить индексы для поиска истёкших leases и reconciliation
    candidates.
9.  Использовать CAS/expected version в UPDATE predicates; не полагаться
    на то, что PostgreSQL сам угадает ожидаемую версию клиента.
10. Не делать новые поля обязательными для текущего Rust insert/update
    path до появления соответствующего adapter. Для будущих
    таблиц/колонок подготовить отдельный SQL change set.

### Критерий готовности

SQL модель позволяет реализовать независимые leases и fencing без гонок
и без возможности stale worker перезаписать результат. Текущий Rust path
не ломается до подключения будущих adapters.

------------------------------------------------------------------------

## 12. AUDIT-010 --- оставить будущие SQL-модули совместимыми, но не навязывать их текущему Rust

**Приоритет:** P2

### Что уже есть в SQL r3

SQL r3 содержит дополнительные области, которые текущий Rust runtime ещё
не реализовал полностью:

-   knowledge и vector retrieval;
-   memory;
-   tool bindings;
-   policy decisions;
-   encrypted command payloads;
-   tool executions;
-   budgets/reservations;
-   tasks/checkpoints.

Эти структуры могут оставаться целевой моделью для будущих этапов, но не
должны нарушать существующие Rust migrations и SQLx queries.

### Что необходимо сделать в SQL-репозитории

1.  Сохранить дополнительные модули как отдельные
    SQL-компоненты/миграции, не переименовывая и не заменяя базовые
    таблицы Rust.
2.  Не добавлять NOT NULL колонки без DEFAULT в таблицы текущего Rust
    path, если текущие Rust INSERT их не передают.
3.  Для будущих обязательных полей использовать отдельную миграцию в
    момент подключения соответствующего Rust adapter.
4.  Сохранить RT-041 binding counter и монотонный `binding_version`;
    физическое удаление binding не должно нарушать историю.
5.  Сохранить RT-043 envelope encryption, hash verification и TTL для
    encrypted command payloads; не хранить raw command payload в
    logs/events/API.
6.  Сохранить RT-044 модель Verified memory как новую Owner-authored row
    с `supersedes_id`, а не UPDATE candidate row в Verified.
7.  Сохранить RT-045 retention правило: обычная retention purge не
    удаляет append-only events, decisions и snapshots.
8.  Оставить tenant offboarding/erasure отдельным privileged audited
    workflow (RT-046), не смешивая его с обычным retention purge.
9.  Для vector retrieval соблюдать фильтрацию knowledge revision до
    vector top-k; использовать корректную метрику и расстояние (`-dist`,
    `1-dist` только для cosine).
10. Для HNSW partial indexes учитывать требования migrator и выполнять
    `CREATE INDEX CONCURRENTLY` вне транзакции.
11. Для budget/reservation и task/checkpoint таблиц заранее определить
    tenant FKs, state transitions, uniqueness и retention.
12. Не объявлять эти модули обязательными зависимостями текущих Rust
    migrations, пока Rust Roadmap не дошёл до соответствующей
    функциональности.

### Критерий готовности

Будущие SQL-модули сохранены как расширения и могут развиваться
независимо. Их наличие не мешает clean install и работе текущего Rust
runtime.

------------------------------------------------------------------------

## 13. Общие проверки после исправления P0

После AUDIT-001...AUDIT-006 выполнить единый SQL acceptance pass:

1.  Создать пустую PostgreSQL базу на поддерживаемой версии.
2.  Применить только документированный SQL clean install path.
3.  Проверить, что физические таблицы и колонки совпадают с Rust
    migrations.
4.  Запустить SQL smoke tests.
5.  Проверить owner authentication lookup и revoked credential.
6.  Проверить object lifecycle с lowercase state values.
7.  Создать две Draft-версии одного объекта.
8.  Выполнить конкурентную публикацию двух версий: должен победить ровно
    один writer.
9.  Вставить snapshot с canonical bytes, hash и JSON projection;
    проверить immutability.
10. В одной транзакции вставить event и outbox; затем отдельно проверить
    rollback.
11. Проверить append-only запрет для events.
12. Выполнить RLS matrix на реальных таблицах под runtime role.
13. Проверить composite FK против cross-tenant references.
14. Проверить, что pooled connection не сохраняет tenant context после
    commit/rollback.
15. Сверить, что SQL schema не требует от текущего Rust дополнительных
    обязательных полей или новых состояний.

## 14. Что не входит в эту работу

-   Изменения Rust-кода, Rust migrations или Rust tests.
-   Пересмотр Rust Roadmap.
-   Изменение доменных контрактов, чтобы подогнать их под SQL r3.
-   Внедрение будущих worker/tool/knowledge/task adapters.
-   Production deployment, эксплуатационные процедуры и legal policy,
    кроме SQL-ограничений, прямо перечисленных в backlog.

## 15. Порядок выполнения

Рекомендуемый порядок:

1.  **AUDIT-001** --- физическая совместимость схемы и миграционной
    линии.
2.  **AUDIT-002** --- owner authentication.
3.  **AUDIT-003** --- object/version states и Draft concurrency.
4.  **AUDIT-004** --- snapshots.
5.  **AUDIT-005** --- events/outbox.
6.  **AUDIT-006** --- RLS на реальных таблицах.
7.  **AUDIT-007** --- DB guards для ObjectVersion.
8.  **AUDIT-008** --- composite tenant FKs.
9.  **AUDIT-009** --- invocation/tool leases и fencing.
10. **AUDIT-010** --- будущие SQL-модули и совместимость.

**Важно:** пункты 1--6 --- блокирующие для согласованной работы текущего
Rust runtime. Пункты 7--8 усиливают DB-level invariants и tenant
integrity. Пункты 9--10 относятся к подготовке и расширению будущей
функциональности.

------------------------------------------------------------------------

## 16. Источники аудита

-   Rust repository: https://github.com/qembed/qembed-object-runtime
-   SQL repository: https://github.com/qembed/qembed-sql
-   SQL README:
    https://github.com/qembed/qembed-sql/blob/master/README.md
-   SQL ADR RT-039...RT-047:
    https://github.com/qembed/qembed-sql/blob/master/ADR_RT-039_to_RT-047.md
-   SQL finalization addendum:
    https://github.com/qembed/qembed-sql/blob/master/Qembed_M0_v2_3_3_Finalization_Addendum.md
-   SQL clean schema:
    https://github.com/qembed/qembed-sql/blob/master/qembed_m0_v2_3_3_clean_schema.sql

Этот документ фиксирует результаты read-only аудита на указанную дату.
Перед реализацией конкретного AUDIT-ID сверяй его с актуальным
состоянием SQL-репозитория, но не меняй Rust-контракты.


------------------------------------------------------------------------

## F-06 — Principal-to-Caller delegation (approved architecture extension)

**Status:** SQL-011 implementation proposed in branch sql-011-principal-caller-delegation; PostgreSQL smoke validation pending.

This is an explicitly approved feature extension, not a remediation of an existing Rust mismatch. The current Rust owner-authentication contract remains unchanged in the SQL PR.

- Keep owner_principals as the authenticated Principal and callers as the invocation Caller; never infer a mapping from UUID equality.
- Add tenant-scoped principal_caller_delegations with composite FKs, one active grant per Principal/Caller pair, immutable grant history, final revocation, and auditable revoker.
- Support explicit selection of all existing Caller kinds: Anonymous, Authenticated, and Service. A Principal can delegate to multiple Callers; delegation is direct and non-transitive.
- Runtime can read mappings but cannot write them directly. SECURITY DEFINER grant/revoke/resolution functions validate trusted app.tenant_id and app.principal_id context. Client DTOs never provide those values.
- Invocation-time resolution must re-check that Principal and Caller remain active. The begin-invocation transaction must call resolve_delegated_caller(uuid), which locks the active delegation plus Principal and Caller lifecycle rows FOR SHARE until commit; revocation updates the delegation row, serializing the race.
- Rust follow-up must add trusted Principal transaction context and the resolver/lock before RUST-036 can safely persist object_invocations.caller_id and caller-scoped idempotency.

Do not mark SQL-011 validated until a clean PostgreSQL 16 + pgvector 0.8.0 install and the full smoke suite, including test 07 and the extended SECURITY DEFINER privilege checks, have actually run.
