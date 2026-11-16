---
name: postgresql
description: "Получить ограниченные наблюдения PostgreSQL через фиксированный read-only каталог TechExpert и оценить видимость, сбросы и покрытие периода."
---

# PostgreSQL

Проверьте профиль, имя SQL-базы и фактический psql через doctor. Пароль передаётся существующим механизмом libpq, не аргументом продукта или полем профиля.

Пример: `python techexpert.py postgresql capabilities --database ИМЯ --host УЗЕЛ --user РОЛЬ`. Затем выбирайте activity, locks, database_stats или statements. В лабораторном Docker допустим явно выбранный --docker-container с установленным /opt/pgpro/1c-16/bin/psql. Это не установка и не создание сервиса.

Результат — сохранённый artifact_id. Читайте `artifact ID` и при необходимости `artifact ID --source s1`. Не перепутайте private SQL-тексты с материалом для публичной базы знаний.

Отсутствующие поля и unavailable остаются неизвестными. statements требует уже подготовленных представлений public.pg_stat_statements; инструмент ничего не включает. [Видимость](../../knowledge/methods/postgresql-visibility.md), [история](../../knowledge/methods/postgresql-history.md). Проверен конкретный PostgreSQL для 1С 16.15; другую версию подтверждайте отдельно.

Команды запускайте из проверенного корня пакета; [общий контракт](../techexpert/references/local-cli.md) задаёт состояние и формат ошибок.
