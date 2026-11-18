---
name: sql-server
description: "Прочитать текущие запросы, ожидания, блокировки и интервальную историю Query Store через фиксированный адаптер SQL Server 2022; проверить видимость и границы вывода."
---

# Microsoft SQL Server

Для серверной ИБ возьмите узел, порт и имя БД из настроенного профиля. Файловой ИБ этот источник не требуется. `python techexpert.py doctor` показывает наличие клиента.

Используйте `sqlserver.observe` с операцией `capabilities`, `requests`, `waits`, `locks` или `query_store` в поле `query`. Обязательны `host` и `database`. Порт по умолчанию 1433. Для `auth=sql` укажите пользователя, а пароль задайте вне чата через сеансовый `SQLCMDPASSWORD`. `auth=integrated` использует текущую учётную запись и требует отдельной проверки. Проверенный сервер 16.0.4325.4, клиенты Go sqlcmd 1.10.0 и ODBC sqlcmd 18.7.

Прямой запуск для учётной записи SQL: `python techexpert.py sqlserver capabilities --host sql.example.invalid --database Orders --auth sql --user observer`. Для `query_store` добавьте `--start` и `--end` с часовым поясом. Длина окна до 31 дня. В CodeMode задайте точные `settings`, разрешённые `queries`, `max_calls` и для истории точные `windows` в `scope.sqlserver`. На Linux ODBC-клиент проверен с лимитом 256 МиБ, Go с 1 ГиБ. Сохранённый результат открывается через `artifact.show`.

Сначала прочитайте `capabilities`. Для серверных DMV требуется `VIEW SERVER PERFORMANCE STATE`, для Query Store — `VIEW DATABASE PERFORMANCE STATE`. Недоступность данных и пустая видимая выборка имеют разные статусы. Таймаут запроса 5 секунд, ожидания блокировки 500 мс. Лимит 200 текущих или 100 исторических строк. Используйте проверяемый сертификат сервера. Для тестового самоподписанного сертификата доверие задаётся явно параметром `trust_server_certificate`. [Справочник sqlcmd](https://learn.microsoft.com/en-us/sql/tools/sqlcmd/sqlcmd-utility?view=sql-server-ver16)

Текущие снимки DMV показывают активность при чтении. Идентификаторы сеансов, локальные часы и имена SQL сверяйте с данными 1С. Длительности текущих запросов и ожиданий в миллисекундах. [Текущие запросы](https://learn.microsoft.com/en-us/sql/relational-databases/system-dynamic-management-objects/sys-dm-exec-requests-transact-sql?view=sql-server-ver16)

История Query Store возвращает агрегаты целых пересекающихся интервалов, номера запросов, планов и реплик. Средние взвешены по числу выполнений. Длительности и CPU в микросекундах, first/last execution обозначают время завершения. Если нужных интервалов нет, историческое покрытие остаётся неизвестным. [Показатели Query Store](https://learn.microsoft.com/en-us/sql/relational-databases/system-catalog-views/sys-query-store-runtime-stats-transact-sql?view=sql-server-ver16)

Запускайте команды из корня проверенного пакета. Перед предложением инцидента проверьте точный предпросмотр. [Контракт CLI](../techexpert/references/local-cli.md)
