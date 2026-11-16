# Изолированный лабораторный стенд

Рецепт для Linux-контейнеров Docker Desktop: сервер 1С 8.3.27.1989 и PostgreSQL для 1С 16.15. Это отдельный стенд; `init` его не создаёт. Полный серверный SC-01 на данном ПК пропущен по решению пользователя, поскольку действующая лицензия находится на другом ПК. Запущенный процесс и успешный RAC не подтверждают работу приложения.

Перед сборкой проверьте свободное место на диске Docker и входных файлов: сохраняйте не менее 10 ГиБ. Предоставьте официальный `setup-full-8.3.27.1989-x86_64.run` в отдельном каталоге и частный файл со случайным паролем PostgreSQL. В репозитории нет дистрибутивов, лицензий и паролей. `ONEC_DISTR_DIR` и `TECH_PG_PASSWORD_FILE` указывают эти пути; credential build args не используются.

Из этого каталога после задания переменных выполните:

```text
docker compose --project-name YOUR_UNIQUE_LAB config
docker compose --project-name YOUR_UNIQUE_LAB build
docker compose --project-name YOUR_UNIQUE_LAB up -d
docker compose --project-name YOUR_UNIQUE_LAB ps
docker compose --project-name YOUR_UNIQUE_LAB exec onec rac cluster list localhost:2545
docker compose --project-name YOUR_UNIQUE_LAB stop
```

Замените имя проекта своим уникальным именем. Порты публикуются только на loopback; проверьте их доступность до запуска. Учётная запись PostgreSQL `postgres` предназначена для подготовки пустой лаборатории. Для наблюдений подготовьте отдельную роль с минимальными нужными правами; действующий адаптер ничего не выдаёт сам. Подключение к базе и `CREATE EXTENSION pg_stat_statements` — отдельные действия подготовки.

Compose не активирует лицензию и не загружает прикладную конфигурацию. Windows→Docker NAT может нарушать определение принадлежности клиента и сервера одному компьютеру. Для полной проверки нужны подтверждённый способ подключения и действующее лицензирование. Не подменяйте аппаратную привязку и не меняйте глобальную сеть ради такого теста.

Тома сохраняются после stop; автоматического удаления данных и Docker prune нет. Удаление конкретного стенда требует проверки его владельца, текущего использования и нужных данных. Не используйте этот Compose в продуктивной системе без отдельной подготовки.

Исходные ориентиры: [рецепт Docker на GitHub](https://github.com/firstBitMarksistskaya/onec-docker/tree/3297e7ecd98d58bf5aefebb76b862480f4d3fe75), [Docker Fresh 1С](https://github.com/1C-Company/docker_fresh/tree/75903d11ca0bce7340e99a25a5646ae42dcb2bea), [ограничение NAT](https://github.com/1C-Company/docker_fresh/issues/7), [руководство 1С](https://1c-dn.com/library/tutorials/1c_enterprise_administrator_guide_client_server_mode_8_3_27/), [репозиторий PostgreSQL для 1С](https://repo.postgres.ru/1c/1c-16/debian/). Скрипты этого стенда используют локальный дистрибутив и не выполняют вход на портал поставщика.
