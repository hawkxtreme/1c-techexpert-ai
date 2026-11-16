#!/bin/sh
set -eu
if [ ! -s "$PGDATA/PG_VERSION" ]; then
    initdb -D "$PGDATA" --encoding=UTF8 --locale=ru_RU.UTF-8 --auth-local=trust --auth-host=scram-sha-256 --pwfile=/run/secrets/pgpass
    printf '\nhost all all 0.0.0.0/0 scram-sha-256\n' >> "$PGDATA/pg_hba.conf"
fi
exec postgres -D "$PGDATA" -c listen_addresses='*' -c shared_buffers=256MB -c max_connections=30 -c shared_preload_libraries=pg_stat_statements -c track_io_timing=on
