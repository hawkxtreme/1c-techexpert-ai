"""Bounded read-only PostgreSQL observations; no arbitrary SQL or historical fiction."""
from datetime import datetime,timezone
import os
import re

from .artifacts import save_artifact
from .inputs import InputError,json_value
from .processes import run_bounded

SELECTS={
 'capabilities':"""SELECT current_setting('server_version') AS version,
    current_setting('server_version_num')::int AS version_num, current_user AS role,
    current_setting('transaction_read_only') AS transaction_read_only,
    current_setting('track_activities') AS track_activities,current_setting('track_counts') AS track_counts,
    current_setting('track_io_timing') AS track_io_timing,
    pg_has_role(current_user,'pg_read_all_stats','MEMBER') AS read_all_stats,
    (SELECT rolsuper FROM pg_roles WHERE rolname=current_user) AS superuser,
    to_regclass('public.pg_stat_statements') IS NOT NULL AS public_statements_view,
    pg_postmaster_start_time() AS server_started_at""",
 'activity':"""SELECT pid,datname,usename,application_name,client_addr,backend_start,xact_start,query_start,
    state,wait_event_type,wait_event,left(query,2000) AS query,
    pg_has_role(current_user,'pg_read_all_stats','MEMBER') OR usename=current_user AS full_visibility_expected
    FROM pg_stat_activity WHERE datname=current_database() ORDER BY pid LIMIT 200""",
 'locks':"""SELECT a.pid,a.backend_start,a.query_start,a.state,a.wait_event_type,a.wait_event,
    pg_blocking_pids(a.pid) AS blocking_pids,left(a.query,2000) AS query
    FROM pg_stat_activity a WHERE a.datname=current_database() AND
    (a.wait_event_type='Lock' OR cardinality(pg_blocking_pids(a.pid))>0) ORDER BY a.pid LIMIT 200""",
 'database_stats':"""SELECT datname,numbackends,xact_commit,xact_rollback,blks_read,blks_hit,
    temp_files,temp_bytes,deadlocks,blk_read_time,blk_write_time,stats_reset,
    current_setting('track_io_timing') AS current_track_io_timing
    FROM pg_stat_database WHERE datname=current_database() LIMIT 1""",
 'statements':"""SELECT s.userid,s.dbid,s.queryid,left(s.query,2000) AS query,s.calls,s.total_exec_time,
    s.mean_exec_time,s.rows,s.shared_blks_hit,s.shared_blks_read,s.temp_blks_read,s.temp_blks_written,
    (SELECT stats_reset FROM public.pg_stat_statements_info LIMIT 1) AS stats_reset
    FROM public.pg_stat_statements s WHERE s.dbid=(SELECT oid FROM pg_database WHERE datname=current_database())
    ORDER BY s.total_exec_time DESC LIMIT 100"""}


def query(operation):
    if operation not in SELECTS:raise InputError('operation is not in the PostgreSQL read-only catalogue')
    return """BEGIN READ ONLY;
SET LOCAL statement_timeout='3000ms';
SET LOCAL lock_timeout='500ms';
SET LOCAL idle_in_transaction_session_timeout='5000ms';
SET LOCAL search_path=pg_catalog;
SELECT json_build_object('captured_at',clock_timestamp(),'database',current_database(),
                         'rows',coalesce(json_agg(observed),'[]'::json)) FROM (
"""+SELECTS[operation]+"\n) observed;\nROLLBACK;\n"


class PsqlClient:
    def __init__(self,*,database='postgres',host=None,port=5432,user=None,executable='psql',docker_container=None):
        for value in (database,user):
            if value is not None and (not isinstance(value,str) or not re.fullmatch(r'[\w][\w.-]{0,127}',value)):
                raise InputError('database and role must be plain names, not connection strings')
        if host is not None and (not isinstance(host,str) or not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9_.:-]{0,252}',host)):
            raise InputError('invalid PostgreSQL host')
        if type(port) is not int or not 1<=port<=65535:raise InputError('invalid PostgreSQL port')
        if docker_container is not None and not re.fullmatch('[A-Za-z0-9][A-Za-z0-9_.-]{0,127}',docker_container):
            raise InputError('invalid Docker container')
        self.scope=dict(database=database,host=host or ('container_local_socket' if docker_container else 'libpq_default'),
                        port=port,user=user or 'libpq_default')
        self.prefix=(['docker','exec','-i','--env','PGCONNECT_TIMEOUT=5','--env','PGAPPNAME=1c-techexpert-ai',
                      docker_container,'timeout','--kill-after=2','9','/opt/pgpro/1c-16/bin/psql']
                     if docker_container else [str(executable)])
        self.options=['-X','--no-password','--quiet','--tuples-only','--no-align','--set=ON_ERROR_STOP=1','--dbname='+database]
        if host:self.options+=['--host='+host,'--port='+str(port)]
        if user:self.options+=['--username='+user]

    def execute(self,operation):
        environment=dict(os.environ,PGCONNECT_TIMEOUT='5',PGAPPNAME='1c-techexpert-ai')
        return run_bounded(self.prefix+self.options,input_data=query(operation).encode('utf-8'),timeout=13,
                           max_bytes=2*1024*1024,env=environment)


def observe(state_dir,client,operation):
    query(operation)
    started=datetime.now(timezone.utc).isoformat()
    code,data,error=client.execute(operation)
    sources=[('postgresql-response.json' if not code else 'postgresql-response.txt',data)]
    if error:sources.append(('postgresql-diagnostics.txt',error))
    cumulative=operation in ('database_stats','statements')
    result=dict(operation=operation,connection_scope=client.scope,status='unavailable' if code else 'observed',
        rows=None,started_at=started,finished_at=datetime.now(timezone.utc).isoformat(),
        temporal_scope='cumulative_not_event_history' if cumulative else 'current_snapshot_only',
        historical_window_coverage=None,requires_ai_interpretation=True,
        limits=dict(statement_timeout_ms=3000,lock_timeout_ms=500,max_rows=100 if operation=='statements' else 200),
        limitations=['Permission-limited fields can be NULL; invisible data is unknown, not zero.',
            'Current activity/locks do not reconstruct a past incident.',
            'Cumulative statistics span resets/restarts and cannot locate individual past events.',
            'Timing counters can be zero because timing was disabled; current configuration does not prove past configuration.',
            'Statements requires already enabled pg_stat_statements with public views. This adapter never enables it.',
            'Only the fixed SELECT catalogue runs in a read-only transaction; query text may contain private application data.'])
    if not code:
        response=json_value(data.decode('utf-8-sig'),reject_duplicates=True)
        if not isinstance(response,dict) or not isinstance(response.get('rows'),list) or len(response['rows'])>200:
            raise InputError('invalid PostgreSQL observation response')
        result.update(rows=response['rows'],database=response.get('database'),captured_at=response.get('captured_at'))
        result['rows_may_be_truncated']=len(response['rows'])>=result['limits']['max_rows']
    else:result['reason']='connection_permission_or_capability_error; inspect private diagnostics'
    return save_artifact(state_dir,'postgresql',dict(operation=operation,**client.scope),sources,result)
