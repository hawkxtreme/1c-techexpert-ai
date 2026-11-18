"""Finite SQL Server 2022 monitoring reads; only typed UTC literals vary."""
from datetime import datetime,timezone,timedelta
import re

from .inputs import InputError

OPERATIONS=('capabilities','requests','waits','locks','query_store')
PROFILE='sqlserver-2022-monitor-v1'


def normalize_window(value):
    if type(value) is not dict or set(value)!={'start','end'}:raise InputError('exact SQL history start/end required')
    result={}
    for key,text in value.items():
        if (type(text) is not str or not re.fullmatch(r'[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}(?:\.[0-9]{1,6})?(?:Z|[+-](?:[01][0-9]|2[0-3]):[0-5][0-9])',text)
            or text.endswith('-00:00')):raise InputError('SQL history requires known ISO zones and at most six fractional digits')
        try:result[key]=datetime.fromisoformat(text.replace('Z','+00:00')).astimezone(timezone.utc)
        except (ValueError,OverflowError):raise InputError('invalid SQL history instant') from None
    if not timedelta(0)<result['end']-result['start']<=timedelta(days=31):raise InputError('SQL history window must be positive and at most31 days')
    return {k:v.isoformat() for k,v in result.items()}


SELECTS={
 'capabilities':"SELECT 1 AS unused WHERE 1=0",
 'requests':"""SELECT TOP(200) r.session_id,s.login_time,r.request_id,r.start_time,r.status,r.command,
 r.database_id,r.blocking_session_id,r.wait_type,r.wait_time AS wait_time_ms,r.wait_resource,
 r.cpu_time AS cpu_time_ms,r.total_elapsed_time AS total_elapsed_time_ms,r.reads,r.writes,r.logical_reads,
 s.login_name,s.host_name,s.program_name,LEFT(t.text,1000) AS batch_text
 FROM sys.dm_exec_requests r LEFT JOIN sys.dm_exec_sessions s ON r.session_id=s.session_id
 OUTER APPLY sys.dm_exec_sql_text(r.sql_handle) t
 WHERE r.database_id=DB_ID() AND r.session_id<>@@SPID ORDER BY r.session_id,r.request_id""",
 'waits':"""SELECT TOP(200) w.session_id,s.login_time,w.exec_context_id,w.wait_duration_ms,w.wait_type,
 w.blocking_session_id,w.blocking_exec_context_id,w.resource_description
 FROM sys.dm_os_waiting_tasks w LEFT JOIN sys.dm_exec_sessions s ON w.session_id=s.session_id
 WHERE w.session_id<>@@SPID AND EXISTS
 (SELECT 1 FROM sys.dm_exec_requests r WHERE r.session_id=w.session_id AND r.database_id=DB_ID())
 ORDER BY w.session_id,w.exec_context_id,w.wait_duration_ms DESC""",
 'locks':"""SELECT TOP(200) l.request_session_id,s.login_time,l.resource_type,l.resource_subtype,l.resource_database_id,
 l.resource_description,l.resource_associated_entity_id,l.request_mode,l.request_type,l.request_status,
 l.request_owner_type,l.request_owner_id,l.request_owner_guid,l.request_exec_context_id
 FROM sys.dm_tran_locks l LEFT JOIN sys.dm_exec_sessions s ON l.request_session_id=s.session_id
 WHERE l.resource_database_id=DB_ID() AND l.request_session_id<>@@SPID
 ORDER BY l.request_session_id,l.resource_type,l.request_owner_id"""}


def script(operation,*,window=None):
    if operation not in OPERATIONS:raise InputError('operation is not in the SQLServer read-only catalogue')
    if operation=='query_store':
        selected=normalize_window(window)
        # Count-weight active and persisted rows. Whole intersecting intervals
        # remain aggregates; this never filters them as individual executions.
        select="""SELECT TOP(100) p.query_id,r.plan_id,r.runtime_stats_interval_id,r.execution_type,r.replica_group_id,
 MIN(i.start_time) AS interval_start,MAX(i.end_time) AS interval_end,
 SUM(CONVERT(bigint,r.count_executions)) AS count_executions,
 SUM(CONVERT(float,r.avg_duration)*r.count_executions)/NULLIF(SUM(CONVERT(bigint,r.count_executions)),0) AS avg_duration_us,
 MIN(r.min_duration) AS min_duration_us,MAX(r.max_duration) AS max_duration_us,
 SUM(CONVERT(float,r.avg_cpu_time)*r.count_executions)/NULLIF(SUM(CONVERT(bigint,r.count_executions)),0) AS avg_cpu_time_us,
 MIN(r.first_execution_time) AS first_execution_end_time,MAX(r.last_execution_time) AS last_execution_end_time,
 q.query_text_id,LEFT(t.query_sql_text,1000) AS query_text
 FROM sys.query_store_runtime_stats r JOIN sys.query_store_runtime_stats_interval i
 ON r.runtime_stats_interval_id=i.runtime_stats_interval_id
 JOIN sys.query_store_plan p ON r.plan_id=p.plan_id JOIN sys.query_store_query q ON p.query_id=q.query_id
 JOIN sys.query_store_query_text t ON q.query_text_id=t.query_text_id
 WHERE i.start_time<CONVERT(datetimeoffset(7),'"""+selected['end']+"""',127)
 AND i.end_time>CONVERT(datetimeoffset(7),'"""+selected['start']+"""',127)
 GROUP BY p.query_id,r.plan_id,r.runtime_stats_interval_id,r.execution_type,r.replica_group_id,q.query_text_id,t.query_sql_text
 ORDER BY SUM(CONVERT(float,r.avg_duration)*r.count_executions) DESC,r.plan_id,r.runtime_stats_interval_id,r.execution_type,r.replica_group_id"""
    else:
        if window is not None:raise InputError('history window applies only to query_store')
        select=SELECTS[operation]
    return """SET NOCOUNT ON;
SET LOCK_TIMEOUT 500;
SET XACT_ABORT ON;
IF CONVERT(int,SERVERPROPERTY('ProductMajorVersion'))<>16 THROW 51000,'Unsupported SQLServer major version',1;
BEGIN TRANSACTION;
DECLARE @options nvarchar(max)=NULL;
IF HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','VIEW DATABASE PERFORMANCE STATE')=1
 SET @options=(SELECT desired_state_desc,actual_state_desc,readonly_reason,current_storage_size_mb,max_storage_size_mb,
 query_capture_mode_desc,interval_length_minutes,stale_query_threshold_days
 FROM sys.database_query_store_options FOR JSON PATH,INCLUDE_NULL_VALUES,WITHOUT_ARRAY_WRAPPER);
DECLARE @metadata nvarchar(max)=(SELECT CONVERT(int,SERVERPROPERTY('ProductMajorVersion')) AS product_major_version,
 CONVERT(varchar(50),SERVERPROPERTY('ProductVersion')) AS product_version,DB_NAME() AS [database],DB_ID() AS database_id,
 CONCAT(CONVERT(varchar(33),SYSUTCDATETIME(),126),'Z') AS captured_at_utc,
 CONVERT(nvarchar(128),SERVERPROPERTY('ServerName')) AS server_name,
 CONVERT(nvarchar(128),SERVERPROPERTY('MachineName')) AS machine_name,
 CONVERT(nvarchar(128),SERVERPROPERTY('InstanceName')) AS instance_name,
 CONVERT(varchar(48),SYSDATETIMEOFFSET(),127) AS server_local_time,SUSER_SNAME() AS login_name,
 CONVERT(bit,HAS_PERMS_BY_NAME(NULL,NULL,'VIEW SERVER PERFORMANCE STATE')) AS view_server_performance_state,
 CONVERT(bit,HAS_PERMS_BY_NAME(DB_NAME(),'DATABASE','VIEW DATABASE PERFORMANCE STATE')) AS view_database_performance_state,
 JSON_QUERY(@options) AS query_store_options FOR JSON PATH,INCLUDE_NULL_VALUES,WITHOUT_ARRAY_WRAPPER);
DECLARE @rows nvarchar(max)=("""+select+""" FOR JSON PATH,INCLUDE_NULL_VALUES);
DECLARE @payload nvarchar(max)=(SELECT '"""+PROFILE+"""' AS profile,'"""+operation+"""' AS operation,
 JSON_QUERY(@metadata) AS metadata,JSON_QUERY(COALESCE(NULLIF(@rows,N''),N'[]')) AS rows FOR JSON PATH,WITHOUT_ARRAY_WRAPPER);
ROLLBACK;
IF DATALENGTH(@payload)>1048576 THROW 51001,'Observation exceeds JSON budget',1;
DECLARE @hex varchar(max)=CONVERT(varchar(max),CONVERT(varbinary(max),@payload),2),@p int=1;
SELECT CAST('TECHEXPERT_SQLSERVER_V1' AS varchar(8000));
WHILE @p<=LEN(@hex) BEGIN
 SELECT CAST(SUBSTRING(@hex,@p,8000) AS varchar(8000)); SET @p=@p+8000;
END;
SELECT CAST('TECHEXPERT_END' AS varchar(8000));
"""
