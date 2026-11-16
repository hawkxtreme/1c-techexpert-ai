"""Common managed response shape, including admission and control failures."""
from copy import deepcopy

STATUSES=['preparing','starting','running','stopping','succeeded','partial','invalid_input','failed','cancelled','interrupted']


def schema(data=None):
    return dict(type='object',required=['schema_version','run_id','operation','status','data','snapshots','evidence','limitations','truncated'],
        properties=dict(schema_version=dict(type='integer',const=1),
            run_id=dict(anyOf=[dict(type='string',pattern='^[a-f0-9]{64}$'),dict(type='null')]),
            operation=dict(type=['string','null']),status=dict(type='string',enum=list(STATUSES)),
            data=dict(anyOf=[deepcopy(data) if data else dict(type='object'),dict(type='null')]),
            snapshots=dict(type='array'),evidence=dict(type='array'),limitations=dict(type='array'),truncated=dict(type='boolean')),
        additionalProperties=True)


def normalize(value,*,operation=None,run_id=None):
    result=dict(schema_version=1,run_id=run_id,operation=operation,data=None,snapshots=[],evidence=[],limitations=[],truncated=False)
    result.update(value)
    if result['status']=='error':result['status']='invalid_input'
    return result
