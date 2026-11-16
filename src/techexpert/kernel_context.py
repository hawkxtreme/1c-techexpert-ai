"""Process-local managed boundary context, never a model/session resource policy."""
import os
import time

from . import operation_state as fs

_ACTIVE=None


def install(value):
    global _ACTIVE
    _ACTIVE=value


def current():return _ACTIVE


def stop(context=None):
    context=_ACTIVE if context is None else context
    if not context:return None
    if time.monotonic()>=context['deadline']:return 'timeout'
    if fs.inspect_process(context['parent'])['state'] in ('not_running','different_lifetime'):return 'timeout'
    return None


def attach(value):
    if not _ACTIVE:return value
    return dict(value,kernel_call_id=_ACTIVE['call_id'],kernel_limits=dict(memory_bytes=_ACTIVE['limits']['memory_bytes'],
        memory_scope='controller and descendant Windows Jobs' if os.name=='nt' else 'per-process inherited address space; aggregate tree memory unknown',
        time_scope='admission, engine/replay and finalization; transport I/O separately bounded by size',
        model_harness_resources='unknown and outside this boundary'))
