"""Standalone standard-library OS probe; safe to run locally or send over SSH/WinRM.

It installs nothing, changes no counters/services, and always stops at a budget.
"""
import argparse
import ctypes
from datetime import datetime,timezone
import json
import math
import os
from pathlib import Path
import platform
import re
import socket
import time


def plan(duration_seconds=300,interval_seconds=1,max_bytes=8*1024*1024):
    for name,value in (('duration_seconds',duration_seconds),('interval_seconds',interval_seconds)):
        if type(value) not in (int,float) or not math.isfinite(value) or value<=0:raise ValueError(name+' must be finite and positive')
    if not 1<=interval_seconds<=60:raise ValueError('interval must be 1..60 seconds for the supported profiles')
    if not interval_seconds<=duration_seconds<=1800:raise ValueError('duration must be at least one interval and at most 1800 seconds')
    if type(max_bytes) is not int or not 16384<=max_bytes<=8*1024*1024:raise ValueError('max_bytes must be 16384..8388608')
    return dict(duration_seconds=duration_seconds,interval_seconds=interval_seconds,max_bytes=max_bytes)


def metric(name,instance,value,unit,status='known',**extra):
    if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or value<0):
        value=None;status='invalid_counter'
    return dict(metric=name,instance=instance,value=value,unit=unit,status=status if value is not None else (status if status!='known' else 'unavailable'),**extra)


def linux_snapshot():
    result=dict(monotonic=time.monotonic(),boot_id=None,cpu=None,memory_available_bytes=None,disks={},network={},errors=[])
    def text(path):
        try:
            with open(path,encoding='ascii') as stream:data=stream.read(1024*1024+1)
            if len(data)>1024*1024:raise ValueError('counter byte limit')
            return data
        except (OSError,UnicodeError,ValueError) as error:
            result['errors'].append(dict(source=path,error=type(error).__name__));return ''
    result['boot_id']=text('/proc/sys/kernel/random/boot_id').strip() or None
    for line in text('/proc/stat').splitlines():
        if line.startswith('cpu '):result['cpu']=[int(x) for x in line.split()[1:]]
    for line in text('/proc/meminfo').splitlines():
        if line.startswith('MemAvailable:'):result['memory_available_bytes']=int(line.split()[1])*1024
    for line in text('/proc/diskstats').splitlines():
        parts=line.split()
        if len(parts)<14 or parts[2].startswith(('loop','ram')):continue
        result['disks'][parts[2]]=dict(device=parts[0]+':'+parts[1],counters=[int(x) for x in parts[3:]],
                                       partition=Path('/sys/class/block',parts[2],'partition').exists())
        if len(result['disks'])>128:raise ValueError('more than 128 disk objects; narrow the node scope')
    for line in text('/proc/net/dev').splitlines():
        name,separator,data=line.partition(':')
        if separator:
            values=data.split()
            if len(values)>=16:result['network'][name.strip()]=[int(values[0]),int(values[8])]
    return result


def linux_metrics(previous,current):
    elapsed=current['monotonic']-previous['monotonic'] if previous else None
    comparable=bool(previous and previous.get('boot_id') and previous['boot_id']==current.get('boot_id') and elapsed>0)
    status='warmup' if previous is None else 'reset_or_missing_previous'
    values=[];busy=None
    a=previous.get('cpu') if previous else None;b=current.get('cpu')
    if comparable and a and b and len(a)>=8 and len(b)>=8:
        delta=[y-x for x,y in zip(a[:8],b[:8])]
        if all(v>=0 for v in delta) and sum(delta)>0:busy=100*(1-(delta[3]+delta[4])/sum(delta))
    values.append(metric('cpu.busy_percent','all',busy,'percent',status if busy is None else 'known'))
    values.append(metric('memory.available','all',current.get('memory_available_bytes'),'bytes'))
    for name,disk in current['disks'].items():
        c=disk['counters'];prior=previous['disks'].get(name) if previous else None
        d=None
        if comparable and prior and prior['device']==disk['device'] and len(prior['counters'])>=11 and len(c)>=11:
            diff=[y-x for x,y in zip(prior['counters'],c)]
            if all(diff[i]>=0 for i in (0,2,3,4,6,7,9,10)):d=diff
        extra=dict(partition=disk.get('partition'),device=disk['device'])
        observations=[('avg_queue',d[10]/(elapsed*1000) if d else None,'requests'),
            ('read_iops',d[0]/elapsed if d else None,'operations/second'),
            ('write_iops',d[4]/elapsed if d else None,'operations/second'),
            ('read_bytes_per_second',d[2]*512/elapsed if d else None,'bytes/second'),
            ('write_bytes_per_second',d[6]*512/elapsed if d else None,'bytes/second'),
            ('read_latency',d[3]/d[0]/1000 if d and d[0] else None,'seconds'),
            ('write_latency',d[7]/d[4]/1000 if d and d[4] else None,'seconds')]
        for suffix,value,unit in observations:
            state='known' if value is not None else 'no_completed_io' if d and suffix.endswith('latency') else status
            values.append(metric('disk.'+suffix,name,value,unit,state,**extra))
        values.append(metric('disk.inflight',name,c[8] if len(c)>=9 else None,'requests',**extra))
    for name,raw in current['network'].items():
        prior=previous['network'].get(name) if previous else None
        for i,direction in enumerate(('rx','tx')):
            value=(raw[i]-prior[i])/elapsed if comparable and prior and raw[i]>=prior[i] else None
            values.append(metric('network.'+direction+'_bytes_per_second',name,value,'bytes/second','known' if value is not None else status))
    return values


class WindowsPdh:
    """English counter names translated by PDH; unavailable objects stay unknown."""
    def __init__(self):
        from ctypes import wintypes as w
        self.w=w;self.dll=ctypes.WinDLL('pdh');self.query=w.HANDLE();self.counters=[];self.errors=[]
        signatures={
            'PdhOpenQueryW':([w.LPCWSTR,ctypes.c_size_t,ctypes.POINTER(w.HANDLE)],w.LONG),
            'PdhAddEnglishCounterW':([w.HANDLE,w.LPCWSTR,ctypes.c_size_t,ctypes.POINTER(w.HANDLE)],w.LONG),
            'PdhAddCounterW':([w.HANDLE,w.LPCWSTR,ctypes.c_size_t,ctypes.POINTER(w.HANDLE)],w.LONG),
            'PdhGetCounterInfoW':([w.HANDLE,w.BOOL,ctypes.POINTER(w.DWORD),ctypes.c_void_p],w.LONG),
            'PdhExpandWildCardPathW':([w.LPCWSTR,w.LPCWSTR,w.LPWSTR,ctypes.POINTER(w.DWORD),w.DWORD],w.LONG),
            'PdhRemoveCounter':([w.HANDLE],w.LONG),'PdhCollectQueryData':([w.HANDLE],w.LONG),
            'PdhCloseQuery':([w.HANDLE],w.LONG),
            'PdhGetFormattedCounterValue':([w.HANDLE,w.DWORD,ctypes.POINTER(w.DWORD),ctypes.c_void_p],w.LONG)}
        for name,(args,returns) in signatures.items():
            fn=getattr(self.dll,name);fn.argtypes=args;fn.restype=returns
        status=self.dll.PdhOpenQueryW(None,0,ctypes.byref(self.query))
        if status:raise OSError('PdhOpenQuery failed: '+hex(status&0xffffffff))
        class Info(ctypes.Structure):
            _fields_=[(k,w.DWORD) for k in ('length','type','version','status')]+[('scale',w.LONG),('default_scale',w.LONG),
                       ('user',ctypes.c_size_t),('query_user',ctypes.c_size_t),('full_path',w.LPWSTR)]
        disk=[('Avg. Disk Queue Length','disk.avg_queue','requests'),('Current Disk Queue Length','disk.inflight','requests'),
              ('Avg. Disk sec/Read','disk.read_latency','seconds'),('Avg. Disk sec/Write','disk.write_latency','seconds'),
              ('Disk Reads/sec','disk.read_iops','operations/second'),('Disk Writes/sec','disk.write_iops','operations/second'),
              ('Disk Read Bytes/sec','disk.read_bytes_per_second','bytes/second'),('Disk Write Bytes/sec','disk.write_bytes_per_second','bytes/second')]
        specs=[('\\PhysicalDisk(*)\\'+suffix,name,unit) for suffix,name,unit in disk]+[
            ('\\Processor(_Total)\\% Processor Time','cpu.busy_percent','percent'),
            ('\\Memory\\Available Bytes','memory.available','bytes'),
            ('\\Network Interface(*)\\Bytes Received/sec','network.rx_bytes_per_second','bytes/second'),
            ('\\Network Interface(*)\\Bytes Sent/sec','network.tx_bytes_per_second','bytes/second')]
        for prototype,name,unit in specs:
            handle=w.HANDLE();status=self.dll.PdhAddEnglishCounterW(self.query,prototype,0,ctypes.byref(handle))
            if status:
                self.errors.append(dict(counter=prototype,status=hex(status&0xffffffff)));continue
            if '*' not in prototype:
                self.counters.append((handle,name,'all',unit,prototype));continue
            size=w.DWORD();self.dll.PdhGetCounterInfoW(handle,False,ctypes.byref(size),None)
            if not 0<size.value<=1024*1024:raise OSError('PDH counter info size invalid')
            buffer=ctypes.create_string_buffer(size.value)
            status=self.dll.PdhGetCounterInfoW(handle,False,ctypes.byref(size),buffer)
            localized=ctypes.cast(buffer,ctypes.POINTER(Info)).contents.full_path if not status else None
            self.dll.PdhRemoveCounter(handle)
            if not localized:
                self.errors.append(dict(counter=prototype,status='localization_failed'));continue
            length=w.DWORD();self.dll.PdhExpandWildCardPathW(None,localized,None,ctypes.byref(length),0)
            if not 0<length.value<=100000:raise OSError('PDH instance expansion limit')
            paths=ctypes.create_unicode_buffer(length.value)
            status=self.dll.PdhExpandWildCardPathW(None,localized,paths,ctypes.byref(length),0)
            if status:
                self.errors.append(dict(counter=prototype,status=hex(status&0xffffffff)));continue
            for path in paths[:length.value].split('\0'):
                if not path:continue
                instance=re.search(r'\((.*)\)\\',path)
                instance=instance[1] if instance else 'unknown'
                if instance=='_Total':continue
                handle=w.HANDLE();status=self.dll.PdhAddCounterW(self.query,path,0,ctypes.byref(handle))
                if not status:self.counters.append((handle,name,instance,unit,path))
                else:self.errors.append(dict(counter=path,status=hex(status&0xffffffff)))
                if len(self.counters)>512:raise ValueError('PDH counter budget exceeded')

    def sample(self,warmup=False):
        w=self.w
        class Value(ctypes.Structure):_fields_=[('status',w.DWORD),('value',ctypes.c_double)]
        collected=self.dll.PdhCollectQueryData(self.query);result=[]
        for handle,name,instance,unit,path in self.counters:
            value=Value();status=self.dll.PdhGetFormattedCounterValue(handle,0x200,None,ctypes.byref(value))
            known=not collected and not status and value.status in (0,1) and not warmup
            result.append(metric(name,instance,value.value if known else None,unit,
                'known' if known else 'warmup' if warmup else 'counter_unavailable',counter_path=path,
                native_status=hex((status or value.status or collected)&0xffffffff)))
        return result

    def close(self):self.dll.PdhCloseQuery(self.query)


def collect(duration_seconds=300,interval_seconds=1,*,node=None,role='onec',max_bytes=8*1024*1024,should_stop=None):
    settings=plan(duration_seconds,interval_seconds,max_bytes)
    if role not in ('onec','sql','storage','client','terminal','web','other'):raise ValueError('unsupported node role')
    if node is not None and (not isinstance(node,str) or not 1<=len(node)<=256 or any(ord(c)<32 for c in node)):raise ValueError('invalid node label')
    windows=os.name=='nt'
    if not windows and platform.system()!='Linux':raise ValueError('only Windows and Linux collectors are available')
    report=dict(schema_version=1,profile='os-metrics-v1',node=node or socket.gethostname(),role=role,
        scope='windows_host' if windows else 'linux_kernel_and_current_network_namespace',
        observed_hostname=socket.gethostname(),platform=platform.platform(),python=platform.python_version(),container=Path('/.dockerenv').exists() if not windows else False,
        plan=settings,started_at=datetime.now(timezone.utc).isoformat(),samples=[],status='running',limitations=[])
    if report['container']:report['limitations'].append('Kernel disk/CPU counters belong to the Linux VM/host; network counters belong to this container namespace. They do not measure the Windows physical disk directly.')
    provider=WindowsPdh() if windows else None
    started=time.monotonic();previous=None;used=0;index=0
    try:
        while True:
            stop=should_stop() if should_stop is not None else None
            if stop:report['status']=stop;break
            elapsed=time.monotonic()-started
            if index and elapsed>duration_seconds+interval_seconds*.5:break
            if windows:
                row=dict(elapsed_seconds=elapsed,metrics=provider.sample(warmup=index==0))
            else:
                current=linux_snapshot()
                row=dict(elapsed_seconds=elapsed,metrics=linux_metrics(previous,current),raw=current)
                previous=current
            row['timestamp']=datetime.now(timezone.utc).isoformat()
            # ASCII wire JSON also survives legacy Windows PowerShell encodings.
            size=len(json.dumps(row,ensure_ascii=True,allow_nan=False).encode('ascii'))+2
            if used+size>max_bytes-8192:report['status']='byte_limit';break
            report['samples'].append(row);used+=size;index+=1
            if elapsed>=duration_seconds:break
            next_sample=index*interval_seconds
            remaining=max(0,min(duration_seconds,next_sample)-(time.monotonic()-started))
            if should_stop is None:time.sleep(remaining)
            else:
                finish=time.monotonic()+remaining
                while time.monotonic()<finish and not should_stop():time.sleep(min(.1,max(0,finish-time.monotonic())))
        if report['status']=='running':report['status']='completed'
    except KeyboardInterrupt:report['status']='cancelled'
    finally:
        if provider:
            report['counter_errors']=provider.errors;provider.close()
    report['finished_at']=datetime.now(timezone.utc).isoformat()
    report['actual_duration_seconds']=time.monotonic()-started
    return report


def summarize(document):
    if not isinstance(document,dict) or document.get('schema_version')!=1 or document.get('profile')!='os-metrics-v1':raise ValueError('unsupported OS measurements profile')
    settings=document.get('plan',{});settings=plan(**settings)
    rows=document.get('samples');expected=math.floor(settings['duration_seconds']/settings['interval_seconds'])+1
    if not isinstance(rows,list) or len(rows)>1801:raise ValueError('invalid OS sample count')
    groups={};slots=set();last=-1
    for row in rows:
        elapsed=row.get('elapsed_seconds')
        if type(elapsed) not in (int,float) or not math.isfinite(elapsed) or elapsed<0 or elapsed<=last:raise ValueError('OS sample times must increase')
        if elapsed>settings['duration_seconds']+settings['interval_seconds']:raise ValueError('OS sample exceeds plan window')
        last=elapsed;slots.add(round(elapsed/settings['interval_seconds']))
        metrics=row.get('metrics')
        if not isinstance(metrics,list) or len(metrics)>1024:raise ValueError('invalid OS metrics count')
        seen=set()
        for item in metrics:
            key=(item.get('metric'),item.get('instance'),item.get('unit'))
            if any(not isinstance(x,str) or not 1<=len(x)<=2048 for x in key) or key in seen:raise ValueError('invalid or duplicate OS metric')
            seen.add(key);value=item.get('value')
            if value is not None and (type(value) not in (int,float) or not math.isfinite(value) or value<0):raise ValueError('invalid OS metric value')
            if value is not None and item.get('status')!='known':raise ValueError('known numeric value must have known status')
            entry=groups.setdefault(key,dict(metric=key[0],instance=key[1],unit=key[2],values=[],unknown=0))
            if value is None:entry['unknown']+=1
            else:entry['values'].append(value)
    result=[]
    for key,entry in sorted(groups.items()):
        values=entry.pop('values');entry.update(known=len(values),missing_object_samples=len(rows)-len(values)-entry['unknown'],
            minimum=min(values) if values else None,maximum=max(values) if values else None,
            sample_mean=sum(values)/len(values) if values else None)
        result.append(entry)
    missing=max(0,expected-len({slot for slot in slots if 0<=slot<expected}))
    return dict(node=document.get('node'),observed_hostname=document.get('observed_hostname'),role=document.get('role'),scope=document.get('scope'),platform=document.get('platform'),
        started_at=document.get('started_at'),finished_at=document.get('finished_at'),plan=settings,
        expected_samples=expected,observed_samples=len(rows),missing_samples=missing,
        coverage_status='complete' if not missing and document.get('status')=='completed' else 'incomplete',
        collection_status=document.get('status'),metrics=result,counter_errors=document.get('counter_errors',[]),
        historical_incident_explained=False,limitations=document.get('limitations',[])+[
            'Zero queue or no matching sample does not exclude an incident outside this collection window.',
            'Missing/unavailable counters and resets are unknown. Devices/partitions are not added together.',
            'A high queue alone does not establish a bottleneck; compare latency, throughput and workload.'])


if __name__=='__main__':
    parser=argparse.ArgumentParser(description='Bounded Windows/Linux OS collector')
    parser.add_argument('--duration',type=float,default=300)
    parser.add_argument('--interval',type=float,default=1)
    parser.add_argument('--node')
    parser.add_argument('--role',default='onec')
    parser.add_argument('--max-bytes',type=int,default=8388608)
    args=parser.parse_args()
    print(json.dumps(collect(args.duration,args.interval,node=args.node,role=args.role,max_bytes=args.max_bytes),ensure_ascii=True,allow_nan=False))
