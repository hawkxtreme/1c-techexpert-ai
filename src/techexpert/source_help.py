"""Bundled preparation instructions; loading help never contacts its references."""
from pathlib import Path
from urllib.parse import urlsplit
from .inputs import InputError,json_value,read_snapshot

def catalogue():
    result=json_value(read_snapshot(Path(__file__).parent/'assets/source-help.json',128*1024).decode('utf-8'),reject_duplicates=True)
    if result.get('schema_version')!=1 or set(result.get('sources',{}))!={'tj','jr','source','sql','rac','os'}:raise InputError('unsupported source-help catalogue')
    for item in result['sources'].values():
        for key in ('purpose','expected_format','example','rights','agent_actions','long_observation','excluded_inputs'):
            if not isinstance(item.get(key),str) or not 1<=len(item[key])<=8192:raise InputError('incomplete source help')
        for key in ('windows_steps','linux_steps'):
            if not isinstance(item.get(key),list) or not 1<=len(item[key])<=10 or any(not isinstance(x,str) or not 1<=len(x)<=8192 for x in item[key]):raise InputError('incomplete preparation steps')
        for link in item.get('links',[]):
            url=urlsplit(link['url'])
            if url.scheme!='https' or not url.hostname or url.username or url.password:raise InputError('invalid source-help reference')
    return result

def source_help(kind):
    result=catalogue()
    if kind not in result['sources']:raise InputError('unknown source help type')
    return dict(schema_version=1,revision=result['revision'],type=kind,**result['sources'][kind])
