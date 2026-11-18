"""Bundled preparation instructions; loading help never contacts its references."""
from pathlib import Path
from urllib.parse import urlsplit
from .inputs import InputError,json_value,read_snapshot

def catalogue(*,root=None):
    path=Path(root)/'src/techexpert/assets/source-help.json' if root is not None else Path(__file__).parent/'assets/source-help.json'
    result=json_value(read_snapshot(path,128*1024).decode('utf-8'),reject_duplicates=True)
    if result.get('schema_version')!=1 or set(result.get('sources',{}))!={'tj','jr','source','sql','rac','os'}:raise InputError('unsupported source-help catalogue')
    for item in result['sources'].values():
        if 'export_help' in item:
            helper=item['export_help']
            if not isinstance(helper,dict) or set(helper)!={'title','request_in_chat','steps','scope'}:raise InputError('invalid source export help')
            if any(not isinstance(helper[key],str) or not helper[key] or len(helper[key])>2048 for key in ('title','request_in_chat','scope')):raise InputError('invalid source export help text')
            if not isinstance(helper['steps'],list) or not 1<=len(helper['steps'])<=10 or any(not isinstance(x,str) or not x or len(x)>2048 for x in helper['steps']):raise InputError('invalid source export help steps')
        for key in ('purpose','expected_format','example','rights','agent_actions','long_observation','excluded_inputs'):
            if not isinstance(item.get(key),str) or not 1<=len(item[key])<=8192:raise InputError('incomplete source help')
        for key in ('sftp_expected_format','sftp_example'):
            if key in item and (not isinstance(item[key],str) or not 1<=len(item[key])<=8192):raise InputError('invalid SFTP preparation help')
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
