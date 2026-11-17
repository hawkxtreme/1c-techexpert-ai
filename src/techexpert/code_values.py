"""Finite JSON values used by the capability interpreter; no host objects."""
from copy import deepcopy
import json
import math

from .inputs import InputError

MAX_INT=2**63-1
MAX_VALUE_BYTES=16*1024**2
MAX_STRING=MAX_VALUE_BYTES
MAX_ITEMS=200000


class CodeError(InputError):
    def __init__(self,code,message):
        self.code=code
        super().__init__(message)


def number(value):
    if type(value) is int:
        if abs(value)>MAX_INT:raise CodeError('value_limit','Integer exceeds signed 64-bit range.')
    elif type(value) is float:
        if not math.isfinite(value) or abs(value)>1e300:raise CodeError('value_limit','Floating-point value is outside the finite profile.')
    else:raise CodeError('invalid_value','A finite number is required; unknown and boolean are not numbers.')
    return value


def scalar_size(value):
    if value is None or type(value) is bool:return len(json.dumps(value))
    if type(value) in (int,float):number(value)
    elif type(value) is str:
        if len(value)>MAX_STRING:raise CodeError('value_limit','String exceeds the program value limit.')
    else:raise CodeError('invalid_value','Only finite JSON values are available in the program.')
    try:return len(json.dumps(value,ensure_ascii=False,allow_nan=False,separators=(',',':')).encode('utf-8'))
    except UnicodeError as exc:raise CodeError('invalid_value','Invalid Unicode scalar in program data.') from exc


def bounded(value,*,max_bytes=MAX_VALUE_BYTES,max_depth=64,max_nodes=200000):
    active=set();size=0;nodes=0
    def visit(item,depth):
        nonlocal size,nodes
        nodes+=1
        if nodes>max_nodes or depth>max_depth:raise CodeError('value_limit','Program value exceeds structural limits.')
        if type(item) in (dict,list):
            if id(item) in active:raise CodeError('invalid_value','Cyclic program values are not JSON.')
            if len(item)>MAX_ITEMS:raise CodeError('value_limit','Program collection exceeds its item limit.')
            active.add(id(item));size+=2+max(0,len(item)-1)
            if type(item) is dict:
                for key,child in item.items():
                    if type(key) is not str:raise CodeError('invalid_value','Program dictionary keys must be strings.')
                    size+=scalar_size(key)+1;visit(child,depth+1)
            else:
                for child in item:visit(child,depth+1)
            active.remove(id(item))
        else:size+=scalar_size(item)
        if size>max_bytes:raise CodeError('value_limit','Program value exceeds its byte limit.')
    visit(value,0)
    return dict(bytes=size,nodes=nodes)


def copy_json(value,**limits):
    bounded(value,**limits)
    return deepcopy(value)
