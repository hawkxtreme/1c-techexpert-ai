"""Bounded XML inspection and byte-preserving edits; never applies a configuration."""
import re
from xml.parsers import expat

from .inputs import InputError

NS='http://v8.1c.ru/v8/tech-log'
MAX_BYTES=1024**2


class XmlIssue(InputError):
    pass


def _tag_end(raw, start):
    quote=None
    for index in range(start,len(raw)):
        value=raw[index]
        if quote:
            if value==quote:quote=None
        elif value in (34,39):quote=value
        elif value==62:return index+1
    raise XmlIssue('invalid_xml')


def inspect(raw):
    if type(raw) is not bytes or len(raw)>MAX_BYTES:raise XmlIssue('xml_byte_limit')
    try:raw.decode('utf-8-sig')
    except UnicodeError as exc:raise XmlIssue('unsupported_encoding') from exc
    parser=expat.ParserCreate(namespace_separator='}')
    nodes=[];stack=[];comments=[]
    def reject(*_):raise XmlIssue('dtd_or_entity_not_supported')
    def declaration(version,encoding,standalone):
        if version!='1.0' or encoding and encoding.upper() not in ('UTF-8','UTF8'):raise XmlIssue('unsupported_encoding_or_xml_version')
    def start(name,attrs):
        if len(nodes)>=10000 or len(stack)>=32 or len(attrs)>128:raise XmlIssue('xml_structure_limit')
        at=parser.CurrentByteIndex;end=_tag_end(raw,at)
        node=dict(name=name,attrs=attrs,start=at,open_end=end,depth=len(stack),self_closing=raw[at:end].rstrip().endswith(b'/>'))
        nodes.append(node);stack.append(node)
    def end(name):
        node=stack.pop();node['close_start']=parser.CurrentByteIndex
        node['end']=node['open_end'] if node['self_closing'] else _tag_end(raw,parser.CurrentByteIndex)
    parser.XmlDeclHandler=declaration
    parser.StartDoctypeDeclHandler=reject;parser.EntityDeclHandler=reject;parser.ExternalEntityRefHandler=reject
    parser.StartElementHandler=start;parser.EndElementHandler=end
    def comment(text):
        if len(comments)>=10000:raise XmlIssue('xml_structure_limit')
        comments.append(dict(text=text,depth=len(stack),start=parser.CurrentByteIndex))
    parser.CommentHandler=comment
    try:parser.Parse(raw,True)
    except expat.ExpatError as exc:raise XmlIssue(f'invalid_xml_line_{exc.lineno}_column_{exc.offset}') from exc
    if not nodes or nodes[0]['name']!=NS+'}config':raise XmlIssue('unsupported_config_root_or_namespace')
    return dict(root=nodes[0],nodes=nodes,comments=comments)


def insert(raw, document, block):
    root=document['root']
    if root['self_closing']:
        opening=raw[root['start']:root['open_end']]
        match=re.match(rb'<([^\s/>]+)',opening)
        replacement=opening[:-2]+b'>'+block+b'</'+match[1]+b'>'
        return raw[:root['start']]+replacement+raw[root['open_end']:]
    at=root['close_start']
    return raw[:at]+block+raw[at:]


def remove_owned(raw, document, change_id, block):
    markers=[' techexpert:begin '+change_id+' ',' techexpert:end '+change_id+' ']
    found=[c for c in document['comments'] if c['text'] in markers]
    if (len(found)!=2 or [c['text'] for c in found]!=markers or any(c['depth']!=1 for c in found)
        or raw.count(block)!=1):raise XmlIssue('owned_block_changed_or_missing')
    at=raw.index(block)
    if found[0]['start']!=at+(2 if block.startswith(b'\r\n') else 1):raise XmlIssue('owned_block_changed_or_missing')
    return raw[:at]+raw[at+len(block):]
