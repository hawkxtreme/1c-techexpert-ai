"""Portable stdlib MCP smoke and fixed read-only QA preparation, not an LLM study."""
import argparse
import hashlib
import json
from pathlib import Path
import queue
import subprocess
import sys
import threading
import uuid
import xml.etree.ElementTree as ET

ROOT=Path(__file__).resolve().parents[1]
sys.path.insert(0,str(ROOT))
from src.techexpert import __version__,operation_state as fs
from src.techexpert.mcp_tools import MODERN,LEGACY


def run(state,version=MODERN):
    state=fs.private(state);private=fs.private(state/'mcp-smoke'/uuid.uuid4().hex)
    sequence=0;replies=queue.Queue(maxsize=2);observations=[];wire_bytes=0
    errors=(private/'stderr.log').open('wb')
    process=subprocess.Popen([sys.executable,'-X','utf8',str(ROOT/'techexpert.py'),'--state-dir',str(state),'mcp-stdio','--profile','direct'],
        cwd=ROOT,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=errors)
    def reader():
        while True:
            line=process.stdout.readline(64*1024**2+1)
            replies.put(line)
            if not line:return
    thread=threading.Thread(target=reader,daemon=True);thread.start()
    def rpc(method,params):
        nonlocal sequence,wire_bytes
        sequence+=1;params=dict(params)
        if version==MODERN:params['_meta']={'io.modelcontextprotocol/protocolVersion':MODERN,'io.modelcontextprotocol/clientCapabilities':{}}
        raw=json.dumps(dict(jsonrpc='2.0',id=sequence,method=method,params=params),ensure_ascii=False,separators=(',',':')).encode()+b'\n'
        process.stdin.write(raw);process.stdin.flush();wire_bytes+=len(raw)
        line=replies.get(timeout=40);wire_bytes+=len(line)
        if not line or len(line)>64*1024**2 or line.count(b'\n')!=1:raise ValueError('Invalid bounded MCP response')
        reply=json.loads(line)
        if reply.get('id')!=sequence or 'error' in reply:raise ValueError('MCP request failed: '+str(reply.get('error')))
        return reply['result']
    prefix='mcp-smoke-'+uuid.uuid4().hex
    def call(operation,**arguments):
        frame=rpc('tools/call',dict(name='techexpert_'+operation.replace('.','_'),arguments=dict(
            operation_key=prefix+'-'+str(sequence),executor_id='portable-mcp-smoke',arguments=arguments)))
        value=frame['structuredContent']
        if frame.get('isError') or value['status']!='succeeded' or json.loads(frame['content'][0]['text'])!=value:
            raise ValueError('MCP fixture operation did not succeed: '+str(value.get('message',value['status'])))
        observations.append(dict(operation=operation,run_id=value['run_id'],kernel_call_id=value['kernel_call_id']))
        return value['data']
    try:
        if version==LEGACY:
            init=rpc('initialize',dict(protocolVersion=LEGACY,capabilities={},clientInfo=dict(name='portable-smoke',version=__version__)))
            if init['protocolVersion']!=LEGACY:raise ValueError('Unexpected legacy protocol')
            notification=b'{"jsonrpc":"2.0","method":"notifications/initialized","params":{}}\n'
            process.stdin.write(notification);process.stdin.flush();wire_bytes+=len(notification)
        else:rpc('server/discover',{})
        catalogue=rpc('tools/list',{})
        if len(catalogue['tools'])!=44:raise ValueError('Unexpected finite tool catalogue')
        before=call('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/baseline.json'))
        after=call('case.analyze',manifest=str(ROOT/'tests/fixtures/order-load/cached.json'))
        b=before['case_id'];a=after['case_id']
        before=call('case.show',case_id=b);after=call('case.show',case_id=a)
        comparison=call('case.compare',before=[b],after=[a]);c=comparison['comparison_id']
        comparison=call('comparison.show',comparison_id=c)
        page=call('case.events',case_id=b,linked_run=True,limit=2)
        proof=call('case.evidence',case_id=b,evidence_id=page['records'][0]['evidence']['id'])
        coverage=call('case.coverage',case_id=b)
        bv=before['order_load']['result_validation'];av=after['order_load']['result_validation']
        be=before['order_load']['external_calls'];ae=after['order_load']['external_calls'];p=comparison['performance']
        answers=[
            '|'.join('unknown' if x['durations_seconds']['queue'] is None else str(x['durations_seconds']['queue']) for x in (before,after)),
            '|'.join(str(x) for x in (before['durations_seconds']['execution'],after['durations_seconds']['execution'],p['before_lower_median_seconds'],p['after_upper_median_seconds'])),
            '|'.join(str(v[k]) for v in (bv,av) for k in ('status','expected_count','actual_count','mismatch_count')),
            '|'.join(str(x) for x in (coverage['sources'][0]['record_count'],page['matched_count'],before['ignored_event_count'])),
            proof['evidence_id']+'|'+proof['sha256'],
            comparison['comparability']['status']+'|'+before['order_load']['workload_signature']['input_sha256'],
            '|'.join(str(x) for x in (comparison['status'],p['status'],comparison['before_count'],comparison['after_count'],comparison['required_pairs'])),
            '|'.join(str(x) for x in (be['count'],ae['count'],be['unique_skus'],ae['unique_skus'],be['repeated_lookups'],ae['repeated_lookups'])),
            be['metric_basis'],
            '|'.join(str(x).lower() for d in (before,after) for x in (d['cause_state'],d['requires_ai_interpretation'])),
        ]
        if be['metric_basis']!=ae['metric_basis'] or before['order_load']['workload_signature']['input_sha256']!=after['order_load']['workload_signature']['input_sha256']:
            raise ValueError('Fixed evaluation input facts differ')
        template=ROOT/'evaluations/mcp-sc01.xml';evaluation=ET.fromstring(template.read_bytes());pairs=evaluation.findall('qa_pair')
        if len(pairs)!=10:raise ValueError('Expected ten independent QA cases')
        for pair,answer in zip(pairs,answers):
            if pair.findtext('answer')!=answer:raise ValueError('Fixed QA answer disagrees with observed fixture evidence')
            question=pair.find('question')
            question.text=question.text.replace('{BEFORE}',b).replace('{AFTER}',a).replace('{COMPARISON}',c)
        evaluated=private/'qa.xml';ET.ElementTree(evaluation).write(evaluated,encoding='utf-8',xml_declaration=True)
        receipt=dict(product_version=__version__,protocol=version,catalogue_profile='direct',tool_count=len(catalogue['tools']),verified_answers=10,
            llm_evaluation_performed=False,token_advantage_verified=False,native_platform_started=False,server_license_used=False,
            fixture_scope='retained transformed laboratory excerpts; not new native capture or full SC01 acceptance',
            state_dir=str(state),before_case=b,after_case=a,comparison_id=c,evaluation=str(evaluated),
            evaluation_template_sha256=hashlib.sha256(template.read_bytes()).hexdigest(),
            complete_client_wire_bytes_observed=wire_bytes,model_tokens=None,observations=observations)
        fs.write(private/'receipt.json',receipt)
        return receipt
    finally:
        process.stdin.close()
        try:process.wait(timeout=12)
        except subprocess.TimeoutExpired:process.kill();process.wait(timeout=5)
        thread.join(timeout=2);process.stdout.close();errors.close()


if __name__=='__main__':
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--state-dir',type=Path,required=True)
    parser.add_argument('--protocol',choices=(MODERN,LEGACY),default=MODERN)
    args=parser.parse_args()
    print(json.dumps(run(args.state_dir,args.protocol),ensure_ascii=False,indent=2))
