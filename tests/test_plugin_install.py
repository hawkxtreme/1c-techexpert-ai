"""The shipped plugin connects its own tools without touching source data."""
import json
import os
from pathlib import Path
import queue
import subprocess
import sys
import tempfile
import threading
import unittest
import zipfile

from scripts.package_plugin import build
from src.techexpert import __version__
from src.techexpert import readiness


class PluginInstallTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.home=Path(self.temp.name);self.bundle=self.home/'installed bundle with spaces — тест'
        self.archive=self.home/'plugin.zip';build(self.archive)
        with zipfile.ZipFile(self.archive) as stream:stream.extractall(self.bundle)

    def document(self,name):return json.loads((self.bundle/name).read_text(encoding='utf-8'))

    def test_portable_and_compatibility_metadata_load_the_same_version_and_skills(self):
        manifest=self.document('plugin.json');legacy=self.document('.codex-plugin/plugin.json')
        self.assertEqual(manifest['name'],'1c-techexpert-ai')
        self.assertEqual(manifest['version'],__version__);self.assertEqual(legacy['version'],__version__)
        extension=manifest['extensions']['com.openai']
        self.assertTrue(extension['requires_local_executor'])
        self.assertTrue((self.bundle/extension['onboardingSkill']).is_file())
        self.assertEqual(legacy['mcpServers'],'./.mcp.json')
        self.assertEqual(legacy['onboardingSkill'],extension['onboardingSkill'])
        self.assertEqual(len(list((self.bundle/'skills').glob('*/SKILL.md'))),18)
        self.assertNotIn('hooks',extension)

    def test_marketplace_selects_only_this_clean_local_package_without_auto_install(self):
        catalogue=self.document('.agents/plugins/marketplace.json')
        self.assertEqual(catalogue['name'],'1c-techexpert-local');self.assertEqual(len(catalogue['plugins']),1)
        entry=catalogue['plugins'][0]
        self.assertEqual(entry['name'],self.document('plugin.json')['name'])
        self.assertEqual(entry['source'],dict(source='local',path='./'))
        self.assertEqual(entry['policy']['installation'],'AVAILABLE')
        with zipfile.ZipFile(self.archive) as archive:
            self.assertFalse(any(name.startswith(('.local/','.git/')) or '__pycache__' in name for name in archive.namelist()))

    def test_packaged_stdio_declaration_discovers_tools_from_another_working_directory(self):
        portable=self.document('mcp.json')['mcpServers'];legacy=self.document('.mcp.json')['mcpServers']
        self.assertEqual(portable,legacy);self.assertEqual(set(portable),{'techexpert'})
        server=portable['techexpert'];self.assertEqual(server['type'],'stdio')
        self.assertEqual(server['command'],'python3');self.assertNotIn('env',server)
        args=[item.replace('${PLUGIN_ROOT}',str(self.bundle)) for item in server['args']]
        self.assertEqual(args[:2],['-X','utf8']);self.assertEqual(Path(args[2]),self.bundle/'techexpert.py')
        self.assertEqual(args[3:],['mcp-stdio'])
        cwd=server['cwd'].replace('${PLUGIN_ROOT}',str(self.bundle))
        self.assertEqual(Path(cwd),self.bundle)
        state=self.home/'private data';env=dict(os.environ,LOCALAPPDATA=str(state),XDG_STATE_HOME=str(state))
        requests=[dict(jsonrpc='2.0',id=1,method='initialize',params=dict(protocolVersion='2025-11-25',capabilities={},clientInfo=dict(name='plugin-package-test',version='1'))),
                  dict(jsonrpc='2.0',method='notifications/initialized'),dict(jsonrpc='2.0',id=2,method='tools/list',params={})]
        # Exercise declared argv with the current interpreter. Redirecting app-data
        # for isolation must not also change an OS Python launcher's own lookup.
        process=subprocess.Popen([sys.executable,*args],cwd=cwd,env=env,stdin=subprocess.PIPE,stdout=subprocess.PIPE,stderr=subprocess.PIPE)
        replies=[];received=queue.Queue()
        def read():
            for line in process.stdout:received.put(line)
            received.put(None)
        reader=threading.Thread(target=read,daemon=True);reader.start()
        try:
            for item in requests:
                process.stdin.write((json.dumps(item)+'\n').encode());process.stdin.flush()
                if 'id' in item:
                    line=received.get(timeout=15);self.assertIsNotNone(line,'Packaged MCP exited before replying')
                    reply=json.loads(line);self.assertEqual(reply.get('id'),item['id']);replies.append(reply)
            process.stdin.close();process.wait(timeout=10)
            self.assertEqual(process.returncode,0,process.stderr.read().decode('utf-8','replace'))
        finally:
            if process.poll() is None:process.kill();process.wait(timeout=5)
            reader.join(2)
            for stream in (process.stdin,process.stdout,process.stderr):
                if not stream.closed:stream.close()
        self.assertEqual(replies[0]['result']['serverInfo']['version'],__version__)
        tools=next(item['result']['tools'] for item in replies if item.get('id')==2)
        self.assertEqual(len(tools),33)
        self.assertIn('techexpert_code_execute',{item['name'] for item in tools})
        self.assertFalse(state.exists());self.assertFalse((self.bundle/'cases').exists())

    def test_readiness_refuses_a_package_with_missing_mcp_configuration(self):
        path=self.bundle/'mcp.json';self.assertTrue(path.is_file());path.unlink()
        state=self.home/'uncreated state';result=readiness.check(state,root=self.bundle)
        self.assertEqual(result['status'],'blocked')
        self.assertFalse(result['capabilities']['analyze_supplied_files']);self.assertFalse(state.exists())
