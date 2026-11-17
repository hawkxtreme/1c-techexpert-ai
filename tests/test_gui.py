import http.client
from html.parser import HTMLParser
import importlib
import importlib.util
import json
import tempfile
import threading
import unittest
from pathlib import Path


class GuiHTTPTests(unittest.TestCase):
    def test_ras_invalid_types_are_rejected_before_any_connection(self):
        from unittest.mock import patch
        with patch('src.techexpert.profiles.discover_ras',side_effect=AssertionError('invalid request connected')):
            for key,value in [('endpoint',0),('executable',None),('cluster',False),('infobase',0),('docker_container',[])] :
                with self.subTest(key=key):
                    request=dict(endpoint='host.invalid:1545');request[key]=value
                    self.assertEqual(self.request('POST','/api/ras',request)[0],400)

    def test_matching_choices_compose_without_save_or_database_access(self):
        from test_registration_matches import profile
        from src.techexpert.profile_resources import effective_profile
        value=profile();body=dict(view=effective_profile(value),draft_profile=value)
        status,_,raw=self.request('POST','/api/profile-compose',body,headers={'If-Match':'"profile-0"'})
        self.assertEqual(status,200);found=json.loads(raw);gid=found['matches']['groups'][0]['id']
        body['registration_decisions']={gid:'separate'}
        status,_,raw=self.request('POST','/api/profile-compose',body,headers={'If-Match':'"profile-0"'})
        self.assertEqual(status,200);self.assertEqual(json.loads(raw)['matches']['groups'][0]['status'],'separate')
        body.pop('registration_decisions');body['base_merge']=dict(keep_id='a',remove_ids=['b'])
        status,_,raw=self.request('POST','/api/profile-compose',body,headers={'If-Match':'"profile-0"'})
        self.assertEqual(status,200);self.assertEqual([b['id'] for b in json.loads(raw)['profile']['bases']],['a']);self.assert_no_profile()

    def test_starter_location_is_a_passive_suggestion_and_requires_authorization(self):
        from unittest.mock import patch
        self.assertEqual(self.request('GET','/api/starter-location',token=False)[0],401)
        with patch('src.techexpert.discovery.read_snapshot',side_effect=AssertionError('GET read a starter list')):
            status,_,raw=self.request('GET','/api/starter-location')
        self.assertEqual(status,200);body=json.loads(raw)
        self.assertEqual(set(body),{'path','checked'});self.assertFalse(body['checked']);self.assert_no_profile()

    def test_detailed_starter_registration_reaches_saved_graph_only_on_explicit_save(self):
        starter=Path(self.temp.name)/'ibases.v8i';entry='11111111-1111-1111-1111-111111111111'
        starter.write_text('[Accounting]\nConnect=File="C:\\Data\\Accounting";\nID='+entry+'\n',encoding='utf-8-sig')
        status,_,raw=self.request('POST','/api/starter',dict(path=str(starter),include_registrations=True))
        self.assertEqual(status,200);found=json.loads(raw);self.assert_no_profile()
        value=dict(schema_version=1,name='Imported',bases=found['bases'],sources=[])
        status,_,raw=self.request('POST','/api/profile-compose',dict(view=value,base_registrations=found['registrations']),headers={'If-Match':'"profile-0"'})
        self.assertEqual(status,200);prepared=json.loads(raw);self.assert_no_profile()
        self.assertEqual(prepared['profile']['bases'][0]['registrations'][0]['entry_id'],entry)
        self.assertEqual(self.request('POST','/api/profile',prepared['profile'],headers={'If-Match':'"profile-0"'})[0],200)
        status,_,raw=self.request('GET','/api/profile');saved=json.loads(raw)
        self.assertEqual(saved['bases'][0]['mode_origin']['origin'],'starter_connect_file')
        self.assertFalse((self.state_dir/'artifacts').exists());self.assertFalse((self.state_dir/'cases').exists())

    def test_preflight_legacy_os_with_omitted_settings_defaults_returns_a_response(self):
        value=dict(schema_version=1,name='Legacy',bases=[dict(id='a',name='File',mode='file',connection='//file.invalid/main')],sources=[dict(id='os',type='os',path='',host='',base_ids=['a'],settings={})])
        status,_,raw=self.request('POST','/api/check',value)
        self.assertEqual(status,200);self.assertEqual(json.loads(raw)['sources'][0]['status'],'local_collector_available')
        self.assertFalse(self.state_dir.exists())

    def test_shared_profile_editor_is_protected_and_configuration_only(self):
        from test_profile_resources import graph
        from src.techexpert.profiles import save_profile,load_profile
        value=save_profile(self.state_dir,graph(),expected_revision=0)
        self.assertEqual(self.request('POST','/api/profile-editor',{'profile':value},token=False)[0],401)
        self.assertEqual(self.request('POST','/api/profile-editor',{'profile':value},origin=False)[0],403)
        status,_,raw=self.request('POST','/api/profile-editor',{'profile':value})
        self.assertEqual(status,200);opened=json.loads(raw)
        self.assertEqual(opened['view']['sources'][0]['host'],'db.internal')
        self.assertEqual(opened['connection_bindings']['sql-a'],opened['connection_bindings']['sql-b'])
        self.assertEqual(load_profile(self.state_dir),value)
        self.assertFalse((self.state_dir/'artifacts').exists())

    def test_shared_compose_previews_all_affected_bases_before_an_explicit_save(self):
        from test_profile_resources import graph
        from src.techexpert.profiles import save_profile,load_profile
        from src.techexpert.profile_resources import effective_profile
        value=save_profile(self.state_dir,graph(),expected_revision=0)
        body=dict(view=effective_profile(value),draft_profile=value,connection_edits={'sql':dict(address='replacement')})
        status,_,raw=self.request('POST','/api/profile-compose',body,headers={'If-Match':'"profile-1"'})
        self.assertEqual(status,200);prepared=json.loads(raw)
        self.assertFalse(prepared['saved']);self.assertEqual(prepared['impact']['affected_base_ids'],['a','b'])
        self.assertEqual(load_profile(self.state_dir),value)
        self.assertFalse((self.state_dir/'profiles/2.json').exists())
        self.assertEqual(self.request('POST','/api/profile',prepared['profile'],headers={'If-Match':'"profile-1"'})[0],200)
        self.assertEqual(load_profile(self.state_dir)['schema_version'],2)
        self.assertEqual(load_profile(self.state_dir)['connections'][1]['address'],'replacement')

    def test_shared_compose_rejects_missing_and_stale_profile_revisions(self):
        from test_profile_resources import graph
        from src.techexpert.profiles import save_profile,load_profile
        from src.techexpert.profile_resources import effective_profile
        value=save_profile(self.state_dir,graph(),expected_revision=0);body=dict(view=effective_profile(value))
        self.assertEqual(self.request('POST','/api/profile-compose',body)[0],428)
        second=save_profile(self.state_dir,dict(value,name='Different environment'),expected_revision=1)
        self.assertEqual(self.request('POST','/api/profile-compose',body,headers={'If-Match':'"profile-1"'})[0],409)
        self.assertEqual(load_profile(self.state_dir),second)

    def test_readiness_is_protected_read_only_and_has_separate_demo_action(self):
        self.assertEqual(self.request('GET','/api/readiness',token=False)[0],401)
        status,_,body=self.request('GET','/api/readiness');self.assertEqual(status,200)
        report=json.loads(body);self.assertTrue(report['capabilities']['run_synthetic_demo'])
        self.assertFalse(self.state_dir.exists())
        self.assertEqual(self.request('GET','/api/demo')[0],404)
        self.assertEqual(self.request('POST','/api/demo',{},token=False)[0],401)
        self.assertEqual(self.request('POST','/api/demo',{},origin=False)[0],403)
        self.assertEqual(self.request('POST','/api/demo',{'path':'//private/source'})[0],400)
        self.assertFalse(self.state_dir.exists())

    def test_explicit_gui_demo_is_synthetic_reused_and_keeps_case_profile(self):
        from src.techexpert.investigations import create,load
        from src.techexpert.profiles import save_profile,load_profile
        original=save_profile(self.state_dir,self.profile)
        case=create(self.state_dir,dict(task='Existing SC01',template_id='TPL-02',time_mode='past',scale='background'))
        self.server.investigation_id=case['investigation_id']
        status,_,body=self.request('POST','/api/demo',{});self.assertEqual(status,200)
        result=json.loads(body);self.assertEqual(result['origin'],'synthetic')
        self.assertEqual(result['durations_seconds']['execution'],2460)
        again=json.loads(self.request('POST','/api/demo',{})[2]);self.assertEqual(again['case_id'],result['case_id'])
        report=json.loads(self.request('GET','/api/readiness')[2]);self.assertEqual(report['demonstration']['case_id'],result['case_id'])
        self.assertEqual(load_profile(self.state_dir),original)
        self.assertEqual(load(self.state_dir,case['investigation_id'])['revision'],case['revision'])
        broken=self.state_dir/'cases'/result['case_id']/'sources/s1.bin';broken.write_bytes(b'changed')
        self.assertEqual(self.request('POST','/api/demo',{})[0],400)
        self.assertEqual(len(list((self.state_dir/'cases').iterdir())),1)

    def test_gui_shows_readiness_without_requiring_a_profile(self):
        status,_,body=self.request('GET','/');self.assertEqual(status,200)
        html=body.decode('utf-8')
        self.assertTrue('id="readiness-panel"' in html,'readiness view is missing')
        self.assertTrue('id="run-demo"' in html,'separate safe demo action is missing')

    def test_stale_gui_does_not_remove_a_source_added_by_the_cli_writer(self):
        from src.techexpert.profiles import save_profile,load_profile
        first=save_profile(self.state_dir,self.profile)
        self.request('GET','/api/profile')
        changed=json.loads(json.dumps(self.profile));changed['sources'].append(dict(id='fresh-code',type='source',path='D:/fresh-code',host='',base_ids=['file-1']))
        fresh=save_profile(self.state_dir,changed,expected_revision=first['revision'])
        status,_,body=self.request('POST','/api/profile',self.profile,headers={'If-Match':'"profile-'+str(first['revision'])+'"'})
        self.assertEqual(status,409,'stale GUI replaced the fresh CLI source configuration')
        self.assertEqual(load_profile(self.state_dir)['revision'],fresh['revision'])
        self.assertTrue(any(x['id']=='fresh-code' for x in load_profile(self.state_dir)['sources']))

    def test_pinned_gui_cannot_overwrite_a_different_current_profile(self):
        from src.techexpert.profiles import save_profile,load_profile
        from src.techexpert.investigations import create,load
        first=save_profile(self.state_dir,self.profile)
        doc=create(self.state_dir,dict(task='Pinned A',template_id='TPL-02',time_mode='past',scale='background'))
        self.server.investigation_id=doc['investigation_id']
        other=json.loads(json.dumps(self.profile));other['name']='Other environment'
        fresh=save_profile(self.state_dir,other,expected_revision=first['revision'])
        _,headers,body=self.request('GET','/api/profile');self.assertEqual(json.loads(body)['revision'],first['revision'])
        status,_,_=self.request('POST','/api/profile',self.profile,headers={'If-Match':'"profile-'+str(first['revision'])+'"'})
        self.assertEqual(status,409);self.assertEqual(load_profile(self.state_dir)['revision'],fresh['revision'])
        self.assertEqual(load(self.state_dir,doc['investigation_id'])['revision'],doc['revision'])

    def test_unconfigured_pinned_gui_does_not_replace_a_later_global_profile(self):
        from src.techexpert.profiles import save_profile,load_profile
        from src.techexpert.investigations import create
        doc=create(self.state_dir,dict(task='Initially unconfigured',template_id='TPL-02',time_mode='past',scale='background'))
        self.server.investigation_id=doc['investigation_id'];fresh=save_profile(self.state_dir,self.profile)
        self.assertIsNone(json.loads(self.request('GET','/api/profile')[2]))
        status,_,_=self.request('POST','/api/profile',self.profile,headers={'If-Match':'"profile-0"'})
        self.assertEqual(status,409);self.assertEqual(load_profile(self.state_dir)['revision'],fresh['revision'])

    def test_profile_etag_is_returned_and_updates_only_after_a_successful_save(self):
        status,headers,_=self.request('GET','/api/profile');self.assertEqual(status,200)
        self.assertEqual(headers.get('ETag'),'"profile-0"')
        status,headers,body=self.request('POST','/api/profile',self.profile)
        self.assertEqual(status,200);self.assertEqual(headers.get('ETag'),'"profile-'+str(json.loads(body)['revision'])+'"')

    def test_profile_write_requires_one_explicit_loaded_revision(self):
        status,_,_=self.request('POST','/api/profile',self.profile,profile_tag=False)
        self.assertEqual(status,428)
        for value in ('*','profile-0','"profile-01"','"profile-0", "profile-1"'):
            with self.subTest(value=value):
                self.assertEqual(self.request('POST','/api/profile',self.profile,headers={'If-Match':value})[0],400)
        self.assert_no_profile()
    def test_selected_investigation_loads_its_pinned_profile_instead_of_global_current(self):
        from src.techexpert.investigations import create
        from src.techexpert.profiles import save_profile
        a=save_profile(self.state_dir,dict(schema_version=1,name='A',bases=[dict(id='a',name='IB A',mode='file',connection='D:/A')],sources=[]))
        doc=create(self.state_dir,dict(task='Case A',template_id='TPL-02',time_mode='past',scale='background'))
        self.server.investigation_id=doc['investigation_id']
        save_profile(self.state_dir,dict(schema_version=1,name='B',bases=[dict(id='b',name='IB B',mode='file',connection='D:/B')],sources=[]))
        status,_,body=self.request('GET','/api/profile');self.assertEqual(status,200)
        self.assertEqual(json.loads(body)['name'],'A')
        self.assertEqual(json.loads(body)['revision'],a['revision'])
        self.server.investigation_id=None
        self.assertEqual(json.loads(self.request('GET','/api/profile')[2])['name'],'B')

    def test_unconfigured_investigation_does_not_inherit_a_later_unrelated_profile(self):
        from src.techexpert.investigations import create
        from src.techexpert.profiles import save_profile
        doc=create(self.state_dir,dict(task='Unconfigured case',template_id='TPL-02',time_mode='past',scale='background'))
        self.server.investigation_id=doc['investigation_id']
        save_profile(self.state_dir,dict(schema_version=1,name='Other',bases=[dict(id='other',name='Other',mode='file',connection='D:/Other')],sources=[]))
        self.assertIsNone(json.loads(self.request('GET','/api/profile')[2]))

    def test_source_help_requires_auth_and_includes_offline_preparation(self):
        self.assertEqual(self.request('GET','/api/source-help',token=False)[0],401)
        status,_,body=self.request('GET','/api/source-help');self.assertEqual(status,200)
        value=json.loads(body)
        self.assertIn('1Cv8.lgf',value['sources']['jr']['expected_format'])
        self.assertTrue(value['sources']['tj']['windows_steps'])
        self.assertFalse(self.state_dir.exists())

    def test_source_export_help_is_available_without_starting_export_or_saving_profile(self):
        from unittest.mock import patch
        with patch('src.techexpert.source_export.prepare') as prepare,patch('src.techexpert.windows_native.run') as launch:
            status,_,body=self.request('GET','/')
            self.assertEqual(status,200);self.assertTrue(b'id="source-export-help"' in body,'source preparation route is missing')
            self.assertTrue('Помочь получить исходники' in body.decode('utf-8'))
            status,_,body=self.request('GET','/api/source-help');self.assertEqual(status,200)
            self.assertTrue(json.loads(body)['sources']['source']['export_help']['request_in_chat'])
            prepare.assert_not_called();launch.assert_not_called();self.assertFalse(self.state_dir.exists())

    def test_investigation_context_requires_auth_and_only_edits_selected_investigation(self):
        from src.techexpert.investigations import create,load
        investigation=create(self.state_dir,dict(task='Загрузка медленная',template_id='TPL-02',time_mode='past',scale='background'))
        self.server.investigation_id=investigation['investigation_id']
        self.assertEqual(self.request('GET','/api/context',token=False)[0],401)
        status,_,body=self.request('GET','/api/context');self.assertEqual(status,200)
        context=json.loads(body);self.assertEqual(context['task'],investigation['task'])
        self.assertEqual(self.request('GET','/api/templates',token=False)[0],401)
        status,_,body=self.request('GET','/api/templates');self.assertEqual(status,200)
        self.assertEqual(len(json.loads(body)['templates']),11)
        body=dict(expected_revision=1,template_id='TPL-01',variant='document-posting',time_mode='current',scale='one')
        self.assertEqual(self.request('POST','/api/context',body,origin=False)[0],403)
        self.assertEqual(self.request('POST','/api/context',dict(body,investigation_id='other'))[0],400)
        status,_,result=self.request('POST','/api/context',body);self.assertEqual(status,200,result)
        self.assertEqual(json.loads(result)['revision'],2)
        self.assertEqual(load(self.state_dir,investigation['investigation_id'])['task'],investigation['task'])
        self.assertEqual(self.request('POST','/api/context',body)[0],400)
        self.assertFalse((self.state_dir/'artifacts').exists())

    def test_new_checks_require_auth_and_local_preflight_has_no_side_effects(self):
        status,_,_=self.request('POST','/api/check',self.profile,token=False)
        self.assertEqual(status,401)
        status,_,body=self.request('POST','/api/check',self.profile)
        self.assertEqual(status,200)
        result=json.loads(body)
        self.assertFalse(result['connected'])
        self.assertFalse(result['collection_started'])
        self.assertFalse(self.state_dir.exists())
        status,_,_=self.request('POST','/api/ras',{'endpoint':'localhost:1545','executable':'cmd.exe'})
        self.assertEqual(status,400)

    def test_manual_base_selector_contains_file_server_unknown(self):
        class SelectParser(HTMLParser):
            active = False
            values = None
            def handle_starttag(self, tag, attrs):
                attrs = dict(attrs)
                if tag == 'select':
                    self.active = attrs.get('id') == 'manual-mode'
                elif tag == 'option' and self.active:
                    self.values.append(attrs.get('value'))
            def handle_endtag(self, tag):
                if tag == 'select':
                    self.active = False
        status, _, body = self.request('GET', '/', token=False, origin=False)
        self.assertEqual(status, 200)
        parser = SelectParser()
        parser.values = []
        parser.feed(body.decode('utf-8'))
        self.assertCountEqual(parser.values, ['file', 'server', 'unknown'])

    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.gui'),
                             'The local init HTTP boundary is not implemented yet')
        self.gui = importlib.import_module('src.techexpert.gui')
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.state_dir = Path(self.temp.name) / 'state'
        self.server = self.gui.create_server(self.state_dir, ttl=10)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.addCleanup(self.stop_server, self.server, self.thread)
        self.origin = 'http://127.0.0.1:' + str(self.server.server_port)
        self.profile = {
            'schema_version': 1, 'name': 'Local test',
            'bases': [{'id': 'file-1', 'name': 'Accounting', 'mode': 'file',
                       'connection': str(Path(self.temp.name) / 'Accounting')}],
            'sources': [{'id': 'tj-1', 'type': 'tj', 'path': str(Path(self.temp.name) / 'logs'),
                         'host': '', 'base_ids': ['file-1']}],
        }

    @staticmethod
    def stop_server(server, thread):
        server.shutdown()
        server.server_close()
        thread.join(timeout=3)

    def request(self, method, route, body=None, *, token=True, origin=True, headers=None, profile_tag=True):
        options = {'Origin': self.origin} if origin else {}
        if profile_tag and method=='POST' and route=='/api/profile':options['If-Match']=getattr(self,'profile_etag','"profile-0"')
        if token:
            options['Authorization'] = 'Bearer ' + self.server.token
        if body is not None:
            options['Content-Type'] = 'application/json'
            if not isinstance(body, (str, bytes)):
                body = json.dumps(body).encode('utf-8')
        options.update(headers or {})
        connection = http.client.HTTPConnection('127.0.0.1', self.server.server_port, timeout=3)
        try:
            connection.request(method, route, body=body, headers=options)
            response = connection.getresponse()
            response_headers=dict(response.getheaders());raw=response.read()
            if route=='/api/profile' and response.status==200 and 'ETag' in response_headers:self.profile_etag=response_headers['ETag']
            return response.status,response_headers,raw
        finally:
            connection.close()

    def assert_no_profile(self):
        status, _, body = self.request('GET', '/api/profile')
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(body))

    def test_loopback_and_page_do_not_expose_token(self):
        self.assertEqual(self.server.server_address[0], '127.0.0.1')
        status, headers, body = self.request('GET', '/', token=False, origin=False)
        self.assertEqual(status, 200)
        self.assertNotIn(self.server.token.encode(), body)
        self.assertIn("frame-ancestors 'none'", headers['Content-Security-Policy'])
        self.assertEqual(headers['Referrer-Policy'], 'no-referrer')
        self.assertIn('no-store', headers['Cache-Control'])

    def test_doctor_reports_this_helpers_state_directory(self):
        status,_,body=self.request('GET','/api/doctor')
        self.assertEqual(status,200)
        self.assertEqual(Path(json.loads(body)['state_dir']),self.state_dir.resolve())
        self.assertFalse(self.state_dir.exists())

    def test_missing_or_wrong_token_cannot_read_profile(self):
        for headers in ({}, {'Authorization': 'Bearer incorrect'}):
            with self.subTest(headers=headers):
                status, _, _ = self.request('GET', '/api/profile', token=False, headers=headers)
                self.assertEqual(status, 401)

    def test_query_token_is_not_an_authentication_route(self):
        status, _, _ = self.request('GET', '/api/profile?token=' + self.server.token, token=False)
        self.assertIn(status, (400, 401))

    def test_foreign_host_is_rejected_even_with_token(self):
        status, _, _ = self.request('POST', '/api/profile', self.profile,
                                    headers={'Host': 'attacker.example'})
        self.assertEqual(status, 403)
        self.assert_no_profile()

    def test_foreign_or_absent_origin_cannot_save(self):
        for origin in ('https://attacker.example', 'null', None):
            with self.subTest(origin=origin):
                headers = {'Origin': origin} if origin is not None else {}
                status, _, _ = self.request('POST', '/api/profile', self.profile,
                                            origin=False, headers=headers)
                self.assertEqual(status, 403)
        self.assert_no_profile()

    def test_cross_origin_read_is_rejected(self):
        status, _, _ = self.request('GET', '/api/profile',
                                    headers={'Origin': 'http://attacker.example'})
        self.assertEqual(status, 403)

    def test_non_json_cannot_save(self):
        status, _, _ = self.request('POST', '/api/profile', json.dumps(self.profile),
                                    headers={'Content-Type': 'text/plain'})
        self.assertEqual(status, 415)
        self.assert_no_profile()

    def test_malformed_or_oversized_json_does_not_save(self):
        for body, expected in (('{broken', 400), ('x' * 70000, 413), ('[]', 400)):
            with self.subTest(expected=expected, size=len(body)):
                status, _, _ = self.request('POST', '/api/profile', body)
                self.assertEqual(status, expected)
        self.assert_no_profile()

    def test_save_validation_does_not_overwrite_previous_profile(self):
        status, _, saved = self.request('POST', '/api/profile', self.profile)
        self.assertEqual(status, 200)
        bad = json.loads(json.dumps(self.profile))
        bad['sources'][0]['type'] = 'sql'
        bad['sources'][0]['host'] = 'not-contacted.example'
        status, _, _ = self.request('POST', '/api/profile', bad)
        self.assertEqual(status, 400)
        status, _, loaded = self.request('GET', '/api/profile')
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(loaded), json.loads(saved))

    def test_authorized_save_and_load_return_backend_revision(self):
        status, _, raw = self.request('POST', '/api/profile', self.profile)
        self.assertEqual(status, 200)
        saved = json.loads(raw)
        self.assertTrue(saved['revision'])
        self.assertEqual(saved['bases'][0]['mode'], 'file')
        self.assertEqual(saved['sources'][0]['status'], 'not_checked')
        status, _, raw = self.request('GET', '/api/profile', origin=False)
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw), saved)

    def test_starter_import_reads_only_explicit_file(self):
        starter = Path(self.temp.name) / 'ibases.v8i'
        starter.write_text('[Accounting]\nConnect=File="C:\\Data\\Accounting";\n', encoding='utf-8-sig')
        status, _, raw = self.request('POST', '/api/starter', {'path': str(starter)})
        self.assertEqual(status, 200)
        bases = json.loads(raw)
        self.assertEqual(len(bases), 1)
        self.assertEqual(bases[0]['mode'], 'file')
        self.assert_no_profile()

    def test_ttl_ends_server_lifetime(self):
        server = self.gui.create_server(self.state_dir, ttl=0.15)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(self.stop_server, server, thread)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive(), 'The helper must terminate when its token expires')


if __name__ == '__main__':
    unittest.main()
