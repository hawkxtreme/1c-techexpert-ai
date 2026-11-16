import importlib
import importlib.util
import json
import unittest


FOLDER = dict(format='1c-tj-text-v1', platform_version='8.3.27.1989', encoding='utf-8',
              placement='folders', timestamp_format='minute',
              file_hour='2026-11-16T09:00:00+03:00', rotation_hours=1)
PLAIN = dict(format='1c-tj-text-v1', platform_version='8.3.27.1989', encoding='utf-8',
             placement='plain', timestamp_format='iso', utc_offset='+03:00')
GOOD = b'04:05.123456-250000,SCALL,2,level=INFO,process=rphost\n'


class NativeTJParserTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.native_tj'),
                             'The bounded native TJ parser is not implemented yet')
        self.module = importlib.import_module('src.techexpert.native_tj')

    def profile(self, spec=None, path='26111609.log'):
        return self.module.validate_profile(dict(FOLDER if spec is None else spec), path)

    def parse(self, data=GOOD, profile=None, **limits):
        return self.module.parse_tj(data, self.profile() if profile is None else profile, **limits)

    def test_folder_event_duration_and_explicit_time(self):
        result = self.parse()
        self.assertEqual(result['status'], 'parsed')
        self.assertEqual(result['records_seen'], 1)
        record = result['records'][0]
        self.assertEqual((record['raw_time'], record['duration_us'], record['event'], record['depth']),
                         ('04:05.123456', 250000, 'SCALL', 2))
        self.assertEqual(record['timestamp'], '2026-11-16T09:04:05.123456+03:00')
        self.assertEqual(record['timestamp_utc'], '2026-11-16T06:04:05.123456+00:00')
        self.assertIsNone(record['start_timestamp_utc'])
        self.assertNotIn('kind', record)

    def test_plain_date_and_negative_offset(self):
        profile = self.profile(dict(PLAIN, utc_offset='-05:30'), 'rphost_1.log')
        result = self.parse(b'2026-11-16T09:04:05.123456-0,UNKNOWN_EVENT,0,k=v\n', profile)
        record = result['records'][0]
        self.assertEqual(record['timestamp'], '2026-11-16T09:04:05.123456-05:30')
        self.assertEqual(record['timestamp_utc'], '2026-11-16T14:34:05.123456+00:00')
        self.assertEqual(record['duration_us'], 0)
        self.assertIsNone(record['start_timestamp_utc'])

    def test_plain_minute_header_observed_in_local_capture(self):
        # Only this header comes from a local capture; no private properties are copied.
        data = b'22:37.730000-0,EXCP,1,Detail=synthetic\n'
        spec = dict(FOLDER, placement='plain', file_hour='2026-11-16T08:00:00+03:00')
        profile = self.profile(spec, '1cv8_12345_26111608.log')
        result = self.parse(data, profile)
        self.assertEqual(result['status'], 'parsed')
        self.assertEqual(result['records'][0]['timestamp'], '2026-11-16T08:22:37.730000+03:00')
        self.assertEqual(result['records'][0]['event'], 'EXCP')

    def test_timestamp_grammar_is_independent_of_placement(self):
        for placement in ('folders', 'plain'):
            for time_format, spec, data in (
                    ('minute', FOLDER, GOOD),
                    ('iso', PLAIN, b'2026-11-16T09:04:05.123456-250000,SCALL,2\n')):
                with self.subTest(placement=placement, timestamp_format=time_format):
                    profile = self.profile(dict(spec, placement=placement), 'capture.log')
                    self.assertEqual(profile['placement'], placement)
                    self.assertEqual(profile['timestamp_format'], time_format)
                    result = self.parse(data, profile)
                    self.assertEqual(result['status'], 'parsed')
                    self.assertEqual(result['records'][0]['timestamp_utc'], '2026-11-16T06:04:05.123456+00:00')

    def test_timestamp_format_must_be_explicit_and_cannot_be_guessed(self):
        for value in (None, '', 'auto', 'folders', 'plain', [], {}, True):
            spec = dict(FOLDER)
            if value is None:
                spec.pop('timestamp_format')
            else:
                spec['timestamp_format'] = value
            with self.subTest(value=value), self.assertRaises(ValueError):
                self.profile(spec)
        self.assertEqual(self.parse(GOOD, self.profile(PLAIN, 'plain.log'))['status'], 'invalid')
        iso_data = b'2026-11-16T09:04:05.123456-250000,SCALL,2\n'
        self.assertEqual(self.parse(iso_data, self.profile(FOLDER))['status'], 'invalid')

    def test_metadata_is_json_safe_whitelisted_and_explicit(self):
        profile = self.profile(dict(FOLDER, context={'secret': 'not metadata'}, arbitrary='ignore'))
        json.dumps(profile)
        self.assertNotIn('context', profile)
        self.assertNotIn('arbitrary', profile)
        self.assertEqual(profile['duration_unit'], 'microseconds')
        self.assertEqual(profile['time_basis'], 'user_declared_hour_and_offset')

    def test_version_encoding_and_placement_are_not_guessed(self):
        for changes in ({'platform_version':'8.3.27'}, {'platform_version':'8.3.28.1'},
                        {'encoding':'cp1251'}, {'placement':'auto'}, {'format':'json'}):
            with self.subTest(changes=changes), self.assertRaises(ValueError):
                self.profile(dict(FOLDER, **changes))

    def test_json_wrong_type_profile_is_rejected_as_value_error(self):
        for placement in ([], {}, None, 42, True):
            with self.subTest(placement=placement), self.assertRaises(ValueError):
                self.profile(dict(FOLDER, placement=placement))

    def test_minute_timestamp_requires_explicit_single_hour_rotation(self):
        for placement in ('folders', 'plain'):
            for value in (None, 0, 2, '1', True):
                spec = dict(FOLDER, placement=placement)
                if value is None:
                    spec.pop('rotation_hours')
                else:
                    spec['rotation_hours'] = value
                with self.subTest(placement=placement, value=value), self.assertRaises(ValueError):
                    self.profile(spec)

    def test_hour_requires_offset_exact_hour_and_matching_filename(self):
        for hour in ('2026-11-16T09:00:00', '2026-11-16T09:01:00+03:00',
                     '2026-11-16T09:00:01+03:00', '2026-13-16T09:00:00+03:00'):
            with self.subTest(hour=hour), self.assertRaises(ValueError):
                self.profile(dict(FOLDER, file_hour=hour))
        with self.assertRaises(ValueError):
            self.profile(path=r'C:\logs\rphost_1\26111608.log')
        self.assertEqual(self.profile(dict(FOLDER, file_hour='2126-11-16T09:00:00+03:00'))['file_hour'][:4], '2126')

    def test_minute_timestamp_checks_both_filename_shapes_for_both_placements(self):
        for placement in ('folders', 'plain'):
            spec = dict(FOLDER, placement=placement)
            for name in ('26111609.log', '1cv8_12345_26111609.log',
                         r'C:\logs\rphost_4321_26111609.log'):
                with self.subTest(placement=placement, name=name):
                    self.profile(spec, name)
            for name in ('26111608.log', '1cv8_12345_26111608.log',
                         r'C:\logs\rphost_4321_26111608.log'):
                with self.subTest(placement=placement, name=name), self.assertRaises(ValueError):
                    self.profile(spec, name)
            future = dict(spec, file_hour='2126-11-16T09:00:00+03:00')
            self.assertTrue(self.profile(future, '1cv8_12345_26111609.log')['file_hour'].startswith('2126-'))

    def test_iso_requires_strict_explicit_offset_for_both_placements(self):
        for placement in ('folders', 'plain'):
            for offset in (None, '', 'MSK', 'Z', '+3:00', '+24:00', '+03:60', '+03:00:00'):
                with self.subTest(placement=placement, offset=offset), self.assertRaises(ValueError):
                    self.profile(dict(PLAIN, placement=placement, utc_offset=offset), 'capture.log')
            self.profile(dict(PLAIN, placement=placement, utc_offset='+00:00'), 'capture.log')

    def test_quoted_names_values_both_quotes_and_doubling(self):
        raw = b'''04:05.123456-1,CALL,0,"a,b"="x,y",'n''ame'='v''alue',"double"="a""b",'a=b'=x=y\n'''
        record = self.parse(raw)['records'][0]
        self.assertEqual(record['properties'], {'a,b':'x,y', "n'ame":"v'alue", 'double':'a"b', 'a=b':'x=y'})

    def test_unquoted_apostrophes_and_backslash_are_not_escape(self):
        raw = b"04:05.123456-1,CALL,0,Usr=O'Brien,O'Key=ok,Path='C:\\logs\\',empty=\n"
        props = self.parse(raw)['records'][0]['properties']
        self.assertEqual(props['Usr'], "O'Brien")
        self.assertEqual(props["O'Key"], 'ok')
        self.assertEqual(props['Path'], 'C:\\logs\\')
        self.assertEqual(props['empty'], '')

    def test_multiline_name_value_crlf_and_fake_header(self):
        raw = ('04:05.123456-1,CALL,0,"name\r\npart"="Привет,\r\n'
               '05:00.000000-0,FAKE,0,k=v\r\nend"\r\n').encode('utf-8')
        result = self.parse(raw + GOOD)
        self.assertEqual([row['event'] for row in result['records']], ['CALL','SCALL'])
        first, second = result['records']
        self.assertEqual(first['properties']['name\r\npart'], 'Привет,\r\n05:00.000000-0,FAKE,0,k=v\r\nend')
        self.assertEqual((first['line'],first['end_line'],first['byte_start'],first['byte_end']), (1,4,0,len(raw)))
        self.assertEqual((second['line'],second['byte_start'],second['byte_end']), (5,len(raw),len(raw + GOOD)))

    def test_utf8_bom_only_at_start_and_byte_offsets(self):
        result = self.parse(b'\xef\xbb\xbf' + GOOD + b'\xef\xbb\xbf' + GOOD)
        self.assertEqual(len(result['records']), 1)
        self.assertEqual(result['records'][0]['byte_start'], 3)
        self.assertEqual(result['status'], 'partial')

    def test_bom_inside_quoted_value_is_rejected(self):
        result = self.parse(b'04:05.123456-1,CALL,0,k="x\xef\xbb\xbfy"\n')
        self.assertEqual(result['status'], 'invalid')

    def test_invalid_utf8_is_not_replaced_and_next_header_can_recover(self):
        bad = b'04:05.123456-1,CALL,0,k=\xff\n'
        result = self.parse(bad + GOOD)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['records_seen'], 2)
        self.assertEqual(len(result['records']), 1)
        self.assertEqual(result['records'][0]['byte_start'], len(bad))
        self.assertTrue(any(item['code'] == 'invalid_utf8' for item in result['limitations']))

    def test_missing_final_newline_and_incomplete_utf8_are_not_records(self):
        for tail in (GOOD[:-1], b'04:05.123456-1,CALL,0,k=\xd0'):
            with self.subTest(tail=tail):
                result = self.parse(GOOD + tail)
                self.assertEqual(result['status'], 'partial')
                self.assertEqual(len(result['records']), 1)

    def test_open_quote_never_recovers_fake_header(self):
        result = self.parse(b'04:05.123456-1,CALL,0,k="unterminated\n' + GOOD)
        self.assertEqual(result['records_seen'], 1)
        self.assertEqual(result['records'], [])
        self.assertEqual(result['status'], 'invalid')

    def test_duplicate_decoded_keys_preserve_record_without_selecting_a_value(self):
        bad = b'04:05.123456-1,CALL,0,k=first,"k"=second\n'
        result = self.parse(bad + GOOD)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['records_seen'], 2)
        self.assertEqual(len(result['records']), 2)
        self.assertNotIn('k', result['records'][0]['properties'])
        self.assertEqual(result['records'][0]['ambiguous_properties'], {'k':['first','second']})

    def test_real_transaction_has_two_func_properties(self):
        raw=b'04:05.123456-20,SDBL,2,process=1cv8,Func=Transaction,Func=CommitTransaction\n'
        result=self.parse(raw)
        self.assertEqual(len(result['records']),1)
        self.assertEqual(result['records'][0]['ambiguous_properties']['Func'],['Transaction','CommitTransaction'])
        self.assertNotIn('Func',result['records'][0]['properties'])

    def test_bad_record_recovery_requires_fresh_valid_header(self):
        bad = b'not a header\n04:05.123456-1,CALL,0,k="closed"junk\n'
        result = self.parse(bad + GOOD)
        self.assertEqual(result['records_seen'], 3)
        self.assertEqual(len(result['records']), 1)
        self.assertEqual(result['records'][0]['line'], 3)

    def test_record_byte_limit_recovers_only_outside_quotes(self):
        oversized = b'04:05.123456-1,CALL,0,k="' + b'x' * 100 + b'\n' + GOOD + b'"\n'
        result = self.parse(oversized + GOOD, max_record_bytes=80)
        self.assertEqual(result['records_seen'], 2)
        self.assertEqual([row['event'] for row in result['records']], ['SCALL'])
        self.assertEqual(result['status'], 'partial')

    def test_record_budget_counts_invalid_records_and_accepts_zero(self):
        result = self.parse(b'bad\nbad\n' + GOOD, max_records=2)
        self.assertEqual(result['records_seen'], 2)
        self.assertEqual(result['records'], [])
        self.assertTrue(any(item['code'] == 'record_limit' for item in result['limitations']))
        result = self.parse(GOOD, max_records=0)
        self.assertEqual(result['records_seen'], 0)
        self.assertEqual(result['records'], [])
        self.assertEqual(result['status'], 'not_parsed')
        self.assertEqual([item['code'] for item in result['limitations']], ['record_limit'])

    def test_limitations_are_bounded_and_summarize_omissions(self):
        result = self.parse(b'bad\n' * 1000)
        self.assertEqual(result['records_seen'], 1000)
        self.assertLessEqual(len(result['limitations']), 200)
        self.assertEqual(result['limitations'][-1]['code'], 'additional_limitations')
        self.assertGreater(result['limitations'][-1]['count'], 0)

    def test_input_scan_limit_withholds_tail_and_reports_partial_evidence(self):
        raw = GOOD + b'x' * (16 * 1024 * 1024) + b'\n' + GOOD
        result = self.parse(raw)
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['records_seen'], 2)
        self.assertEqual(len(result['records']), 1)
        self.assertTrue(any(item['code'] == 'input_byte_limit' for item in result['limitations']))

    def test_invalid_resource_limits_are_rejected_without_coercion(self):
        for limits in ({'max_records':-1}, {'max_records':True}, {'max_records':100001},
                       {'max_record_bytes':0}, {'max_record_bytes':True},
                       {'max_record_bytes':16 * 1024 * 1024 + 1}):
            with self.subTest(limits=limits), self.assertRaises(ValueError):
                self.parse(**limits)

    def test_empty_file_and_bom_only_are_empty(self):
        for data in (b'', b'\xef\xbb\xbf'):
            with self.subTest(data=data):
                result = self.parse(data)
                self.assertEqual(result['status'], 'empty')
                self.assertEqual(result['records_seen'], 0)
                self.assertEqual(self.parse(data, max_records=0)['status'], 'empty')

    def test_unknown_and_exception_context_are_only_observations(self):
        result = self.parse(b'04:05.123456-0,NEW_EVENT,0\n04:06.000000-500000,EXCPCNTX,1,SrcName=CALL\n')
        self.assertEqual([row['event'] for row in result['records']], ['NEW_EVENT','EXCPCNTX'])
        for row in result['records']:
            self.assertIsNone(row['start_timestamp_utc'])
            self.assertNotIn('kind', row)

    def test_invalid_time_integer_or_property_grammar_does_not_coerce(self):
        for raw in (b'60:05.123456-1,CALL,0,k=v\n', b'04:60.123456-1,CALL,0,k=v\n',
                    b'04:05.123-1,CALL,0,k=v\n', b'04:05.123456--1,CALL,0,k=v\n',
                    b'04:05.123456-1,CALL,-1,k=v\n', b'04:05.123456-1,CALL,0,missing\n',
                    b'04:05.123456-1,CALL,0,k=v,\n'):
            with self.subTest(raw=raw):
                self.assertEqual(self.parse(raw)['status'], 'invalid')


if __name__ == '__main__':
    unittest.main()
