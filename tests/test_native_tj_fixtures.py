"""Golden excerpts captured from an isolated local 1C 8.3.27.1989 process."""
import hashlib
import json
from pathlib import Path
import unittest

from src.techexpert.native_tj import parse_tj, validate_profile

ROOT=Path(__file__).resolve().parent/'fixtures/native-tj'


class RealNativeFixtureTests(unittest.TestCase):
    def test_real_hourly_creation_completion_is_not_a_job_boundary(self):
        raw=(ROOT/'folders-minute.txt').read_bytes()
        profile=dict(format='1c-tj-text-v1',platform_version='8.3.27.1989',encoding='utf-8',
                     placement='folders',timestamp_format='minute',rotation_hours=1,
                     file_hour='2026-11-16T08:00:00+03:00')
        result=parse_tj(raw,validate_profile(profile,'folders-minute.txt'))
        self.assertEqual(result['status'],'parsed')
        self.assertEqual(len(result['records']),1)
        row=result['records'][0]
        self.assertEqual(row['event'],'PROC')
        self.assertEqual(row['duration_us'],13062000)
        self.assertEqual(row['properties']['Finish'],'ib creation success')
        self.assertEqual(row['timestamp_utc'],'2026-11-16T05:20:39.674000+00:00')
        self.assertIsNone(row['start_timestamp_utc'])

    def test_real_iso_query_preserves_multiline_sql_and_microseconds(self):
        raw=(ROOT/'plain-iso.txt').read_bytes()
        profile=dict(format='1c-tj-text-v1',platform_version='8.3.27.1989',encoding='utf-8',
                     placement='plain',timestamp_format='iso',utc_offset='+03:00')
        result=parse_tj(raw,validate_profile(profile,'plain-iso.txt'))
        self.assertEqual(result['status'],'parsed')
        self.assertEqual([r['event'] for r in result['records']],['DBV8DBEng','PROC'])
        query,completed=result['records']
        self.assertEqual(query['duration_us'],1)
        self.assertEqual(query['timestamp_utc'],'2026-11-16T05:25:43.948080+00:00')
        self.assertEqual(query['properties']['Sql'].splitlines()[1],'FROM v8users')
        self.assertEqual((query['line'],query['end_line']),(1,3))
        self.assertEqual(completed['duration_us'],4890000)
        self.assertEqual(completed['line'],4)
        self.assertIsNone(completed['start_timestamp_utc'])

    def test_public_fixture_hashes_and_capture_scope(self):
        passport=json.loads((ROOT/'passport.json').read_text(encoding='utf-8'))
        self.assertFalse(passport['sc01_job_reproduced'])
        for fixture in passport['fixtures']:
            raw=(ROOT/fixture['file']).read_bytes()
            self.assertEqual(hashlib.sha256(raw).hexdigest(),fixture['sha256'])
            self.assertEqual(len(raw),fixture['bytes'])


if __name__=='__main__':
    unittest.main()
