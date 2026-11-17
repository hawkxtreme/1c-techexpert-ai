import importlib
import importlib.util
import unittest


class ApdexTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.apdex'))
        self.apdex=importlib.import_module('src.techexpert.apdex').calculate

    def sample(self,i,duration,success=True,**extra):
        return dict(id=str(i),operation='load',started_at='2026-11-16T09:00:00+03:00',
                    duration_seconds=duration,success=success,**extra)

    def test_boundaries_failures_and_denominator(self):
        rows=[self.sample(i,t) for i,t in enumerate((0,5,5.01,20,20.01))]+[self.sample(5,0,False)]
        r=self.apdex(rows,5)
        self.assertEqual((r['satisfied'],r['tolerating'],r['frustrated'],r['total']),(2,2,2,6))
        self.assertEqual(r['score'],.5)
        self.assertEqual(r['target_seconds'],5)

    def test_empty_unknown_and_invalid_do_not_become_zero_or_success(self):
        self.assertIsNone(self.apdex([],5)['score'])
        r=self.apdex([self.sample(1,None)],5)
        self.assertIsNone(r['score']);self.assertEqual(r['unknown'],1)
        self.assertEqual(self.apdex([self.sample(1,None,False)],5)['frustrated'],1)
        for value in (0,-1,True,float('nan'),float('inf')):
            with self.assertRaises(ValueError):self.apdex([],value)

    def test_different_operations_require_selection_and_window_is_half_open(self):
        rows=[self.sample(1,1),dict(self.sample(2,20),operation='other')]
        with self.assertRaises(ValueError):self.apdex(rows,5)
        self.assertEqual(self.apdex(rows,5,operation='load')['total'],1)
        self.assertEqual(self.apdex(rows,5,operation='load',start='2026-11-16T06:00:00Z',end='2026-11-16T06:00:01Z')['total'],1)
        self.assertEqual(self.apdex(rows,5,operation='load',end='2026-11-16T06:00:00Z')['total'],0)
        with self.assertRaises(ValueError):self.apdex(rows,5,operation='load',start='2026-11-16T09:00:00')

    def test_duplicate_ids_and_invalid_types_cannot_inflate_quality(self):
        sample=self.sample(1,1)
        with self.assertRaises(ValueError):self.apdex([sample,sample],5)
        for update in (dict(duration_seconds=-1),dict(duration_seconds=True),dict(success='yes'),dict(duration_seconds=float('inf'))):
            with self.assertRaises(ValueError):self.apdex([dict(sample,**update)],5)

    def test_large_finite_integer_duration_is_classified_without_float_conversion_overflow(self):
        result=self.apdex([self.sample(1,10**400)],5)
        self.assertEqual(result['frustrated'],1);self.assertEqual(result['score'],0)
        with self.assertRaises(ValueError):self.apdex([],10**400)

    def test_shared_measurement_validation_preserves_rows_and_does_not_choose_an_apdex_target(self):
        api = importlib.import_module('src.techexpert.apdex')
        self.assertTrue(hasattr(api, 'validated_records'), 'Shared timed-operation validation is missing')
        rows = [self.sample(1, 1), dict(self.sample(2, None), operation='other')]
        valid, operations = api.validated_records(rows)
        self.assertEqual(operations, {'load', 'other'})
        self.assertEqual([row for row, _, _ in valid], rows)
        self.assertEqual([value for _, _, value in valid], [1, None])
        self.assertEqual(valid[0][1].isoformat(), '2026-11-16T06:00:00+00:00')
        with self.assertRaises(ValueError):
            api.validated_records([rows[0], rows[0]])


if __name__=='__main__':unittest.main()
