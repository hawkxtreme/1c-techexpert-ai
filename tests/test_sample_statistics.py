"""Descriptive observed-value statistics with explicit method and denominator."""
import importlib
import math
import unittest


class SampleStatisticsTests(unittest.TestCase):
    def setUp(self):
        self.assertIsNotNone(importlib.util.find_spec('src.techexpert.sample_statistics'),
                             'Bounded sample statistics are not implemented')
        self.api = importlib.import_module('src.techexpert.sample_statistics')

    def test_even_sample_has_median_robust_spread_and_explicit_percentile_method(self):
        result = self.api.describe_values([1, 2, 3, 4])
        self.assertEqual(result['count'], 4)
        self.assertEqual(result['median'], 2.5)
        self.assertEqual((result['minimum'], result['maximum'], result['range']), (1, 4, 3))
        self.assertEqual(result['median_absolute_deviation'], 1)
        self.assertEqual(result['interquartile_range'], 1.5)
        for key, expected in {'25': 1.75, '50': 2.5, '75': 3.25, '90': 3.7, '95': 3.85}.items():
            self.assertAlmostEqual(result['percentiles']['values'][key], expected)
        self.assertEqual(result['percentiles']['sample_size'], 4)
        self.assertEqual(result['percentiles']['method'], 'linear_between_ordered_positions_(n-1)*p')
        self.assertFalse(result['population_inference'])

    def test_missing_values_never_become_zero_or_disappear_from_the_denominator(self):
        result = self.api.describe_values([None, 0, 5, None])
        self.assertEqual((result['supplied_count'], result['count'], result['missing_count']), (4, 2, 2))
        self.assertEqual(result['status'], 'partial')
        self.assertEqual(result['median'], 2.5)

    def test_empty_and_all_unknown_have_no_center_spread_or_percentile(self):
        for values in ([], [None, None]):
            with self.subTest(values=values):
                result = self.api.describe_values(values)
                self.assertEqual(result['count'], 0)
                self.assertIsNone(result['median'])
                self.assertIsNone(result['range'])
                self.assertIsNone(result['median_absolute_deviation'])
                self.assertTrue(all(v is None for v in result['percentiles']['values'].values()))

    def test_one_observation_is_only_its_own_observed_distribution(self):
        result = self.api.describe_values([7])
        self.assertEqual(result['median'], 7)
        self.assertEqual(result['range'], 0)
        self.assertEqual(result['median_absolute_deviation'], 0)
        self.assertTrue(all(v == 7 for v in result['percentiles']['values'].values()))
        self.assertFalse(result['population_inference'])

    def test_unfavorable_extremes_are_retained_and_inputs_are_not_mutated(self):
        values = [10000, 0, 2, 1, 3]
        before = list(values)
        result = self.api.describe_values(values)
        self.assertEqual(values, before)
        self.assertEqual(result['count'], 5)
        self.assertEqual(result['median'], 2)
        self.assertEqual(result['maximum'], 10000)
        self.assertGreater(result['percentiles']['values']['95'], 1000)
        self.assertEqual(result['outlier_removal'], 'none')

    def test_invalid_numbers_and_work_bounds_are_rejected(self):
        for bad in (True, False, -1, float('nan'), float('inf'), -float('inf'), 10**400, '1', [], {}):
            with self.subTest(value=repr(bad)), self.assertRaises(ValueError):
                self.api.describe_values([1, bad])
        with self.assertRaises(ValueError):
            self.api.describe_values([1] * 100001)
        for bad in (None, (), {}, '1'):
            with self.assertRaises(ValueError):
                self.api.describe_values(bad)
        edge = self.api.describe_values([31536000, 0])
        self.assertTrue(math.isfinite(edge['percentiles']['values']['95']))


if __name__ == '__main__':
    unittest.main()
