"""Investigation/source transfer reservations survive failures and serialize callers."""
from pathlib import Path
import tempfile
import unittest

from src.techexpert import remote_budget as budgets
from src.techexpert import operation_state as fs
from src.techexpert.inputs import InputError


def settings(root):
    known=Path(root)/'known';known.write_text('example ssh-ed25519 SYNTHETIC\n',encoding='ascii')
    return dict(investigation_id='a'*32,revision=1,
        sources=[dict(id='tj',connection=dict(host='reader@example.test',port=22,known_hosts_file=str(known),node='reported',root='/logs'),
            max_connections=2,max_protocol_bytes=65536,max_retained_bytes=32768)],
        max_connections=3,max_protocol_bytes=131072,max_retained_bytes=65536)


class RemoteBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp=tempfile.TemporaryDirectory();self.addCleanup(self.temp.cleanup)
        self.root=Path(self.temp.name);self.state=self.root/'state';self.plan=budgets.normalize(**settings(self.root))

    def reserve(self,key='1'*64,source='tj',protocol=16384,retained=1000,plan=None):
        return budgets.reserve(self.state,self.plan if plan is None else plan,source,key,protocol,retained)

    def test_conservative_charge_is_immutable_and_same_key_never_connects_again(self):
        with self.reserve() as charge:self.assertEqual(charge['reserved_protocol_bytes'],16384)
        with self.assertRaisesRegex(InputError,'already reserved'):
            with self.reserve():pass
        with self.reserve('2'*64):pass
        with self.assertRaisesRegex(InputError,'connection'):
            with self.reserve('3'*64):pass

    def test_failure_keeps_full_reservation_and_total_source_limits(self):
        with self.assertRaises(RuntimeError):
            with self.reserve(protocol=32768,retained=20000):raise RuntimeError('interrupted connection')
        with self.assertRaisesRegex(InputError,'retained'):
            with self.reserve('2'*64,retained=20000):pass
        with self.assertRaisesRegex(InputError,'protocol'):
            with self.reserve('2'*64,protocol=40000):pass

    def test_changed_investigation_plan_cannot_reset_its_spent_budget(self):
        with self.reserve():pass
        changed=dict(self.plan,max_connections=4)
        with self.assertRaisesRegex(InputError,'configuration'):
            with self.reserve('2'*64,plan=changed):pass

    def test_investigation_kernel_lock_prevents_parallel_transfer(self):
        with self.reserve():
            with self.assertRaisesRegex(InputError,'writer'):
                with self.reserve('2'*64):pass

    def test_connection_kernel_lock_is_shared_between_investigations(self):
        other=dict(self.plan,investigation_id='b'*32)
        with self.reserve():
            with self.assertRaisesRegex(InputError,'writer'):
                with self.reserve('2'*64,plan=other):pass

    def test_malformed_or_corrupt_charge_is_unknown_not_zero(self):
        with self.reserve() as charge:path=Path(charge['reservation_file'])
        path.write_bytes(b'{')
        with self.assertRaises(InputError):
            with self.reserve('2'*64):pass

    def test_source_and_overall_budgets_are_independent(self):
        one=dict(self.plan['sources'][0]);two=dict(one,id='jr',connection=dict(one['connection'],root='/journals'))
        plan=dict(self.plan,sources=[one,two],max_retained_bytes=1000)
        with self.reserve(plan=plan):pass
        with self.assertRaisesRegex(InputError,'retained'):
            with self.reserve('2'*64,source='jr',plan=plan):pass

    def test_missing_charge_or_entire_charge_directory_is_unknown_not_a_budget_reset(self):
        for directory in (False,True):
            with self.subTest(directory=directory):
                state=self.root/('missing-dir' if directory else 'missing-file')
                limited=dict(self.plan,max_connections=1)
                with budgets.reserve(state,limited,'tj','1'*64,16384,1000) as charge:path=Path(charge['reservation_file'])
                path.unlink()
                if directory:path.parent.rmdir()
                with self.assertRaises(InputError):
                    with budgets.reserve(state,limited,'tj','2'*64,16384,1000):pass

    def test_lost_authority_index_does_not_reinitialize_existing_history(self):
        with self.reserve():pass
        index=self.state/'remote-budget-authority/index.json'
        self.assertTrue(index.exists(),'Transfer history needs an authority outside the replaceable charge directory')
        index.unlink()
        with self.assertRaises(InputError):
            with self.reserve('2'*64):pass

    def test_missing_registered_ledger_or_inventory_is_unknown(self):
        for member in ('ledger','inventory'):
            with self.subTest(member=member):
                state=self.root/member
                with budgets.reserve(state,self.plan,'tj','1'*64,16384,1000) as charge:path=Path(charge['reservation_file'])
                missing=path.parent.parent if member=='ledger' else path.parent.parent/'inventory.json'
                missing.rename(state/'retained-original')
                with self.assertRaises(InputError):
                    with budgets.reserve(state,self.plan,'tj','2'*64,16384,1000):pass

    def test_interrupted_initialization_or_charge_write_cannot_reopen_allowance(self):
        from unittest.mock import patch
        for phase in ('configuration.json','2'*64+'.json'):
            with self.subTest(phase=phase):
                state=self.root/phase;original=budgets._new
                def interrupted(path,value):
                    if path.name==phase:raise OSError('simulated lost write')
                    return original(path,value)
                with patch.object(budgets,'_new',side_effect=interrupted):
                    with self.assertRaises(OSError):
                        with budgets.reserve(state,self.plan,'tj','2'*64,16384,1000):pass
                with self.assertRaises(InputError):
                    with budgets.reserve(state,self.plan,'tj','3'*64,16384,1000):pass


if __name__=='__main__':unittest.main()
