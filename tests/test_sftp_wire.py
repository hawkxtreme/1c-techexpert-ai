"""Finite SFTPv3 response framing; no transport side effects."""
import stat
import struct
import unittest

from src.techexpert.inputs import InputError
from src.techexpert import sftp_wire as wire


class SftpWireTests(unittest.TestCase):
    def test_strings_and_attributes_keep_size_permissions_and_seconds_explicit(self):
        raw=wire.u32(15)+wire.u64(7)+wire.u32(1)+wire.u32(2)+wire.u32(stat.S_IFREG|0o600)+wire.u32(10)+wire.u32(20)
        reader=wire.Reader(raw)
        self.assertEqual(reader.attrs(),dict(size=7,uid=1,gid=2,permissions=stat.S_IFREG|0o600,atime=10,mtime=20))
        reader.end()
        text=wire.Reader(wire.string('ТЖ/one.log'))
        self.assertEqual(text.text(),'ТЖ/one.log')

    def test_rejects_short_oversized_unknown_and_unterminated_fields(self):
        for raw in (b'',wire.u32(0xFFFFFFFF),wire.u32(16),wire.u32(1)+b'xx'):
            with self.subTest(raw=raw),self.assertRaises(InputError):wire.Reader(raw).attrs()
        with self.assertRaises(InputError):wire.Reader(wire.u32(999999)).bytes()
        with self.assertRaises(InputError):wire.Reader(wire.string(b'\xff')).text()
        with self.assertRaises(InputError):wire.Reader(b'extra').end()

    def test_extended_attributes_are_bounded_and_ignored_without_execution(self):
        reader=wire.Reader(wire.u32(0x80000000)+wire.u32(1)+wire.string('vendor')+wire.string('value'))
        self.assertEqual(reader.attrs(),{})
        reader.end()
        with self.assertRaises(InputError):wire.Reader(wire.u32(0x80000000)+wire.u32(100000)).attrs()

    def test_only_fixed_read_only_request_types_can_be_framed(self):
        self.assertEqual(set(wire.REQUESTS),{3,4,5,7,8,11,12,16})
        for operation in (6,9,10,13,14,15,17,18,19,20,200):
            with self.subTest(operation=operation),self.assertRaises(InputError):wire.request(operation,1,b'')
        self.assertEqual(wire.request(7,1,wire.string('/logs'))[4],7)
        with self.assertRaises(InputError):wire.request(7,1,b'x'*200000)

    def test_status_is_bounded_and_failure_text_is_not_treated_as_an_instruction(self):
        reader=wire.Reader(wire.u32(3)+wire.string('permission denied')+wire.string('en'))
        self.assertEqual(reader.status(),3)
        reader.end()


if __name__=='__main__':unittest.main()
