"""Finite SFTPv3 codec (filexfer-02); no SSH, shell or filesystem access."""
import struct

from .inputs import InputError

MAX_PACKET=128*1024
REQUESTS=frozenset((3,4,5,7,8,11,12,16))


def u32(value):
    if type(value) is not int or not 0<=value<2**32:raise InputError('invalid SFTP uint32')
    return struct.pack('>I',value)


def u64(value):
    if type(value) is not int or not 0<=value<2**64:raise InputError('invalid SFTP uint64')
    return struct.pack('>Q',value)


def string(value):
    if type(value) is str:
        try:value=value.encode('utf-8')
        except UnicodeError as exc:raise InputError('unsupported SFTP path encoding') from exc
    if type(value) is not bytes or len(value)>65536:raise InputError('SFTP string exceeds byte limit')
    return u32(len(value))+value


def frame(payload):
    if type(payload) is not bytes or not 1<=len(payload)<=MAX_PACKET:raise InputError('SFTP packet exceeds limit')
    return u32(len(payload))+payload


def request(operation,identifier,payload):
    if type(operation) is not int or operation not in REQUESTS:raise InputError('unsupported SFTP operation')
    return frame(bytes([operation])+u32(identifier)+payload)


class Reader:
    def __init__(self,raw):
        if type(raw) is not bytes or len(raw)>MAX_PACKET:raise InputError('invalid SFTP response size')
        self.raw=raw;self.at=0

    def take(self,count):
        if type(count) is not int or count<0 or self.at+count>len(self.raw):raise InputError('truncated SFTP response')
        raw=self.raw[self.at:self.at+count];self.at+=count;return raw

    def uint32(self):return struct.unpack('>I',self.take(4))[0]
    def uint64(self):return struct.unpack('>Q',self.take(8))[0]

    def bytes(self,limit=65536):
        count=self.uint32()
        if count>limit:raise InputError('SFTP field exceeds byte limit')
        return self.take(count)

    def text(self,limit=4096):
        try:return self.bytes(limit).decode('utf-8')
        except UnicodeError as exc:raise InputError('unsupported SFTP UTF8 field') from exc

    def attrs(self):
        flags=self.uint32()
        if flags&~0x8000000F:raise InputError('unsupported SFTP attribute flags')
        result={}
        if flags&1:result['size']=self.uint64()
        if flags&2:result.update(uid=self.uint32(),gid=self.uint32())
        if flags&4:result['permissions']=self.uint32()
        if flags&8:result.update(atime=self.uint32(),mtime=self.uint32())
        if flags&0x80000000:
            count=self.uint32()
            if count>16:raise InputError('too many SFTP extended attributes')
            for _ in range(count):self.bytes(16384);self.bytes(16384)
        return result

    def status(self):
        code=self.uint32();self.bytes(8192);self.bytes(128)
        return code

    def end(self):
        if self.at!=len(self.raw):raise InputError('unexpected trailing SFTP response fields')
