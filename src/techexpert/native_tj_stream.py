"""Bounded binary framing; quoted newlines never become recovery boundaries."""
from itertools import chain,islice

MAX_CHUNK_BYTES=65536
BOM=b'\xef\xbb\xbf'


class Frames:
    def __init__(self,stream,*,chunk_size,max_input_bytes,max_record_bytes):
        self.stream=stream;self.chunk_size=chunk_size;self.limit=max_input_bytes;self.record_limit=max_record_bytes
        self.seen=0;self.eof=False;self.start=0;self.prefix=b'';self._bytes_iterator=self._bytes()

    def _read(self):
        size=min(self.chunk_size,self.limit+1-self.seen)
        if size<=0:return b''
        data=self.stream.read(size)
        if not isinstance(data,bytes) or len(data)>size:raise ValueError('Binary stream returned invalid bounded data')
        self.seen+=len(data);self.eof=not data
        return data

    def _bytes(self):
        consumed=0
        while not self.eof and self.seen<=self.limit:
            data=self._read()
            if not data:break
            allowed=min(len(data),self.limit-consumed)
            yield from data[:allowed]
            consumed+=allowed

    def initialize(self):
        self.prefix=bytes(islice(self._bytes_iterator,3))
        if self.prefix==BOM:self.start=3;self.prefix=b''

    def finish(self):
        """Read bounded remaining bytes without treating them as record attempts."""
        self._bytes_iterator.close()
        while not self.eof and self.seen<self.limit+1:self._read()

    @property
    def scan_size(self):return min(self.seen,self.limit)

    def __iter__(self):
        start=position=self.start;first_line=line=1
        section,token_start,quote,pending_quote,commas='prefix',True,None,False,0
        payload=bytearray();oversized=False
        for char in chain(self.prefix,self._bytes_iterator):
            if not oversized:
                if len(payload)<self.record_limit:payload.append(char)
                else:payload.clear();oversized=True
            outside=quote is None
            if quote is not None:
                if pending_quote:
                    pending_quote=False
                    if char!=quote:quote=None;outside=True
                elif char==quote:pending_quote=True
                elif char==10:line+=1
            if outside:
                if char==10:
                    yield dict(byte_start=start,byte_end=position+1,line=first_line,end_line=line,terminated=True,open_quote=False,raw=None if oversized else bytes(payload))
                    start=position+1;first_line=line+1;line+=1;payload.clear();oversized=False
                    section,token_start,quote,pending_quote,commas='prefix',True,None,False,0
                elif token_start and char in (34,39):quote=char;token_start=False
                elif section=='prefix':
                    if char==44:
                        commas+=1;token_start=True
                        if commas==3:section='name'
                    else:token_start=False
                elif section=='name':
                    if char==61:section,token_start='value',True
                    elif char==44:token_start=True
                    else:token_start=False
                elif char==44:section,token_start='name',True
                else:token_start=False
            position+=1
        if start<position:
            yield dict(byte_start=start,byte_end=position,line=first_line,end_line=line,terminated=False,open_quote=quote is not None and not pending_quote,raw=None if oversized else bytes(payload))
