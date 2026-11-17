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
        self.close()
        while not self.eof and self.seen<self.limit+1:self._read()

    def close(self):
        """Release generator buffers without reading or closing caller-owned I/O."""
        self._bytes_iterator.close()

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


def summarize_frames(stream, *, size, max_records=100000, max_record_bytes=262144, point=None):
    """Bounded framing only; a terminated frame is not an accepted native event.

    The caller owns whole-source hash verification, including unframed bytes.
    """
    if (type(size) is not int or not 0 <= size <= 16*1024**2
        or type(max_records) is not int or not 0 <= max_records <= 100000
        or type(max_record_bytes) is not int or not 1 <= max_record_bytes <= 16*1024**2
        or point is not None and (type(point) is not int or not 0 <= point < size)):
        raise ValueError('invalid framing summary bounds')
    frames = Frames(stream, chunk_size=65536, max_input_bytes=size, max_record_bytes=max_record_bytes)
    frames.initialize()
    cursor = terminated = frames.start
    tail = selected = None
    count = 0
    iterator = iter(frames)
    try:
        for frame in islice(iterator, max_records):
            count += 1
            cursor = frame['byte_end']
            if frame['terminated']:
                terminated = cursor
            else:
                tail = dict(byte_start=frame['byte_start'], byte_end=cursor, bytes=cursor-frame['byte_start'], open_quote=frame['open_quote'])
            if point is not None and frame['byte_start'] <= point < cursor:
                selected = {key: frame[key] for key in ('byte_start', 'byte_end', 'line', 'end_line', 'terminated', 'open_quote')}
    finally:
        iterator.close()
        frames.close()
    result = dict(boundary_basis='quote_aware_frame_not_valid_event', terminated_prefix_bytes=terminated,
        incomplete_tail=tail, complete_scan=cursor == size, unframed_bytes=size-cursor,
        frame_attempts=count, max_records=max_records, max_record_bytes=max_record_bytes)
    if point is not None:
        result['point_frame'] = selected
    return result
