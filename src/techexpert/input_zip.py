"""ZIP metadata preview before decompression; never extract archive-supplied paths."""
import io
from pathlib import Path
import stat
import struct
import zipfile
import zlib

from . import input_files as files
from .inputs import InputError

MAX_CENTRAL_BYTES=256*1024


def catalogue(stream,bound):
    stream.seek(0,2);size=stream.tell()
    if size>files.MAX_ARCHIVE_BYTES:raise InputError('archive byte limit')
    stream.seek(max(0,size-65557));tail=stream.read(65557);offset=tail.rfind(b'PK\x05\x06')
    if offset<0 or len(tail)-offset<22:raise InputError('unsupported ZIP end record')
    _,disk,cd_disk,on_disk,count,cd_size,cd_offset,comment=struct.unpack_from('<4s4H2LH',tail,offset)
    end=size-len(tail)+offset
    if (disk or cd_disk or on_disk!=count or count>files.MAX_ENTRIES or cd_size>MAX_CENTRAL_BYTES
        or cd_offset+cd_size!=end or offset+22+comment!=len(tail)
        or count==0xffff or cd_offset==0xffffffff):raise InputError('unsupported or excessive ZIP directory')
    # stdlib follows this locator even when all classic fields are ordinary,
    # allowing an embedded ZIP64 record to replace the preflight size/offset.
    if end>=20:
        stream.seek(end-20)
        if stream.read(4)==b'PK\x06\x07':raise InputError('ZIP64 locator is outside the supported bounded profile')
    stream.seek(0)
    try:
        with zipfile.ZipFile(stream) as archive:
            entries=archive.infolist()
            if len(entries)!=count:raise InputError('ZIP directory count mismatch')
            names={};members=[];total=0
            for info in entries:
                directory=info.is_dir();name=info.filename[:-1] if directory else info.filename
                parts=files.name_parts(name);key=files.name_key(name)
                if info.orig_filename!=info.filename or key in names:raise InputError('duplicate or ambiguous ZIP member')
                if len(parts)-1>bound['max_depth']:raise InputError('ZIP directory depth limit')
                mode=stat.S_IFMT(info.external_attr>>16)
                if mode not in (0,stat.S_IFDIR if directory else stat.S_IFREG):raise InputError('special ZIP entry unsupported')
                if info.flag_bits&(1|0x40|0x2000) or info.compress_type not in (zipfile.ZIP_STORED,zipfile.ZIP_DEFLATED):raise InputError('encrypted or unsupported ZIP compression')
                extra=info.extra
                while extra:
                    if len(extra)<4:raise InputError('invalid ZIP extra field')
                    tag,n=struct.unpack_from('<HH',extra)
                    if n>len(extra)-4 or tag==1:raise InputError('unsupported ZIP extra field')
                    extra=extra[4+n:]
                names[key]=directory
                if directory:
                    if info.file_size:raise InputError('ZIP directory contains payload')
                    continue
                if name.casefold().endswith(files.ARCHIVE_SUFFIXES):raise InputError('nested archive input unsupported')
                if info.file_size>bound['max_file_bytes'] or len(members)>=bound['max_files']:raise InputError('ZIP member size or count limit')
                total+=info.file_size
                if total>bound['max_total_bytes']:raise InputError('ZIP expanded byte limit')
                members.append(dict(relative_path=name,bytes=info.file_size,crc32=info.CRC,importable=Path(name).suffix.casefold() not in files.CODE_SUFFIXES))
            for name in names:
                parts=name.split('/')
                if any(names.get('/'.join(parts[:i])) is False for i in range(1,len(parts))):raise InputError('ZIP file/directory collision')
            return sorted(members,key=lambda m:m['relative_path'])
    except (zipfile.BadZipFile,NotImplementedError,RuntimeError,UnicodeError,struct.error) as exc:raise InputError('invalid or unsupported ZIP metadata') from exc


def inspect(path,bound):
    # Snapshot raw container bytes only; metadata parsing never opens a member.
    data,identity=files.read(path,files.MAX_ARCHIVE_BYTES,keep=True)
    return catalogue(io.BytesIO(data),bound),identity


def selected(path,bound,identity,names):
    data,_=files.read(path,files.MAX_ARCHIVE_BYTES,keep=True,expected=identity)
    try:
        with zipfile.ZipFile(io.BytesIO(data)) as archive:
            for name,expected in names:
                info=archive.getinfo(name);pieces=[];count=0;crc=0
                # ZipExtFile stops at the *declared* expanded size. Validate
                # the whole compressed stream independently so a prefix CRC
                # cannot disguise extra expanded payload.
                with archive.open(name):pass  # Local/central name and overlap checks.
                offset=info.header_offset
                if offset<0 or offset+30>len(data):raise InputError('invalid ZIP local header')
                header=struct.unpack_from('<4s5H3L2H',data,offset)
                if header[2]!=info.flag_bits or header[3]!=info.compress_type:raise InputError('ZIP local/central method or flags conflict')
                start=offset+30+header[-2]+header[-1];end=start+info.compress_size
                if end>archive.start_dir or start>end:raise InputError('ZIP compressed payload exceeds container')
                decoder=zlib.decompressobj(-15) if info.compress_type==zipfile.ZIP_DEFLATED else None
                def append(chunk):
                    nonlocal count,crc
                    count+=len(chunk)
                    if count>expected or count>bound['max_file_bytes']:raise InputError('ZIP payload exceeds declared limit')
                    pieces.append(chunk);crc=zlib.crc32(chunk,crc)
                for position in range(start,end,65536):
                    compressed=data[position:min(end,position+65536)]
                    if decoder is None:append(compressed);continue
                    while compressed:
                        append(decoder.decompress(compressed,min(65536,expected+1-count)))
                        if decoder.unused_data:raise InputError('trailing ZIP compressed payload')
                        compressed=decoder.unconsumed_tail
                if count!=expected or crc!=info.CRC or decoder is not None and not decoder.eof:raise InputError('ZIP payload size or CRC mismatch')
                yield name,b''.join(pieces)
    except (zipfile.BadZipFile,NotImplementedError,RuntimeError,EOFError,zlib.error,struct.error) as exc:raise InputError('ZIP member integrity mismatch') from exc
