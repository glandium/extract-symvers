#!/usr/bin/env python

import gzip
import struct
import sys
import StringIO
from optparse import OptionParser

# gzip.GzipFile is being unhelpful trying to read another gzip
# after the first stream is finished, and preventing the first
# stream to be read at all.
def wrap_read_gzip_header(self):
    if self.fileobj.tell() != 0:
        raise EOFError, "Reached EOF"
    _read_gzip_header(self)

_read_gzip_header = gzip.GzipFile._read_gzip_header
gzip.GzipFile._read_gzip_header = wrap_read_gzip_header

ENDIANNESS = {
  'little': '<',
  'le': '<',
  'big': '>',
  'be': '>'
}

PTR = {
  32: 'L',
  64: 'Q'
}

EXPORT_TYPE = [
  'EXPORT_SYMBOL',
  'EXPORT_SYMBOL_GPL',
  'EXPORT_SYMBOL_GPL_FUTURE'
]

class KernelImage(object):
    def __init__(self, file, base, endian, ptr_size):
        with open(file, 'rb') as f:
            kernel = f.read()
            # Try to find a gzip header
            index = kernel.find(b'\x1f\x8b\x08')
            # If one is found, and it's in the first 1% of the file, the kernel
            # is very likely to be a zImage. Uncompressed kernel images may
            # contain what looks like a gzip header much later.
            if index != -1 and float(index) / len(kernel) < 0.01:
                kernel = gzip.GzipFile(fileobj=StringIO.StringIO(kernel[index:])).read()
            self.kernel = kernel
            self.size = len(self.kernel)
            self.base = base
            self.ptr_format = ENDIANNESS[endian] + PTR[ptr_size]
            self.endian = ENDIANNESS[endian]
            self.ptr = PTR[ptr_size]
            self.ptr_bytes = ptr_size / 8

    def read_ptr(self, offset):
        return struct.unpack(self.endian + self.ptr, self.kernel[offset:offset + self.ptr_bytes])[0]

    def read_uint(self, offset):
        return struct.unpack(self.endian + 'I', self.kernel[offset:offset + 4])[0]

    def is_valid_ptr(self, ptr):
        offset = ptr - self.base
        return offset >= 0 and offset <= self.size

    def read_str(self, offset):
        return self.kernel[offset:self.kernel.index('\0',offset)]

    def scan_symsearch(self):
        offset = 0
        while offset < self.size - self.ptr_bytes:
            try:
                symsearch = {}
                off = offset
                for i in [0, 1, 2]:
                    ptrs = {}
                    for j in ['start', 'stop', 'crcs']:
                        p = self.read_ptr(off)
                        if not self.is_valid_ptr(p):
                            raise ScanFailException()
                        ptrs[j] = p
                        off += self.ptr_bytes

                    license = self.read_uint(off)
                    if license != i:
                        raise ScanFailException()
                    off += 4
                    unused = self.read_uint(off)
                    if unused != 0:
                        raise ScanFailException()
                    off += 4
                    symsearch[EXPORT_TYPE[i]] = ptrs

                return symsearch
            except ScanFailException:
                pass
            offset += self.ptr_bytes

    def symbols(self):
        symsearch = self.scan_symsearch()
        for t, s in symsearch.items():
            crc_off = s['crcs'] - self.base
            for offset in range(s['start'] - self.base, s['stop'] - self.base, self.ptr_bytes * 2):
                value = self.read_ptr(offset)
                name_ptr = self.read_ptr(offset + self.ptr_bytes)
                crc = self.read_uint(crc_off)
                yield self.read_str(name_ptr - self.base), crc, t
                crc_off += 4

class ScanFailException(Exception):
    pass

def main():
    parser = OptionParser()
    parser.add_option('-B', '--base-address', dest='base', metavar='ADDRESS',
        help='Base address (in hex) where the kernel is loaded [required]')
    parser.add_option('-e', '--endian', dest='endian', metavar='ENDIANNESS',
        choices=['big', 'little', 'be', 'le'], default='le',
        help='Endianness (big|little|be|le) ; defaults to little/le')
    parser.add_option('-b', '--bits', dest='bits', metavar='ADDRESS',
        choices=['32', '64'], default='32',
        help='Size of pointers in bits ; defaults to 32')

    (options, args) = parser.parse_args()
    if not options.base:
        print >>sys.stderr, "Missing option: -B/--base-address"
	exit(1)

    if len(args) != 1:
        print >>sys.stderr, "Need exactly one kernel file"
        exit(1)

    kernel = KernelImage(args[0], int(options.base, 16), options.endian, int(options.bits))
    for s, crc, t in kernel.symbols():
        print "0x%08x\t%s\tvmlinux\t%s" % (crc, s, t)

if __name__ == '__main__':
    main()
