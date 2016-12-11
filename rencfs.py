#!/usr/bin/python

# Copyright (c) 2016, Jan Varho
#
# Permission to use, copy, modify, and/or distribute this software for any
# purpose with or without fee is hereby granted, provided that the above
# copyright notice and this permission notice appear in all copies.
#
# THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
# WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
# MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
# ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
# WHATSOEVER RESULTING FROM LOSS OF USE, DATA OR PROFITS, WHETHER IN AN
# ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING OUT OF
# OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.

'''rencfs

Reverse-encrypting filesystem based on FUSE
'''

import errno
import hmac
import os

from argparse import ArgumentParser, SUPPRESS
from base64 import b16encode
from hashlib import sha256

from Crypto.Cipher import AES
from Crypto.Util import Counter

from fuse import FUSE, FuseOSError, Operations


__version__ = '0.5'

BLOCK_MASK = 15
BLOCK_SIZE = 16
BUFFER_SIZE = 1024*16
MAC_SIZE = 16
VERIFY = True

class RencFSBase(Operations):
    def __init__(self, root, key):
        self.root = root
        self.hmac = hmac.new(key[:16], digestmod=sha256)
        self.aes_ecb = AES.new(key[16:], AES.MODE_ECB)
        self.keys = {}

    # Helpers

    def _fullpath(self, partial):
        if partial.startswith('/'):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def _enc(self, key, offset, data):
        index = offset // BLOCK_SIZE
        ctr = Counter.new(128, initial_value=index)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        if not offset & BLOCK_MASK:
            return aes.encrypt(data)
        data = b'\0' * (offset & BLOCK_MASK) + data
        return aes.encrypt(data)[offset & BLOCK_MASK:]

    def _key(self, fh):
        if fh not in self.keys:
            raise FuseOSError(errno.EBADF)
        return self.keys[fh]
            

    def _read(self, fh, size, seek=None):
        if seek is not None:
            os.lseek(fh, seek, os.SEEK_SET)
        return os.read(fh, size)


    # Filesystem methods

    def access(self, path, mode):
        full_path = self._fullpath(path)
        if mode == os.W_OK or not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def getattr(self, path, fh=None):
        full_path = self._fullpath(path)
        try:
            st = os.lstat(full_path)
        except OSError as e:
            raise FuseOSError(e.errno)
        st = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode',
            'st_mtime', 'st_nlink', 'st_size', 'st_uid'
        ))
        return st

    def readdir(self, path, fh=None):
        full_path = self._fullpath(path)
        dirents = ['.', '..']
        try:
            dirents.extend(os.listdir(full_path))
        except OSError as e:
            raise FuseOSError(e.errno)
        for r in dirents:
            yield r

    def readlink(self, path):
        try:
            pathname = os.readlink(self._fullpath(path))
        except OSError as e:
            raise FuseOSError(e.errno)
        return os.path.relpath(pathname, self.root)

    def statfs(self, path):
        full_path = self._fullpath(path)
        try:
            stv = os.statvfs(full_path)
        except OSError as e:
            raise FuseOSError(e.errno)
        return dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'
        ))

    def utimens(self, path, times=None):
        raise FuseOSError(errno.EROFS)


    # File methods

    def open(self, path, flags):
        full_path = self._fullpath(path)
        try:
            fh = os.open(full_path, flags)
        except OSError as e:
            raise FuseOSError(e.errno)
        self.keys[fh] = self._getkey(fh)
        return fh

    def create(self, path, mode, fi=None):
        raise FuseOSError(errno.EROFS)

    def release(self, path, fh):
        self.keys.pop(fh, None)
        return os.close(fh)


class RencFSEncrypt(RencFSBase):

    def _mac(self, fh):
        hmac = self.hmac.copy()
        d = self._read(fh, BUFFER_SIZE, 0)
        while d:
            hmac.update(d)
            d = self._read(fh, BUFFER_SIZE)
        return hmac.digest()[:MAC_SIZE]

    def _getkey(self, fh):
        return self._mac(fh)

    def getattr(self, path, fh=None):
        st = super(RencFSEncrypt, self).getattr(path)
        st['st_size'] += MAC_SIZE
        return st

    def read(self, path, length, offset, fh):
        data = b''
        h = self._key(fh)
        if offset < MAC_SIZE:
            data = self.aes_ecb.encrypt(h)[offset:offset+length]
            length -= MAC_SIZE - offset
            offset = 0
        else:
            offset -= MAC_SIZE
        if length > 0:
            data += self._enc(h, offset, self._read(fh, length, offset))
        return data


class RencFSDecrypt(RencFSBase):

    def __init__(self, root, key, verify=VERIFY):
        super(RencFSDecrypt, self).__init__(root, key)
        self.verify = verify

    def _mac(self, fh, h):
        pos, hmac = MAC_SIZE, self.hmac.copy()

        d = self._read(fh, BUFFER_SIZE, pos)
        while d:
            hmac.update(self._dec(h, pos, d))
            pos, d = pos + len(d), self._read(fh, BUFFER_SIZE)
        return hmac.digest()[:MAC_SIZE]

    def _getkey(self, fh):
        h = self.aes_ecb.decrypt(self._read(fh, MAC_SIZE, 0))
        if self.verify and h != self._mac(fh, h):
            raise FuseOSError(errno.EPERM)
        return h

    def _dec(self, key, offset, data):
        return super(RencFSDecrypt, self)._enc(key, offset - MAC_SIZE, data)

    def getattr(self, path, fh=None):
        st = super(RencFSDecrypt, self).getattr(path)
        st['st_size'] -= MAC_SIZE
        return st

    def read(self, path, length, offset, fh):
        h = self._key(fh)
        offset += MAC_SIZE
        return self._dec(h, offset, self._read(fh, length, offset))


if __name__ == '__main__': #pragma no cover

    def parse_args():
        docstrings = __doc__.split('\n')
        name = docstrings[0]
        description = docstrings[-1]
        parser = ArgumentParser(name, description=description)
        parser.add_argument('-v', '--version', action='version',
                            version='%(prog)s ' + __version__,
                            help=SUPPRESS)
        parser.add_argument('ROOT', help='directory to encrypt')
        parser.add_argument('MOUNTPOINT', help='where to mount, must be empty')
        parser.add_argument('KEY', help='master key used for encryption')
        parser.add_argument('-d', '--decrypt', action='store_true',
                            help='decrypt a copy of the encrypted filesystem')
        parser.add_argument('-n', '--no-auth', action='store_false',
                            dest='verify',
                            help='skips authentication checks with --decrypt')
        args = parser.parse_args()
        if (not args.verify and not args.decrypt):
            parser.error('-n/--no-auth requires -d/--decrypt')
        return args


    args = parse_args()
    key = sha256(args.KEY).digest()
    if args.decrypt:
        fs = RencFSDecrypt(args.ROOT, key, args.verify)
    else:
        fs = RencFSEncrypt(args.ROOT, key)
    FUSE(fs, args.MOUNTPOINT, nothreads=True, foreground=True)
