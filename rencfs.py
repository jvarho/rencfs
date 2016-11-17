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


__version__ = '0.4'

BLOCK_MASK = 15
BLOCK_SIZE = 16
BUFFER_SIZE = 1024*16
MAC_SIZE = 16
VERIFY = True

class RencFS(Operations):
    def __init__(self, root, key, decrypt):
        self.root = root
        self.hmac = hmac.new(key[:16], digestmod=sha256)
        self.aes_ecb = AES.new(key[16:], AES.MODE_ECB)
        self.keys = {}
        self.decrypt = decrypt

    # Helpers

    def _fullpath(self, partial):
        if partial.startswith('/'):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def _mac(self, fh, h=''):
        pos, hmac = 0, self.hmac.copy()
        if self.decrypt:
            pos = MAC_SIZE
        os.lseek(fh, pos, os.SEEK_SET)
        while True:
            d = os.read(fh, BUFFER_SIZE)
            if not d:
                break
            if self.decrypt:
                pos, d = len(d), self._enc(h, pos, d)
            hmac.update(d)
        return hmac.digest()[:MAC_SIZE]

    def _getkey(self, fh):
        if fh in self.keys:
            return self.keys[fh]
        if self.decrypt:
            os.lseek(fh, 0, os.SEEK_SET)
            h = self.aes_ecb.decrypt(os.read(fh, MAC_SIZE))
            if VERIFY and h != self._mac(fh, h):
                raise FuseOSError(errno.EPERM)
        else:
            h = self._mac(fh)
        self.keys[fh] = h
        return h

    def _enc(self, key, offset, data):
        if self.decrypt:
            offset -= MAC_SIZE
        index = offset // BLOCK_SIZE
        ctr = Counter.new(128, initial_value=index)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        if not offset & BLOCK_MASK:
            return aes.encrypt(data)
        data = b'\0' * (offset & BLOCK_MASK) + data
        return aes.encrypt(data)[offset & BLOCK_MASK:]


    # Filesystem methods

    def access(self, path, mode):
        full_path = self._fullpath(path)
        if mode in (os.W_OK, os.X_OK) or not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def getattr(self, path, fh=None):
        full_path = self._fullpath(path)
        st = os.lstat(full_path)
        st = dict((key, getattr(st, key)) for key in (
            'st_atime', 'st_ctime', 'st_gid', 'st_mode',
            'st_mtime', 'st_nlink', 'st_size', 'st_uid'
        ))
        if self.decrypt:
            st['st_size'] -= MAC_SIZE
        else:
            st['st_size'] += MAC_SIZE
        return st

    def readdir(self, path, fh):
        full_path = self._fullpath(path)
        dirents = ['.', '..']
        try:
            dirents.extend(os.listdir(full_path))
        except OSError as e:
            raise FuseOSError(e.errno)
        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._fullpath(path))
        return os.path.relpath(pathname, self.root)

    def statfs(self, path):
        full_path = self._fullpath(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in (
            'f_bavail', 'f_bfree', 'f_blocks', 'f_bsize', 'f_favail',
            'f_ffree', 'f_files', 'f_flag', 'f_frsize', 'f_namemax'
        ))

    def utimens(self, path, times=None):
        raise FuseOSError(errno.EROFS)


    # File methods

    def open(self, path, flags):
        full_path = self._fullpath(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        raise FuseOSError(errno.EROFS)

    def read(self, path, length, offset, fh):
        data = b''
        h = self._getkey(fh)
        if self.decrypt:
            offset += MAC_SIZE
        elif offset < MAC_SIZE:
            data = self.aes_ecb.encrypt(h)[offset:offset+length]
            length -= MAC_SIZE - offset
            offset = 0
        else:
            offset -= MAC_SIZE
        if length > 0:
            os.lseek(fh, offset, os.SEEK_SET)
            data += self._enc(h, offset, os.read(fh, length))
        return data

    def release(self, path, fh):
        self.keys.pop(fh, None)
        return os.close(fh)


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
        return parser.parse_args()


    def main(mountpoint, root, rawkey, decrypt):
        key = sha256(rawkey).digest()
        FUSE(RencFS(root, key, decrypt), mountpoint, nothreads=True, foreground=True)

    args = parse_args()
    main(args.MOUNTPOINT, args.ROOT, args.KEY, args.decrypt)
