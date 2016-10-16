#!/usr/bin/python

import errno
import hmac
import os
import sys

from hashlib import sha256

from fuse import FUSE, FuseOSError, Operations

from Crypto.Cipher import AES
from Crypto.Util import Counter

from base64 import b16encode

VERIFY = True
BUFFER = 1024*16
MAC_SIZE = 16

class Passthrough(Operations):
    def __init__(self, root, key, decrypt):
        self.root = root
        self.hmac = hmac.new(key[:16], digestmod=sha256)
        self.aes_ecb = AES.new(key[16:], AES.MODE_ECB)
        self.keys = {}
        self.decrypt = decrypt

    # Helpers

    def _full_path(self, partial):
        if partial.startswith("/"):
            partial = partial[1:]
        path = os.path.join(self.root, partial)
        return path

    def _getkey(self, path):
        if path in self.keys:
            return self.keys[path]
        if self.decrypt:
            h = open(self._full_path(path)).read(MAC_SIZE)
            h = self.aes_ecb.decrypt(h)
            if VERIFY:
                hmac = self.hmac.copy()
                with open(self._full_path(path)) as f:
                    f.seek(MAC_SIZE)
                    pos = MAC_SIZE
                    while True:
                        d = f.read(BUFFER)
                        if not d:
                            break
                        hmac.update(self._enc(h, pos, d))
                        pos += len(d)
                hmac = hmac.digest()[:16]
                if h != hmac:
                    raise FuseOSError(errno.EPERM)
        else:
            hmac = self.hmac.copy()
            with open(self._full_path(path)) as f:
                while True:
                    d = f.read(BUFFER)
                    if not d:
                        break
                    hmac.update(d)
            h = hmac.digest()[:16]
        self.keys[path] = h
        return h

    def _enc(self, key, offset, data):
        index = offset // 16
        if self.decrypt:
            index -= 1
        ctr = Counter.new(128, initial_value=index)
        aes = AES.new(key, AES.MODE_CTR, counter=ctr)
        return aes.encrypt(data)


    # Filesystem methods

    def access(self, path, mode):
        full_path = self._full_path(path)
        if not os.access(full_path, mode):
            raise FuseOSError(errno.EACCES)

    def getattr(self, path, fh=None):
        full_path = self._full_path(path)
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
        full_path = self._full_path(path)

        dirents = ['.', '..']
        if os.path.isdir(full_path):
            dirents.extend(os.listdir(full_path))
        for r in dirents:
            yield r

    def readlink(self, path):
        pathname = os.readlink(self._full_path(path))
        if pathname.startswith("/"):
            # Path name is absolute, sanitize it.
            return os.path.relpath(pathname, self.root)
        else:
            return pathname

    def statfs(self, path):
        full_path = self._full_path(path)
        stv = os.statvfs(full_path)
        return dict((key, getattr(stv, key)) for key in ('f_bavail', 'f_bfree',
            'f_blocks', 'f_bsize', 'f_favail', 'f_ffree', 'f_files', 'f_flag',
            'f_frsize', 'f_namemax'))

    def utimens(self, path, times=None):
        return os.utime(self._full_path(path), times)


    # File methods

    def open(self, path, flags):
        full_path = self._full_path(path)
        return os.open(full_path, flags)

    def create(self, path, mode, fi=None):
        if debug: print 'tried create'
        raise FuseOSError(errno.EROFS)

    def read(self, path, length, offset, fh):
        data = ''
        h = self._getkey(path)
        if self.decrypt:
            offset += MAC_SIZE
        else:
            if offset < MAC_SIZE:
                data = self.aes_ecb.encrypt(h)[offset:]
                length -= MAC_SIZE - offset
                offset = 0
            else:
                offset -= MAC_SIZE
        off = (offset // 16) * 16
        l = length + offset - off
        os.lseek(fh, off, os.SEEK_SET)
        data += self._enc(h, off, os.read(fh, l))
        return data[offset - off:]

    def release(self, path, fh):
        self.keys.pop(path, None)
        return os.close(fh)


def main(mountpoint, root, rawkey, decrypt):
    key = sha256(rawkey).digest()
    FUSE(Passthrough(root, key, decrypt), mountpoint, nothreads=True, foreground=True)

if __name__ == '__main__':
    main(sys.argv[2], sys.argv[1], sys.argv[3], '-d' in sys.argv)

