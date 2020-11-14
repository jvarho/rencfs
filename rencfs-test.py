#!/usr/bin/python3

# Copyright (c) 2016-2020, Jan Varho
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

import os
from os import urandom, R_OK, W_OK, X_OK
from unittest import defaultTestLoader, TestCase, TestSuite, TextTestRunner

try:
    from fusepy import FUSE, FuseOSError, Operations
except ImportError:
    from fuse import FUSE, FuseOSError, Operations

from rencfs import RencFSEncrypt, RencFSDecrypt

class RencFSTest(TestCase):
    td = 'test1/'
    tf = 'f2'
    tl = 'l2'
    len = 1024 * 1024
    key = urandom(32)
    key2 = urandom(32)

    @classmethod
    def setUpClass(cls):
        cls.tfp = cls.td + cls.tf
        try:
            os.mkdir(cls.td)
        except OSError:
            pass
        with open(cls.tfp, 'wb') as f:
            f.write(b' '*cls.len)
        tlf = cls.td + cls.tl
        try:
            os.remove(tlf)
        except OSError:
            pass
        os.symlink(cls.tfp, tlf)

    def test_access(self):
        self.assertFalse(self.fs.access(self.tf, R_OK))
        self.assertRaises(
            FuseOSError,
            self.fs.access,
            '__',
            R_OK
        )
        self.assertRaises(
            FuseOSError,
            self.fs.access,
            self.tf,
            W_OK
        )

    def test_readdir(self):
        self.assertGreaterEqual(
            len(list(self.fs.readdir('/'))),
            4
        )
        self.assertIn(self.tf, list(self.fs.readdir('/')))
        self.assertRaises(
            FuseOSError,
            lambda a: list(self.fs.readdir(a)),
            '__',
        )
        self.assertRaises(
            FuseOSError,
            lambda a: list(self.fs.readdir(a)),
            self.tf,
        )

    def test_readlink(self):
        self.assertEqual(
            self.fs.readlink(self.tl),
            self.tf
        )
        self.assertRaises(
            FuseOSError,
            self.fs.readlink,
            '__'
        )

    def test_statfs(self):
        self.assertGreaterEqual(
            self.fs.statfs('/')['f_files'],
            2
        )
        self.assertRaises(
            FuseOSError,
            self.fs.statfs,
            '__'
        )

    def test_utimens(self):
        self.assertRaises(
            FuseOSError,
            self.fs.utimens,
            self.tf,
            1
        )

    def test_getattr_failure(self):
        self.assertRaises(
            FuseOSError,
            self.fs.getattr,
            '__'
        )

    def test_create(self):
        self.assertRaises(
            FuseOSError,
            self.fs.create,
            '__',
            os.O_RDONLY
        )

    def test_open(self):
        self.assertRaises(
            FuseOSError,
            self.fs.open,
            '__',
            os.O_RDONLY
        )

    def test_read_notopen(self):
        self.assertRaises(
            FuseOSError,
            self.fs.read,
            '__',
            1,
            0,
            0
        )

    def test_release(self):
        fh = self.fs.open(self.tf, os.O_RDONLY)
        self.assertIn(fh, self.fs.keys)
        self.fs.release(self.tf, fh)
        self.assertNotIn(fh, self.fs.keys)
        self.assertRaises(
            FuseOSError,
            self.fs.release,
            self.tf,
            fh
        )


class EncryptTest(RencFSTest):
    @classmethod
    def setUpClass(cls):
        super(EncryptTest, cls).setUpClass()
        cls.fs = RencFSEncrypt(cls.td, cls.key)

    def test_getattr(self):
        self.assertGreater(
            self.fs.getattr(self.tf)['st_size'],
            os.lstat(self.tfp).st_size
        )

    def test_read(self):
        fh = self.fs.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh)
        self.assertGreater(len(self.fs.read(self.tf, self.len + 1, 0, fh)), self.len)
        self.assertEqual(len(self.fs.read(self.tf, 1, 1, fh)), 1)
        self.assertEqual(len(self.fs.read(self.tf, 1, self.len + 1, fh)), 1)


class DecryptTest(RencFSTest):
    @classmethod
    def setUpClass(cls):
        super(DecryptTest, cls).setUpClass()
        fs = RencFSEncrypt(cls.td, cls.key)
        d = fs.read(cls.tf, cls.len + 128, 0, fs.open(cls.tf, os.O_RDONLY))
        with open(cls.tfp, 'wb') as f:
            f.write(d)
        cls.fs = RencFSDecrypt(cls.td, cls.key)
        cls.fs2 = RencFSDecrypt(cls.td, cls.key2)
        cls.fs3 = RencFSDecrypt(cls.td, cls.key2, verify=False)

    def test_getattr(self):
        self.assertLess(
            self.fs.getattr(self.tf)['st_size'],
            os.lstat(self.tfp).st_size
        )
        self.assertEqual(
            self.fs.getattr(self.tf)['st_size'],
            self.len
        )

    def test_read(self):
        fh = self.fs.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh)
        self.assertEqual(self.fs.read(self.tf, self.len + 1024, 0, fh), b' '*self.len)
        self.assertEqual(self.fs.read(self.tf, 1, 1, fh), b' ')
        self.assertEqual(len(self.fs.read(self.tf, 1, self.len + 1, fh)), 0)

    def test_failure(self):
        self.assertRaises(
            FuseOSError,
            self.fs2.open,
            self.tf,
            os.O_RDONLY
        )

    def test_noverify(self):
        fh = self.fs3.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh)
        self.assertNotEqual(self.fs3.read(self.tf, self.len + 1024, 0, fh), b' '*self.len)


def main():
    tests = TestSuite()
    tests.addTest(defaultTestLoader.loadTestsFromTestCase(DecryptTest))
    tests.addTest(defaultTestLoader.loadTestsFromTestCase(EncryptTest))
    TextTestRunner().run(tests)


if __name__ == '__main__':
    main()
