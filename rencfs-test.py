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

import os
from os import urandom, R_OK, W_OK, X_OK
from unittest import defaultTestLoader, TestCase, TestSuite, TextTestRunner
from fuse import FuseOSError

from rencfs import RencFSEncrypt, RencFSDecrypt


class EncryptTest(TestCase):

    @classmethod
    def setUpClass(cls):
        testdir = 'test1/'
        cls.tf = 'f2'
        cls.tff = testdir + cls.tf
        cls.tl = 'l2'
        tlf = testdir + cls.tl
        cls.fs = RencFSEncrypt(testdir, urandom(32))
        try:
            os.mkdir(testdir)
        except OSError:
            pass
        cls.len = 1024 * 1024
        with open(cls.tff, 'w') as f:
            f.write(' '*cls.len)
        try:
            os.remove(tlf)
        except OSError:
            pass
        os.symlink(cls.tff, tlf)

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

    def test_getattr(self):
        self.assertGreater(
            self.fs.getattr(self.tf)['st_size'],
            os.lstat(self.tff).st_size
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

    def test_statfs(self):
        self.assertGreaterEqual(
            self.fs.statfs('/')['f_files'],
            2
        )

    def test_utimens(self):
        self.assertRaises(
            FuseOSError,
            self.fs.utimens,
            self.tf,
            1
        )

    def test_create(self):
        self.assertRaises(
            FuseOSError,
            self.fs.create,
            '__',
            os.O_RDONLY
        )

    def test_read(self):
        fh = self.fs.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh)
        self.assertGreater(len(self.fs.read(self.tf, self.len + 1, 0, fh)), self.len)
        self.assertEqual(len(self.fs.read(self.tf, 1, 1, fh)), 1)
        self.assertEqual(len(self.fs.read(self.tf, 1, self.len + 1, fh)), 1)

    def test_release(self):
        fh = self.fs.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh in self.fs.keys)
        self.fs.release(self.tf, fh)
        self.assertFalse(fh in self.fs.keys)


class DecryptTest(TestCase):

    @classmethod
    def setUpClass(cls):
        testdir = 'test1/'
        cls.tf = 'f2'
        cls.tff = testdir + cls.tf
        cls.len = 1024 * 1024
        try:
            os.mkdir(testdir)
        except OSError:
            pass
        with open(cls.tff, 'w') as f:
            f.write(' '*cls.len)
        key = urandom(32)
        fs = RencFSEncrypt(testdir, key)
        d = fs.read(cls.tf, cls.len + 128, 0, fs.open(cls.tf, os.O_RDONLY))
        f = os.open(cls.tff, os.O_WRONLY)
        os.write(f, d)
        os.close(f)
        cls.fs = RencFSDecrypt(testdir, key)
        cls.fs2 = RencFSDecrypt(testdir, key[16:] + key[:16])
        cls.fs3 = RencFSDecrypt(testdir, key[16:] + key[:16], verify=False)

    def test_getattr(self):
        self.assertLess(
            self.fs.getattr(self.tf)['st_size'],
            os.lstat(self.tff).st_size
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
