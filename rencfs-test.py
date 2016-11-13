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

from rencfs import RencFS


class EncryptTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.td = 'test1/'
        cls.tf = 'f2'
        cls.tff = cls.td + cls.tf
        cls.tl = 'l2'
        cls.tlf = cls.td + cls.tl
        cls.fs = RencFS(cls.td, urandom(32), False)
        with open(cls.tff, 'w') as f:
            f.write(' '*128)
        os.remove(cls.tlf)
        os.symlink(cls.tff, cls.tlf)

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
            len(list(self.fs.readdir('/', 0))),
            4
        )
        self.assertRaises(
            FuseOSError,
            lambda a, b: list(self.fs.readdir(a, b)),
            '__',
            0
        )
        self.assertRaises(
            FuseOSError,
            lambda a, b: list(self.fs.readdir(a, b)),
            self.tf,
            0
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
        self.assertGreater(len(self.fs.read(self.tf, 1024, 0, fh)), 128)
        self.assertEqual(len(self.fs.read(self.tf, 1, 1, fh)), 1)
        self.assertEqual(len(self.fs.read(self.tf, 1, 129, fh)), 1)

    def test_release(self):
        fh = self.fs.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh)
        self.fs.read(self.tf, 128, 1, fh)
        self.assertTrue(fh in self.fs.keys)
        self.fs.release(self.tf, fh)
        self.assertFalse(fh in self.fs.keys)


class DecryptTest(TestCase):

    @classmethod
    def setUpClass(cls):
        cls.td = 'test1/'
        cls.tf = 'f2'
        cls.tff = cls.td + cls.tf
        cls.tl = 'l2'
        cls.tlf = cls.td + cls.tl
        with open(cls.tff, 'w') as f:
            f.write(' '*128)
        key = urandom(32)
        fs = RencFS(cls.td, key, False)
        d = fs.read(cls.tf, 1024, 0, fs.open(cls.tf, os.O_RDONLY))
        with open(cls.tff, 'w') as f:
            f.write(d)
        cls.fs = RencFS(cls.td, key, True)
        cls.fs2 = RencFS(cls.td, key[16:] + key[:16], True)

    def test_getattr(self):
        self.assertLess(
            self.fs.getattr(self.tf)['st_size'],
            os.lstat(self.tff).st_size
        )
        self.assertEqual(
            self.fs.getattr(self.tf)['st_size'],
            128
        )

    def test_read(self):
        fh = self.fs.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh)
        self.assertEqual(self.fs.read(self.tf, 1024, 0, fh), ' '*128)
        self.assertEqual(self.fs.read(self.tf, 1, 1, fh), ' ')
        self.assertEqual(len(self.fs.read(self.tf, 1, 129, fh)), 0)

    def test_failure(self):
        fh = self.fs2.open(self.tf, os.O_RDONLY)
        self.assertTrue(fh)
        self.assertRaises(
            FuseOSError,
            self.fs2.read,
            self.tf,
            1024,
            0,
            fh
        )


def main():
    tests = TestSuite()
    tests.addTest(defaultTestLoader.loadTestsFromTestCase(EncryptTest))
    tests.addTest(defaultTestLoader.loadTestsFromTestCase(DecryptTest))
    TextTestRunner().run(tests)


if __name__ == '__main__':
    main()
