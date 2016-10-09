import os
import hashlib

fn = 'test2/f1'
fno = 'test1/f1'
fnd = 'test3/f1'

d = open(fn).read()
l = len(d)
h = hashlib.sha256(d).hexdigest()
print h


h = hashlib.sha256()

try:
    for i in range(l):
        fh = os.open(fn, os.O_RDONLY)
        os.lseek(fh, i, os.SEEK_SET)
        h.update(os.read(fh, 1))
        os.close(fh)
except:
    print i, fh
    raise

print h.hexdigest()

print hashlib.sha256(open(fno).read()).hexdigest()
print hashlib.sha256(open(fnd).read()).hexdigest()
