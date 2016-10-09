import os
import hashlib
import time

fn = 'test2/f1'
fno = 'test1/f1'
fnd = 'test3/f1'

t = time.time()
def ttime():
    global t
    dt = time.time()
    t, dt = dt, dt-t
    return dt

h = hashlib.sha256()
with open(fn) as f:
    l = 0
    while True:
        d = f.read(1024*1024)
        if not d:
            break
        h.update(d)
        l += len(d)
    h = h.hexdigest()
print h, ttime()


h = hashlib.sha256()

step = 1000

i, fh = -1, None
try:
    fh = os.open(fn, os.O_RDONLY)
    for i in xrange(0, l, step):
        h.update(os.read(fh, step))
    os.close(fh)
except:
    print i, fh
    raise

print h.hexdigest(), ttime()

h = hashlib.sha256()
with open(fno) as f:
    while True:
        d = f.read(1024*1024)
        if not d:
            break
        h.update(d)
print h.hexdigest(), ttime()

h = hashlib.sha256()
with open(fnd) as f:
    while True:
        d = f.read(1024*1024)
        if not d:
            break
        h.update(d)
print h.hexdigest(), ttime()

