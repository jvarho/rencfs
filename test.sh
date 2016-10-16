mkdir -p test1 test2 test3
dd if=/dev/zero of=test1/f1 bs=1024 count=1
python rencfs.py test1 test2 'helloworld' &
sleep 1
python rencfs.py test2 test3 'helloworld' -d &
sleep 1
sha1sum test1/f1
sha1sum test2/f1
sha1sum test3/f1
python testreader.py
kill %2
kill %1
