python enc.py test1 test2 'helloworld' &
python enc.py test2 test3 'helloworld' -d &
sleep 1
python testreader.py
kill %2
kill %1
