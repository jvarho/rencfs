testall:
	python2 rencfs-test.py
	python3 rencfs-test.py

test:
	python rencfs-test.py

coveralls:
	python -m coverage run --branch rencfs-test.py

coverage:
	python -m coverage run --branch rencfs-test.py
	python -m coverage report --include=rencfs.py
	python -m coverage html --include=rencfs.py
