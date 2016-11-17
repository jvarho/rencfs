
test:
	python rencfs-test.py

coverage:
	python2 -m coverage run --branch rencfs-test.py
	python3 -m coverage run --branch -a rencfs-test.py
	python -m coverage report --include=rencfs.py
	python -m coverage html --include=rencfs.py
