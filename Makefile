test:
	python3 rencfs-test.py

coveralls:
	python3 -m coverage run --branch rencfs-test.py

coverage:
	python3 -m coverage run --branch rencfs-test.py
	python3 -m coverage report --include=rencfs.py
	python3 -m coverage html --include=rencfs.py
