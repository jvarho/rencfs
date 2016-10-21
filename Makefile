
test:
	python rencfs-test.py

coverage:
	python -m coverage run --branch rencfs-test.py
	python -m coverage html --include=rencfs.py
	python -m coverage report --include=rencfs.py
