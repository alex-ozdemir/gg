check:
	python3.7 -m unittest

check_remote:
	REMOTE_TEST=1 python3.7 -m unittest

type:
	(cd .. && mypy pygg) && mypy examples/*.py
