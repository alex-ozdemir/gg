check:
	python3 -m unittest

check_remote:
	REMOTE_TEST=1 python3 -m unittest

type:
	(cd .. && mypy pygg) && mypy examples/*.py
