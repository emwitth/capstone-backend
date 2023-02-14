test: test-initial test-many-small

test-initial:
	./test-scripts/initial.sh

test-many-small:
	./test-scripts/many-small.sh

unit-test:
	python3 -m unit-tests.sniffer-test

run:
	sudo python3 backend.py
