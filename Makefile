test: initial

initial:
	./test-scripts/initial.sh

unit-test:
	python3 -m unit-tests.sniffer-test

run:
	sudo python3 backend.py
